#include "er-dtls-13-resource.h"

#include <string.h>

#include "er-coap-13.h"
#include "er-coap-13-separate.h"
#include "er-coap-13-transactions.h"
#include "er-coap-13-block1.h"
#include "er-dtls-13.h"
#include "er-dtls-13-data.h"
#include "er-dtls-13-random.h"
#include "er-dtls-13-prf.h"
#include "er-dtls-13-psk.h"
#include "er-dtls-13-alert.h"
#include "time.h"
#include "aes.h"
#include "ecc.h"
#include "flash-store.h"

#define DEBUG 1
#define DEBUG_COOKIE 0
#define DEBUG_ECC 0
#define DEBUG_PRF 0
#define DEBUG_FIN 0

#if DEBUG || DEBUG_COOKIE || DEBUG_ECC || DEBUG_PRF || DEBUG_FIN
    #include <stdio.h>
    #include "mc1322x.h"

    void printBytes(uint8_t *label, uint8_t *data, uint8_t len) {
        int i;
        printf("%s: ", label);
        for (i = 0; i < len; i++) printf("%02X", data[i]);
        printf("\n");
    }
#endif

#if DEBUG
    #define PRINTF(...) printf(__VA_ARGS__)
#else
    #define PRINTF(...)
#endif

// Die folgenden 6 Funktionen werden nur einmal aufgerufen und dienen lediglich der Codeübersicht.
// Das inline-Keyword wird mit den gesetzten Kompiler-Parametern aufgrund der Funktionsgrößen ignoriert, weshalb das Attribut genutzt wird.
// Bei generateHelloVerifyRequest nimmt die Programmgröße um ca 24 Byte ab während sie bei den anderen gleich bleibt.
// Durch den gesparten Funktionsaufruf nimmt jedoch die Größe des benötigten Stacks erheblich ab.
__attribute__((always_inline)) static void generateHelloVerifyRequest(uint8_t *dst, uint8_t *cookie, size_t cookie_len);
__attribute__((always_inline)) static void generateCookie(uint8_t *dst, DTLSContent_t *data, size_t *data_len);
__attribute__((always_inline)) static AlertDescription checkClientHello(ClientHello_t *clientHello, size_t len);
__attribute__((always_inline)) static void generateServerHello(uint32_t *buf);
__attribute__((always_inline)) static void processClientKeyExchange(KeyExchange_t *cke, uint8_t *buf);
__attribute__((always_inline)) static void generateFinished(uint8_t *buf);

void sendServerHello(void *data, void* resp);
__attribute__((always_inline)) static int readServerHello(void *target, uint8_t offset, uint8_t size);

static uip_ipaddr_t src_addr[1];
static coap_separate_t request_metadata[1];

static uint8_t big_msg[128];
static size_t big_msg_len = 0;

static uint8_t resource_busy = 0;
static uint32_t busy_since = 0;

static uint16_t created_offset;
static uint16_t client_random_offset;
static uint16_t server_random_offset;

/*************************************************************************/
/*  Ressource für den DTLS-Handshake                                     */
/*************************************************************************/
void dtls_handler(void* request, void* response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset) {
    if (resource_busy) {
        // Betreten verboten, falls ip ungleich && busy_since nicht weiter als 60 sekunden zurück liegt
        if (!uip_ipaddr_cmp(src_addr, &UIP_IP_BUF->srcipaddr)) {
            if (clock_seconds() - busy_since <= 60) {
                coap_error_code = SERVICE_UNAVAILABLE_5_03;
                coap_error_message = "AlreadyInUse";
                return;
            }
        }
    } else {
        resource_busy = 1;
        busy_since = clock_seconds();
        uip_ipaddr_copy(src_addr, &UIP_IP_BUF->srcipaddr);
    }

    if (coap_block1_handler(request, response, big_msg, &big_msg_len, 128)) {
        return;
    }

    // Busy wird zunächst aufgehoben. Block 1 Nachricht ist vollständig. Neue Block 1 Nachricht kann eintreffen.
    resource_busy = 0;

    if (big_msg_len > 0) {
        DTLSContent_t *content = (DTLSContent_t *) big_msg;

        uint32_t buf32[52];
        uint8_t *buf = (uint8_t *) buf32;

        const char *uri_path = NULL;
        uint8_t uri_len = coap_get_header_uri_path(request, &uri_path);

        if (uri_len == 4) {
            if (content->type != client_hello) {
                PRINTF("Erwartetes ClientHello nicht erhalten\n");
                generateAlert(response, buffer, illegal_parameter);
                goto dtls_handler_end;
            }

            ClientHello_t *clienthello = (ClientHello_t *) (content->payload + content->len);

            uint8_t cookie_len = clienthello->data[0];
            uint8_t *old_cookie = buf;
            uint8_t *new_cookie = buf + 8;

            if (cookie_len > 0) {
                // Abspeichern für Finished-Hash. Kritisch, da Cookie noch nicht geprüft.
                // Derzeit nicht anders möglich, da generateCookie den alten Cookie entfernt,
                // dieser aber zur Berechnung des Finished-Hash benötigt wird.
                stack_init();
                stack_push(big_msg, big_msg_len);
                client_random_offset = (uint32_t) clienthello->random.random_bytes - (uint32_t) big_msg;

                // Übertragenen Cookie in Buffer sichern zum späteren Vergleich
                memcpy(old_cookie, clienthello->data + 1, cookie_len);
            }

            generateCookie(new_cookie, content, &big_msg_len);

            if (cookie_len == 0 || memcmp(old_cookie, new_cookie, 8)) {
                #if DEBUG
                    if (cookie_len == 0) PRINTF("ClientHello ohne Cookie erhalten\n");
                    else PRINTF("ClientHello mit falschem Cookie erhalten\n");
                #endif
                generateHelloVerifyRequest(buffer, new_cookie, 8);

                coap_set_status_code(response, UNAUTHORIZED_4_01);
                coap_set_header_content_type(response, APPLICATION_OCTET_STREAM);
                coap_set_payload(response, buffer + 1, buffer[0]);
            } else {
                PRINTF("ClientHello mit korrektem Cookie erhalten\n");

                AlertDescription alert = checkClientHello(clienthello, big_msg_len - (sizeof(DTLSContent_t) + content->len));
                if (alert) {
                    PRINTF("ClientHello falsche oder nicht unterstützte Werte\n");
                    generateAlert(response, buffer, alert);
                    goto dtls_handler_end;
                }

                // Zustand wird erzeugt, der erst mit der nächsten Anfrage abgearbeitet ist.
                // Bis dahin sind keine weiteren Anfragen möglich.
                resource_busy = 1;

                coap_separate_accept(request, request_metadata); // ACK + Anfrageinformationen zwischenspeichern

                // ServerHello wird immer gleich generiert da Server nur
                // genau ein Ciphersuit mit einer Konfiguration beherrscht.
                generateServerHello(buf32); // Das dauert nun
                sendServerHello(NULL, request);
            }
        } else {
            PRINTF("POST-Anfrage auf %.*s erhalten\n", uri_len, uri_path);

            if (getSessionData(buf, src_addr, session_id) < 0 || memcmp(buf, uri_path + 5, 8)) {
                PRINTF("Ressource existiert nicht\n");
                coap_set_status_code(response, NOT_FOUND_4_04);
                goto dtls_handler_end;
            }

            if (content->type != client_key_exchange) {
                PRINTF("Erwartetes ClientKeyExchange nicht erhalten\n");
                generateAlert(response, buffer, illegal_parameter);
                goto dtls_handler_end;
            }

            coap_separate_accept(request, request_metadata); // ACK + Anfrageinformationen zwischenspeichern

            stack_push(big_msg, sizeof(DTLSContent_t) + content->len + sizeof(KeyExchange_t));

            // ClientKeyExchange wird ausgewertet und ein KeyBlock berechnet
            processClientKeyExchange((KeyExchange_t *) (content->payload + content->len), buf);
            //  0                   1                   2                   3                   4                   5
            //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            // |#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|     Master-Secret     |
            generateFinished(buf);
            //  0                   1                   2                   3                   4                   5
            //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            // | C-F | S-F |#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|
            content += (sizeof(DTLSContent_t) + content->len + sizeof(KeyExchange_t));

            coap_transaction_t *transaction = NULL;
            transaction = coap_new_transaction(request_metadata->mid, &request_metadata->addr, request_metadata->port);
            if (transaction == NULL) {
                PRINTF("Separate Antwort konnte nicht erstellt werden\n");
                // Da keine Antwort an den Clienten gesendet werden kann,
                // ist es nicht möglich irgendwas zu tun :(
                // Vielleicht nach einiger Zeit nochmal probieren ?
                goto dtls_handler_end;
            }

            coap_separate_resume(response, request_metadata, CHANGED_2_04);
            coap_set_header_content_type(response, APPLICATION_OCTET_STREAM);
            if (content->type == c_change_cipher_spec) {
                content += 3;

                getSessionData(buf + 28, src_addr, session_epoch);
                buf[29]++;
                if (buf[29] == 0) buf[28]++;
                fpoint_t key_block;
                key_block = getKeyBlock(src_addr, (buf[28] << 8) + buf[29], 0);
                nvm_getVar(buf + 24, key_block + KEY_BLOCK_CLIENT_IV, 4);
                memset(buf + 30, 0, 6);
                nvm_getVar(buf + 36, key_block + KEY_BLOCK_CLIENT_KEY, 16);
                //  0                   1                   2                   3                   4                   5
                //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                // | C-F | S-F |Nonce|  Key  |#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|
                #if DEBUG_FIN
                    printBytes("Nonce zum Entschlüsseln von Finished", buf + 24, 12);
                    printBytes("Key zum Entschlüsseln von Finished", buf + 36, 16);
                #endif
                memcpy(buf + 52, ((uint8_t *) content) + 14, MAC_LEN);
                aes_crypt((uint8_t *) content, 14, buf + 36, buf + 24, 0);
                aes_crypt((uint8_t *) content, 14, buf + 36, buf + 24, 1);
                if (memcmp(buf + 52, ((uint8_t *) content) + 14, MAC_LEN)) {
                    PRINTF("DTLS-MAC-Fehler im Finished. Paket ungültig\n");
                    generateAlert(response, buffer, decrypt_error); // nicht bad_record_mac weil finished betroffen
                    goto dtls_handler_end;
                }

                if (content->type != finished) {
                    PRINTF("Erwartetes Finished nicht erhalten\n");
                    generateAlert(response, buffer, illegal_parameter);
                    goto dtls_handler_end;
                }

                #if DEBUG_FIN
                    printBytes("Client Finished gefunden", ((uint8_t *) content) + 2, 12);
                #endif

                if (memcmp(buf, ((uint8_t *) content) + 2, 12)) {
                    PRINTF("Erhaltenes Client-Finished stimmt nicht\n");
                    generateAlert(response, buffer, decrypt_error);
                    goto dtls_handler_end;
                }

                // Antworten generieren

                DTLSContent_t *c;

                c = (DTLSContent_t *) buffer;
                c->type = c_change_cipher_spec;
                c->len = con_length_8_bit;
                c->payload[0] = 1;
                c->payload[1] = 1;

                c = (DTLSContent_t *) (buffer + 3);
                c->type = finished;
                c->len = con_length_8_bit;
                c->payload[0] = 20;
                memcpy(c->payload + 1, buf + 12, 12);

                nvm_getVar(buf + 24, key_block + KEY_BLOCK_SERVER_IV, 4);
                nvm_getVar(buf + 36, key_block + KEY_BLOCK_SERVER_KEY, 16);
                #if DEBUG_FIN
                    printBytes("Nonce zum Verschlüsseln von Finished", buf + 24, 12);
                    printBytes("Key zum Verschlüsseln von Finished", buf + 36, 16);
                #endif
                aes_crypt(buffer + 3, 14, buf + 36, buf + 24, 0);

                coap_set_payload(response, buffer, 25);
            } else {
                PRINTF("Erwartetes ChangeCipherSpec nicht erhalten\n");
                generateAlert(response, buffer, illegal_parameter);
            }
            // TODO Warning: No check for serialization error.
            transaction->packet_len = coap_serialize_message(response, transaction->packet);
            transaction->callback = NULL;
            coap_send_transaction(transaction);
        }
    }
 
    dtls_handler_end: ;
        big_msg_len = 0;
}

/* ------------------------------------------------------------------------- */

__attribute__((always_inline)) static void generateHelloVerifyRequest(uint8_t *dst, uint8_t *cookie, size_t cookie_len) {
    dst[0] = 13;
    DTLSContent_t *content = (DTLSContent_t *) (dst + 1);

    content->type = hello_verify_request;
    content->len = con_length_8_bit;
    content->payload[0] = 11;

    HelloVerifyRequest_t *answer = (HelloVerifyRequest_t *) (content->payload + 1);
    answer->server_version.major = 3;
    answer->server_version.minor = 3;
    answer->cookie_len = cookie_len;
    memcpy(answer->cookie, cookie, cookie_len);
}

__attribute__((always_inline)) static void generateCookie(uint8_t *dst, DTLSContent_t *data, size_t *data_len) {
    uint32_t i;

    #if DEBUG_COOKIE
        printBytes("Content Länge Input (MSB)", data->payload, data->len);
    #endif
    uint32_t hello_len = 0;
    memcpy(((uint8_t *) &hello_len) + 4 - data->len, data->payload, data->len);
    hello_len = uip_ntohl(hello_len);
    #if DEBUG_COOKIE
        printf("Content Länge Berechnet: %u\n", hello_len);
        printBytes("Content Data (mc)", (uint8_t *) data, *data_len);
    #endif
    // Alten Cookie entfernen falls vorhanden
    uint32_t cookie = data->len + sizeof(ProtocolVersion) + sizeof(Random);
    if (data->payload[cookie] > 0) {
        for (i = cookie + 9; i <= hello_len; i++) {
            data->payload[i - 8] = data->payload[i];
        }
        hello_len = uip_ntohl(hello_len - data->payload[cookie]);
        memcpy(data->payload, ((uint8_t *) &hello_len) + 4 - data->len, data->len);
        data->payload[cookie] = 0;
        *data_len -= 8;
    }
    #if DEBUG_COOKIE
        printBytes("Content Data (oc)", (uint8_t *) data, *data_len);
    #endif

    uint8_t mac[16];
    memset(mac, 0, 16);
    uint8_t psk[16];
    getPSK(psk);
    aes_cmac(mac, src_addr->u8, 16, psk, 0);
    aes_cmac(mac, (uint8_t *) data, *data_len, psk, 1);
    memcpy(dst, mac, 8);
}

__attribute__((always_inline)) static AlertDescription checkClientHello(ClientHello_t *clientHello, size_t len) {
    uint8_t *p = clientHello->data + 1;
    uint8_t *end;
    uint32_t check = 0;

    // Version checken
    if (clientHello->client_version.major != 3 || clientHello->client_version.minor != 3) {
        PRINTF("ClientHello: Nicht unterstützte Protokollversion\n");
        return protocol_version;
    }

    // Ciphersuite checken
    end = p + (p[0] << 8) + p[1] + 2;
    p += 2;
    for (; p < end; p+=2) {
        if ((p[0] << 8) + p[1] == TLS_PSK_ECDH_WITH_AES_128_CCM_8) {
            check = 1;
        }
    }
    if (check == 0) {
        PRINTF("ClientHello: Keine geeignete Ciphersuit\n");
        return handshake_failure;
    }

    // CompressionMethod checken
    check = 0;
    end = p + p[0] + 1;
    p += 1;
    for (; p < end; p++) {
        if (p[0] == null) {
            check = 1;
        }
    }
    if (check == 0) {
        PRINTF("ClientHello: Keine geeignete CompressionMethod\n");
        return handshake_failure;
    }

    // Extensions checken
    check = 0;
    p += 2;
    while (p < ((uint8_t *) clientHello) + len) {
        PRINTF("Check: 0x%02X\nAktuelle Extension: %02X %02X %02X %02X %02X %02X\n", check, p[0], p[1], p[2], p[3], p[4], p[5]);
        if (p[0] == 0x00) {
            if (p[1] == 0x0A) { // Supported Elliptic Curves
                end = p + (p[4] << 8) + p[5] + 6;
                for (p += 6; p < end; p+=2) {
                    if ((p[0] << 8) + p[1] == secp256r1) {
                        check |= 0x01;
                    }
                }
                continue;
            }
            if (p[1] == 0x0B) { // Supported Point Formats
                end = p + p[4] + 5;
                for (p += 5; p < end; p++) {
                    if (p[0] == 0x00) { // Uncompressed Point
                        check |= 0x10;
                    }
                }
                continue;
            }
        }

        PRINTF("ClientHello: Unbekannte Extension\n");
        return unsupported_extension;
    }
    PRINTF("Check: 0x%02X\n", check);
    if (check != 0x11) {
        PRINTF("ClientHello: Benötigte Extensions nicht vorhanden\n");
        return handshake_failure;
    }

    return 0;
}

__attribute__((always_inline)) static void generateServerHello(uint32_t *buf) {

    if (createSession(buf, src_addr) == -1) return;

    created_offset = stack_size();

    DTLSContent_t *content = (DTLSContent_t *) buf;

    // ServerHello
    content->type = server_hello;
    content->len = con_length_8_bit;
    content->payload[0] = sizeof(ServerHello_t) + 10;

    ServerHello_t *sh = (ServerHello_t *) (content->payload + content->len);
    sh->server_version.major = 3;
    sh->server_version.minor = 3;
    sh->random.gmt_unix_time = uip_htonl(getTime());
    random_x(sh->random.random_bytes, 28);
    sh->session_id.len = getSessionData(sh->session_id.session_id, src_addr, session_id);
    sh->cipher_suite = UIP_HTONS(TLS_PSK_ECDH_WITH_AES_128_CCM_8);
    sh->compression_method = null;
    sh->extensions[0] = 0x00;        // Länge der Extensions
    sh->extensions[1] = 0x08;        // Länge der Extensions
    sh->extensions[2] = 0x00;        // Supported Elliptic Curves Extension
    sh->extensions[3] = 0x0a;        // Supported Elliptic Curves Extension
    sh->extensions[4] = 0x00;        // Länge der Supported Elliptic Curves Extension Daten
    sh->extensions[5] = 0x04;        // Länge der Supported Elliptic Curves Extension Daten
    sh->extensions[6] = 0x00;        // Länge des Elliptic Curves Arrays
    sh->extensions[7] = 0x02;        // Länge des Elliptic Curves Arrays
    sh->extensions[8] = 0x00;        // Elliptic Curve secp256r1
    sh->extensions[9] = 0x23;        // Elliptic Curve secp256r1
    // Keine "Supported Point Formats Extension" entspricht "Uncompressed only"
    stack_push((uint8_t *) buf, sizeof(DTLSContent_t) + 1 + sizeof(ServerHello_t) + 10);

    server_random_offset = created_offset + (uint32_t) sh->random.random_bytes - (uint32_t) buf;

    //ServerKeyExchange
    content->type = server_key_exchange;
    content->len = con_length_8_bit;
    content->payload[0] = sizeof(KeyExchange_t);

    KeyExchange_t *ske = (KeyExchange_t *) (content->payload + content->len);
    ske->pskHint_len = uip_htons(LEN_UUID);
    nvm_getVar(ske->pskHint, RES_UUID, LEN_UUID);
    ske->curve_params.curve_type = named_curve;
    ske->curve_params.namedcurve = secp256r1;
    ske->public_key.len = 65;
    ske->public_key.type = uncompressed;
    stack_push((uint8_t *) buf, sizeof(DTLSContent_t) + 1 + sizeof(KeyExchange_t) - 64); // -64 weil public key danach geschrieben wird

    nvm_getVar(buf + 16, RES_ECC_BASE_X, LEN_ECC_BASE_X);
    nvm_getVar(buf + 24, RES_ECC_BASE_Y, LEN_ECC_BASE_Y);
    #if DEBUG_ECC
        printBytes("BASE_POINT-X", (uint8_t *) (buf + 16), 32);
        printBytes("BASE_POINT-Y", (uint8_t *) (buf + 24), 32);
    #endif
    getSessionData((uint8_t *) (buf + 32), src_addr, session_key);
    #if DEBUG_ECC
        printBytes("Private Key ", (uint8_t *) (buf + 32), 32);
    #endif
    #if DEBUG
        printf("ECC - START\n");
        uint32_t time = *MACA_CLK;
    #endif
    ecc_ec_mult(buf + 16, buf + 24, buf + 32, buf, buf + 8);
    #if DEBUG
        time = *MACA_CLK - time;
        printf("ECC - BEENDET NACH %u MS\n", time / 250);
    #endif
    #if DEBUG_ECC
        printBytes("_S_PUB_KEY-X", (uint8_t *) (buf), 32);
        printBytes("_S_PUB_KEY-Y", (uint8_t *) (buf + 8), 32);
    #endif
    stack_push((uint8_t *) buf, 64);

    //ServerHelloDone
    content->type = server_hello_done;
    content->len = con_length_0;
    stack_push((uint8_t *) buf, sizeof(DTLSContent_t));
}

__attribute__((always_inline)) static void processClientKeyExchange(KeyExchange_t *cke, uint8_t *buf) {
    uint32_t i;

    #if DEBUG_ECC
        printBytes("_C_PUB_KEY-X", (uint8_t *) cke->public_key.x, 32);
        printBytes("_C_PUB_KEY-Y", (uint8_t *) cke->public_key.y, 32);
    #endif

    memcpy(buf + 96, cke->public_key.x, 32);
    memcpy(buf + 128, cke->public_key.y, 32);
    getSessionData((uint8_t *) (buf + 160), src_addr, session_key);
    //  0                   1                   2                   3                   4                   5
    //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // |#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|   Client-Px   |   Client-Py   |  Private-Key  |#|#|#|#|
    #if DEBUG
        printf("ECC - START\n");
        uint32_t time = *MACA_CLK;
    #endif
    ecc_ec_mult((uint32_t *) (buf + 96), (uint32_t *) (buf + 128), (uint32_t *) (buf + 160), (uint32_t *) (buf + 20), (uint32_t *) (buf + 52));
    //  0                   1                   2                   3                   4                   5
    //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // |#|#|#|#|#|   Secret-Px   |   Secret-Py   |#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|
    #if DEBUG
        time = *MACA_CLK - time;
        printf("ECC - BEENDET NACH %u MS\n", time / 250);
    #endif
    #if DEBUG_ECC
        printBytes("SECRET_KEY-X", buf + 20, 32);
        printBytes("SECRET_KEY-Y", buf + 52, 32);
    #endif

    buf[0] = 0;
    buf[1] = 16;
    getPSK(buf + 2);
    buf[18] = 0;
    buf[19] = 64;
    memcpy(buf + 84, "master secret", 13);
    stack_read(buf + 97, client_random_offset, 28);
    stack_read(buf + 125, server_random_offset, 28);
    //  0                   1                   2                   3                   4                   5
    //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // |016PSK064|   Secret-Px   |   Secret-Py   | "master secret" + C-Rand + S-Rand |#|#|#|#|#|#|#|#|#|#|#|#|#|
    #if DEBUG_PRF
        printf("Seed für Master-Secret:\n    ");
        for (i = 0; i < 33; i++) printf("%02X", buf[i]);
        printf("\n    ");
        for (i = 33; i < 65; i++) printf("%02X", buf[i]);
        printf("\n    ");
        for (i = 65; i < 97; i++) printf("%02X", buf[i]);
        printf("\n    ");
        for (i = 97; i < 125; i++) printf("%02X", buf[i]);
        printf("\n    ");
        for (i = 125; i < 153; i++) printf("%02X", buf[i]);
        printf("\n");
    #endif
    prf(buf + 160, 48, buf, 153);
    //  0                   1                   2                   3                   4                   5
    //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // |#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|     Master-Secret     |
    #if DEBUG_PRF
        printf("Master-Secret:\n    ");
        for (i = 160; i < 184; i++) printf("%02X", buf[i]);
        printf("\n    ");
        for (i = 184; i < 208; i++) printf("%02X", buf[i]);
        printf("\n");
    #endif

    memcpy(buf + 40, buf + 160, 48);
    memcpy(buf + 88, "key expansion", 13);
    stack_read(buf + 101, server_random_offset, 28);
    stack_read(buf + 129, client_random_offset, 28);
    //  0                   1                   2                   3                   4                   5
    //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // |#|#|#|#|#|#|#|#|#|#|     Master-Secret     | "key expansion" + S-Rand + C-Rand |     Master-Secret     |
    prf(buf, 40, buf + 40, 117);
    //  0                   1                   2                   3                   4                   5
    //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // |     Key-Block     |#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|     Master-Secret     |
    #if DEBUG_PRF
        printf("Key-Block:\n    ");
        for (i = 0; i < 20; i++) printf("%02X", buf[i]);
        printf("\n    ");
        for (i = 20; i < 40; i++) printf("%02X", buf[i]);
        printf("\n");
    #endif
    insertKeyBlock(src_addr, (KeyBlock_t *) buf);
    //  0                   1                   2                   3                   4                   5
    //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // |#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|     Master-Secret     |
}

__attribute__((always_inline)) static void generateFinished(uint8_t *buf) {
    memcpy(buf + 24, buf + 160, 48);
    memset(buf + 87, 0, 16);
    getPSK(buf + 104);
    stack_read(buf + 120, 0, 16);
    int i;
    for (i = 16; i < stack_size(); i+=16) {
        aes_cmac(buf + 87, buf + 120, 16, buf + 104, 0);
        stack_read(buf + 120, i, 16);
    }
    aes_cmac(buf + 87, buf + 120, stack_size() + 16 - i, buf + 104, 1);
    //  0                   1                   2                   3                   4                   5
    //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // |#|#|#|#|#|#|     Master-Secret     |#|#|#|#| C-MAC |#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|

    memcpy(buf + 72, "client finished", 15);
    prf(buf, 12, buf + 24, 79);
    //  0                   1                   2                   3                   4                   5
    //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // | C-F |#|#|#|     Master-Secret     |#|#|#|#| C-MAC |#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|
    #if DEBUG_PRF
        printBytes("Client Finished", buf, 12);
    #endif

    memcpy(buf + 72, "server finished", 15);
    prf(buf + 12, 12, buf + 24, 79);
    //  0                   1                   2                   3                   4                   5
    //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // | C-F | S-F |#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|#|
    #if DEBUG_PRF
        printBytes("Server Finished", buf + 12, 12);
    #endif
}

void sendServerHello(void *data, void* resp) {
    if (request_metadata->block2_size == 0 || request_metadata->block2_size > 32) {
        request_metadata->block2_size = 32;
    }

    PRINTF("Block %u wird gesendet.\n", request_metadata->block2_num);

    uint8_t buffer[request_metadata->block2_size];
    int8_t read = readServerHello(buffer, request_metadata->block2_num * request_metadata->block2_size, request_metadata->block2_size);

    coap_transaction_t *transaction = NULL;
    if ( (transaction = coap_new_transaction(request_metadata->mid, &request_metadata->addr, request_metadata->port)) ) {
        coap_packet_t response[1];
        coap_separate_resume(response, request_metadata, CREATED_2_01);
        coap_set_header_content_type(response, APPLICATION_OCTET_STREAM);
        coap_set_payload(response, buffer, read == 0 ? request_metadata->block2_size : read);
        coap_set_header_block2(response, request_metadata->block2_num, read == 0 ? 1 : 0, request_metadata->block2_size);
        // TODO Warning: No check for serialization error.
        transaction->packet_len = coap_serialize_message(response, transaction->packet);
        transaction->callback = (read == 0 ? &sendServerHello : NULL);
        coap_send_transaction(transaction);
        request_metadata->block2_num++;
    }
}

__attribute__((always_inline)) static int readServerHello(void *target, uint8_t offset, uint8_t size) {
    uint8_t length = stack_size() - created_offset;

    if (offset >= length) return -1;

    uint8_t readsize = (length - offset);
    if (size < readsize) readsize = size;

    stack_read(target, created_offset + offset, readsize);

    return (offset + readsize) >= length ? readsize : 0;
}
