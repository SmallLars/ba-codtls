/*
   handshake_failure
      Reception of a handshake_failure alert message indicates that the
      sender was unable to negotiate an acceptable set of security
      parameters given the options available.  This is a fatal error.


   illegal_parameter
      A field in the handshake was out of range or inconsistent with
      other fields.  This message is always fatal.


   decrypt_error
      A handshake cryptographic operation failed, including being unable
      to correctly verify a signature or validate a Finished message.
      This message is always fatal.
*/


#include "er-dtls-13-resource.h"

#include <string.h>

#include "erbium.h"
#include "er-coap-13.h"
#include "er-coap-13-separate.h"
#include "er-coap-13-transactions.h"
#include "er-coap-13-block1.h"
#include "er-dtls-13.h"
#include "er-dtls-13-data.h"
#include "er-dtls-13-random.h"
#include "er-dtls-13-aes.h"
#include "er-dtls-13-prf.h"
#include "er-dtls-13-psk.h"
#include "time.h"
#include "ecc.h"
#include "flash-store.h"

#define DEBUG 1
#define DEBUG_COOKIE 0
#define DEBUG_ECC 0
#define DEBUG_PRF 1
#define DEBUG_FIN 1

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
__attribute__((always_inline)) static  int checkClientHello(ClientHello_t *clientHello, size_t len);
__attribute__((always_inline)) static void generateServerHello(uint32_t *buf);
__attribute__((always_inline)) static void processClientKeyExchange(KeyExchange_t *cke, uint8_t *buf);
__attribute__((always_inline)) static void generateFinished(uint8_t *buf);

void sendServerHello(void *data, void* resp);
int8_t readServerHello(void *target, uint8_t offset, uint8_t size);

uip_ipaddr_t src_addr[1];
coap_separate_t request_metadata[1];

uint8_t big_msg[128];
size_t big_msg_len;

uint8_t handshake_step = 0; // 1 Handshake zur Zeit. 1 = created, 2 = changed. zurück auf 0 bei ersten daten
uint16_t created_offset;
uint16_t changed_offset;
uint16_t client_random_offset;
uint16_t server_random_offset;

/*************************************************************************/
/*  Ressource für den DTLS-Handshake                                     */
/*************************************************************************/
void dtls_handler(void* request, void* response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset) {
    uip_ipaddr_copy(src_addr, &UIP_IP_BUF->srcipaddr);

    if (coap_block1_handler(request, response, big_msg, &big_msg_len, 128)) {
        return;
    }

    if (big_msg_len > 0) {
        DTLSContent_t *content = (DTLSContent_t *) big_msg;

        uint32_t buf32[52];
        uint8_t *buf = (uint8_t *) buf32;

        const char *uri_path = NULL;
        uint8_t uri_len = REST.get_url(request, &uri_path);

        if (uri_len == 4) {
            if (content->type != client_hello) {
                PRINTF("Erwartetes ClientHello nicht erhalten\n");
                // TODO fatal, illegal_parameter
                return;
            }

            ClientHello_t *clienthello = (ClientHello_t *) (content->payload + content->len);

            uint8_t cookie_len = clienthello->data[0];
            uint8_t *old_cookie = buf;
            uint8_t *new_cookie = buf + 8;

            if (cookie_len > 0) {
                // Abspeichern für Finished-Hash
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

                REST.set_response_status(response, UNAUTHORIZED_4_01);
                REST.set_header_content_type(response, APPLICATION_OCTET_STREAM);
                REST.set_response_payload(response, buffer + 1, buffer[0]);
            } else {
                PRINTF("ClientHello mit korrektem Cookie erhalten\n");

                if (checkClientHello(clienthello, big_msg_len - (sizeof(DTLSContent_t) + content->len))) {
                    PRINTF("ClientHello enthält keine unterstützten Werte\n");
                    // TODO fatal, handshake_failure
                    return;
                }

                coap_separate_accept(request, request_metadata); // ACK + Anfrageinformationen zwischenspeichern

                // ServerHello wird immer gleich generiert da Server nur
                // genau ein Ciphersuit mit einer Konfiguration beherrscht.
                generateServerHello(buf32); // Das dauert nun
                sendServerHello(NULL, request);
            }
        } else {
            PRINTF("POST für Session: %.*s erhalten.\n", uri_len - 5, uri_path + 5);

            if (getSessionData(buf, src_addr, session_id) < 0 || memcmp(buf, uri_path + 5, 8)) {
                PRINTF("Ressource existiert nicht\n");
                // TODO coap error
                return;
            }

            coap_separate_accept(request, request_metadata); // ACK + Anfrageinformationen zwischenspeichern

            if (content->type != client_key_exchange) {
                PRINTF("Erwartetes ClientKeyExchange nicht erhalten\n");
                // TODO fatal, ???
                return;
            }

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
            if (content->type != c_change_cipher_spec) {
                PRINTF("Erwartetes ChangeCipherSpec nicht erhalten\n");
                // TODO fatal, ???
                return;
            }

            content += 3; // TODO

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
            aes_crypt((uint8_t *) content, 14, buf + 36, buf + 24, 0);
            // TODO MAC-Check

            if (content->type != finished) {
                PRINTF("Erwartetes Finished nicht erhalten\n");
                // TODO fatal, ???
                return;
            }

            #if DEBUG_FIN
                printBytes("Client Finished gefunden", ((uint8_t *) content) + 2, 12);
            #endif

            // TODO vergleich des clientfinished

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

            coap_transaction_t *transaction = NULL;
            if ( (transaction = coap_new_transaction(request_metadata->mid, &request_metadata->addr, request_metadata->port)) ) {
                coap_packet_t response[1];
                coap_separate_resume(response, request_metadata, REST.status.CHANGED);
                coap_set_header_content_type(response, APPLICATION_OCTET_STREAM);
                coap_set_payload(response, buffer, 25); // TODO Länge anpassen
                // TODO Warning: No check for serialization error.
                transaction->packet_len = coap_serialize_message(response, transaction->packet);
                transaction->callback = NULL;
                coap_send_transaction(transaction);
            }
        }

        big_msg_len = 0;
    }
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
    aes_cmac(mac, src_addr->u8, 16, 0);
    aes_cmac(mac, (uint8_t *) data, *data_len, 1);
    memcpy(dst, mac, 8);
}

__attribute__((always_inline)) static  int checkClientHello(ClientHello_t *clientHello, size_t len) {
    // TODO
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
    sh->cipher_suite = TLS_ECDH_anon_WITH_AES_128_CCM_8;
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
    nvm_getVar(buf + 97, RES_STACK + client_random_offset, 28);
    nvm_getVar(buf + 125, RES_STACK + server_random_offset, 28);
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
    nvm_getVar(buf + 101, RES_STACK + server_random_offset, 28);
    nvm_getVar(buf + 129, RES_STACK + client_random_offset, 28);
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
    nvm_getVar(buf + 104, RES_STACK, 16);
    int i;
    for (i = 16; i < stack_size(); i+=16) {
        aes_cmac(buf + 87, buf + 104, 16, 0);
        nvm_getVar(buf + 104, RES_STACK + i, 16);
    }
    aes_cmac(buf + 87, buf + 104, stack_size() + 16 - i, 1);
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
        coap_separate_resume(response, request_metadata, REST.status.CREATED);
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

int8_t readServerHello(void *target, uint8_t offset, uint8_t size) {
    uint8_t length = stack_size() - created_offset;

    if (offset >= length) return -1;

    uint8_t readsize = (length - offset);
    if (size < readsize) readsize = size;

    nvm_getVar(target, RES_STACK + created_offset + offset, readsize);

    return (offset + readsize) >= length ? readsize : 0;
}
