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
#include "flash-store.h"

#define DEBUG 1
#define DEBUG_COOKIE 0
#define DEBUG_ECC 0
#define DEBUG_PRF 1

#if DEBUG || DEBUG_COOKIE || DEBUG_ECC || DEBUG_PRF
    #include <stdio.h>
    #include "mc1322x.h"
#endif

#if DEBUG
    #define PRINTF(...) printf(__VA_ARGS__)
#else
    #define PRINTF(...)
#endif

// Die folgenden 3 Funktionen werden nur einmal aufgerufen und dienen lediglich der Codeübersicht.
// Das inline-Keyword wird mit den gesetzten Kompiler-Parametern aufgrund der Funktionsgrößen ignoriert, weshalb das Attribut genutzt wird.
// Bei generateHelloVerifyRequest nimmt die Programmgröße um ca 24 Byte ab während sie bei den anderen gleich bleibt.
// Durch den gesparten Funktionsaufruf nimmt jedoch die Größe des benötigten Stacks erheblich ab.
__attribute__((always_inline)) static void generateHelloVerifyRequest(uint8_t *dst, uint8_t *cookie, size_t cookie_len);
__attribute__((always_inline)) static void generateCookie(uint8_t *dst, DTLSContent_t *data, size_t *data_len);
// TODO processClientHello
__attribute__((always_inline)) static void generateServerHello(uint32_t *buf32);
__attribute__((always_inline)) static void processClientKeyExchange(DTLSContent_t *data, uint32_t *buf32, uint8_t *buf08);

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
        uint8_t *buf08 = (uint8_t *) buf32;

        const char *uri_path = NULL;
        uint8_t uri_len = REST.get_url(request, &uri_path);

        if (uri_len == 4) {
            if (content->type == client_hello) {
                ClientHello_t *clienthello = (ClientHello_t *) (content->payload + content->len);

                uint8_t session_len = clienthello->data[0];
                uint8_t cookie_len = clienthello->data[session_len + 1];
                uint8_t *old_cookie = buf08;
                uint8_t *new_cookie = buf08 + 8;

                if (cookie_len > 0) {
                    // Abspeichern für Finished-Hash
                    stack_init();
                    stack_push(big_msg, big_msg_len);
                    client_random_offset = (uint32_t) clienthello->random.random_bytes - (uint32_t) big_msg;

                    // Übertragenen Cookie in Buffer sichern zum späteren Vergleich
                    memcpy(old_cookie, clienthello->data + session_len + 2, cookie_len);
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
                    coap_separate_accept(request, request_metadata); // ACK + Anfrageinformationen zwischenspeichern

                    // TODO Parameter von ClientHello überprüfen.

                    // ServerHello wird immer gleich generiert da Server nur
                    // genau ein Ciphersuit mit einer Konfiguration beherrscht.
                    generateServerHello(buf32); // Das dauert nun
                    sendServerHello(NULL, request);
                }
            }
        } else {
            uint32_t i;
            // ClientKeyExchange + ChangeCypherSpec trifft ein -> Antwort generieren:
            PRINTF("POST für Session: %.*s erhalten.\n", uri_len - 5, uri_path + 5);
            // TODO check ob ip zur session passt

            coap_separate_accept(request, request_metadata); // ACK + Anfrageinformationen zwischenspeichern

            if (content->type == client_key_exchange) {
                stack_push(big_msg, sizeof(DTLSContent_t) + content->len + sizeof(KeyExchange_t));

                // ClientKeyExchange wird ausgewertet und ein KeyBlock berechnet
                processClientKeyExchange(content, buf32, buf08);

                content += (sizeof(DTLSContent_t) + content->len + sizeof(KeyExchange_t));
                if (content->type == c_change_cipher_spec) {
                    PRINTF("ChangeCipherSpec gefunden. Folgedaten werden entschlüsselt.\n");
                }

                // Finished Nachrichten berechnen
                // buf08 = finished[20] + master_secret[48] + label[15] + hash[16]
                //         0              20                  68          83
                memset(buf08 + 83, 0, 16);
                nvm_getVar(buf08, RES_STACK, 16);
                for (i = 16; i < stack_size(); i+=16) {
                    aes_cmac(buf08 + 83, buf08, 16, 0);
                    nvm_getVar(buf08, RES_STACK + i, 16);
                }
                aes_cmac(buf08 + 83, buf08, stack_size() + 16 - i, 1);
                memcpy(buf08 + 20, buf32 + 40, 48);

                memcpy(buf08 + 68, "client finished", 15);
                prf(buf08, 12, buf08 + 20, 79);
                #if DEBUG_PRF
                    printf("Client Finished: ");
                    for (i = 0; i < 12; i++) printf("%02X", buf08[i]);
                    printf("\n");
                #endif

                // TODO vergleichen mit erhaltenem

                memcpy(buf08 + 68, "server finished", 15);
                prf(buf08, 12, buf08 + 20, 79);
                #if DEBUG_PRF
                    printf("Server Finished: ");
                    for (i = 0; i < 12; i++) printf("%02X", buf08[i]);
                    printf("\n");
                #endif

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
                memcpy(c->payload + 1, buf08, 12);
                // TODO verschlüsseln
            }

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
        printf("Content Länge Input: 0x");
        for (i = 0; i < data->len; i++) PRINTF("%02X", data->payload[i]);
        printf(" (MSB)\n");
    #endif
    uint32_t hello_len = 0;
    memcpy(((uint8_t *) &hello_len) + 4 - data->len, data->payload, data->len);
    hello_len = uip_ntohl(hello_len);
    #if DEBUG_COOKIE
        printf("Content Länge Berechnet: %u\n", hello_len);
        printf("Content Data (mc): ");
        for (i = 0; i < *data_len; i++) PRINTF("%02X", data[i]);
        printf("\n");
    #endif
    // Alten Cookie entfernen falls vorhanden
    uint32_t cookie = data->len + sizeof(ProtocolVersion) + sizeof(Random);
    cookie += (data->payload[cookie] + 1); //Längenfeld und Länge der Session addieren
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
        printf("Content Data (oc): ");
        for (i = 0; i < *data_len; i++) PRINTF("%02X", data[i]);
        printf("\n");
    #endif

    uint8_t mac[16];
    memset(mac, 0, 16);
    aes_cmac(mac, src_addr, 16, 0);
    aes_cmac(mac, data, *data_len, 1);
    memcpy(dst, mac, 8);
}

__attribute__((always_inline)) static void generateServerHello(uint32_t *buf32) {

    if (createSession(buf32, src_addr) == -1) return;

    created_offset = stack_size();

    DTLSContent_t *content = (DTLSContent_t *) buf32;

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
    stack_push((uint8_t *) buf32, sizeof(DTLSContent_t) + 1 + sizeof(ServerHello_t) + 10);

    server_random_offset = created_offset + (uint32_t) sh->random.random_bytes - (uint32_t) buf32;

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
    stack_push((uint8_t *) buf32, sizeof(DTLSContent_t) + 1 + sizeof(KeyExchange_t) - 64); // -64 weil public key danach geschrieben wird

    nvm_getVar(buf32 + 16, RES_ECC_BASE_X, LEN_ECC_BASE_X);
    nvm_getVar(buf32 + 24, RES_ECC_BASE_Y, LEN_ECC_BASE_Y);
    #if DEBUG_ECC
        uint8_t i;
        printf("BASE_POINT-X: ");
        for (i = 16; i < 24; i++) printf("%08X", uip_htonl(buf32[i]));
        printf("\nBASE_POINT-Y: ");
        for (i = 24; i < 32; i++) printf("%08X", uip_htonl(buf32[i]));
        printf("\n");
    #endif
    getSessionData((uint8_t *) (buf32 + 32), src_addr, session_key);
    #if DEBUG_ECC
        printf("Private Key : ");
        for (i = 32; i < 40; i++) printf("%08X", uip_htonl(buf32[i]));;
        printf("\n");
    #endif
    #if DEBUG
        printf("ECC - START\n");
        uint32_t time = *MACA_CLK;
    #endif
    ecc_ec_mult(buf32 + 16, buf32 + 24, buf32 + 32, buf32, buf32 + 8);
    #if DEBUG
        time = *MACA_CLK - time;
        printf("ECC - BEENDET NACH %u MS\n", time / 250);
    #endif
    #if DEBUG_ECC
        printf("_S_PUB_KEY-X: ");
        for (i = 0; i < 8; i++) printf("%08X", uip_htonl(buf32[i]));
        printf("\n_S_PUB_KEY-Y: ");
        for (i = 8; i < 16; i++) printf("%08X", uip_htonl(buf32[i]));
        printf("\n");
    #endif
    stack_push((uint8_t *) buf32, 64);

    //ServerHelloDone
    content->type = server_hello_done;
    content->len = con_length_0;
    stack_push((uint8_t *) buf32, sizeof(DTLSContent_t));
}

__attribute__((always_inline)) static void processClientKeyExchange(DTLSContent_t *content, uint32_t *buf32, uint8_t *buf08) {
    uint32_t i;

    KeyExchange_t *cke = (KeyExchange_t *) (content->payload + content->len);

    #if DEBUG_ECC
        printf("_C_PUB_KEY-X: ");
        for (i = 0; i < 8; i++) printf("%08X", uip_htonl(cke->public_key.x[i]));
        printf("\n_C_PUB_KEY-Y: ");
        for (i = 0; i < 8; i++) printf("%08X", uip_htonl(cke->public_key.y[i]));
        printf("\n");
    #endif

    memcpy(buf32 + 24, cke->public_key.x, 32);
    memcpy(buf32 + 32, cke->public_key.y, 32);
    getSessionData((uint8_t *) (buf32 + 40), src_addr, session_key);
    #if DEBUG
        printf("ECC - START\n");
        uint32_t time = *MACA_CLK;
    #endif
    ecc_ec_mult(buf32 + 24, buf32 + 32, buf32 + 40, buf32 + 5, buf32 + 13);
    #if DEBUG
        time = *MACA_CLK - time;
        printf("ECC - BEENDET NACH %u MS\n", time / 250);
    #endif
    #if DEBUG_ECC
        printf("SECRET_KEY-X: ");
        for (i = 20; i < 52; i++) printf("%02X", buf08[i]);
        printf("\nSECRET_KEY-Y: ");
        for (i = 52; i < 84; i++) printf("%02X", buf08[i]);
        printf("\n");
    #endif

    buf08[0] = 0;
    buf08[1] = 16;
    getPSK(buf08 + 2);
    buf08[18] = 0;
    buf08[19] = 64;
    memcpy(buf08 + 84, "master secret", 13);
    nvm_getVar(buf08 + 97, RES_STACK + client_random_offset, 28);
    nvm_getVar(buf08 + 125, RES_STACK + server_random_offset, 28);
    #if DEBUG_PRF
        printf("Seed für Master-Secret:\n    ");
        for (i = 0; i < 33; i++) printf("%02X", buf08[i]);
        printf("\n    ");
        for (i = 33; i < 65; i++) printf("%02X", buf08[i]);
        printf("\n    ");
        for (i = 65; i < 97; i++) printf("%02X", buf08[i]);
        printf("\n    ");
        for (i = 97; i < 125; i++) printf("%02X", buf08[i]);
        printf("\n    ");
        for (i = 125; i < 153; i++) printf("%02X", buf08[i]);
        printf("\n");
    #endif

    prf((uint8_t *) (buf32 + 40), 48, buf08, 153);
    #if DEBUG_PRF
        printf("Master-Secret:\n    ");
        for (i = 40; i < 46; i++) printf("%02X", uip_htonl(buf32[i]));
        printf("\n    ");
        for (i = 46; i < 52; i++) printf("%02X", uip_htonl(buf32[i]));
        printf("\n");
    #endif

    memcpy(buf08 + 40, buf32 + 40, 48);
    memcpy(buf08 + 88, "key expansion", 13);
    nvm_getVar(buf08 + 101, RES_STACK + server_random_offset, 28);
    nvm_getVar(buf08 + 129, RES_STACK + client_random_offset, 28);
    prf(buf08, 40, buf08 + 40, 117);
    #if DEBUG_PRF
        printf("Key-Block:\n    ");
        for (i = 0; i < 20; i++) printf("%02X", buf08[i]);
        printf("\n    ");
        for (i = 20; i < 40; i++) printf("%02X", buf08[i]);
        printf("\n");
    #endif
    insertKeyBlock(src_addr, (KeyBlock_t *) buf08);
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
