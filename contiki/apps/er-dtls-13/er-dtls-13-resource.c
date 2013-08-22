#include "er-dtls-13-resource.h"

#include <string.h>

#include "erbium.h"
#include "er-coap-13.h"
#include "er-coap-13-separate.h"
#include "er-coap-13-transactions.h"
#include "er-dtls-13.h"
#include "er-dtls-13-data.h"
#include "er-dtls-13-random.h"
#include "flash-store.h"

#define DEBUG 1

#if DEBUG
    #include <stdio.h>
    #define PRINTF(...) printf(__VA_ARGS__)
#else
    #define PRINTF(...)
#endif

#define DEBUG_COOKIE 0

#if DEBUG_COOKIE
    #include <stdio.h>
    #define PRINTFC(...) printf(__VA_ARGS__)
#else
    #define PRINTFC(...)
#endif

#define DEBUG_ECC 0

#if DEBUG_ECC
    #include <stdio.h>
    #define PRINTFE(...) printf(__VA_ARGS__)
#else
    #define PRINTFE(...)
#endif

// Die folgenden 3 Funktionen werden nur einmal aufgerufen und dienen lediglich der Codeübersicht.
// Das inline-Keyword wird mit den gesetzten Kompiler-Parametern aufgrund der Funktionsgrößen ignoriert, weshalb das Attribut genutzt wird.
// Bei generateHelloVerifyRequest nimmt die Programmgröße um ca 24 Byte ab während sie bei den anderen gleich bleibt.
// Durch den gesparten Funktionsaufruf nimmt jedoch die Größe des benötigten Stacks erheblich ab.
__attribute__((always_inline)) static void generateHelloVerifyRequest(uint8_t *dst, uint8_t *cookie, size_t cookie_len);
__attribute__((always_inline)) static void generateCookie(uint8_t *dst, DTLSContent_t *data, size_t *data_len);
__attribute__((always_inline)) static void generateServerHello(uint32_t *buf32);

void sendServerHello(void *data, void* resp);
int8_t readServerHello(void *target, uint8_t offset, uint8_t size);

uint8_t src_ip[16];

uint8_t handshake_step = 0; // 1 Handshake zur Zeit. 1 = created, 2 = changed. zurück auf 0 bei ersten daten
uint16_t created_offset;
uint16_t changed_offset;

coap_separate_t request_metadata[1];

/*************************************************************************/
/*  Ressource für den DTLS-Handshake                                     */
/*************************************************************************/
void dtls_handler(void* request, void* response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset) {
    memcpy(src_ip, (uint8_t *) &UIP_IP_BUF->srcipaddr, 16);

    uint32_t buf32[16];
    uint8_t *buf08 = (uint8_t *) buf32;

    const uint8_t *payload = 0;
    size_t pay_len = REST.get_request_payload(request, &payload);
    if (pay_len && payload) {
        size_t query_session_len = 0;
        const char *query_session = NULL;
        if ((query_session_len = REST.get_query_variable(request, "s", &query_session))) {
            uint32_t i;
            // ClientKeyExchange + ChangeCypherSpec trifft ein -> Antwort generieren:
            PRINTF("POST für Session: %.*s erhalten.\n", query_session_len, query_session);

            coap_separate_accept(request, request_metadata); // ACK + Anfrageinformationen zwischenspeichern

            DTLSContent_t *content = (DTLSContent_t *) payload;
            KeyExchange_t *cke = (KeyExchange_t *) (content->payload + content->len);

            stack_push((uint8_t *) payload, sizeof(DTLSContent_t) + content->len + sizeof(KeyExchange_t));

            #if DEBUG_ECC
                PRINTFE("_C_PUB_KEY-X: ");
                for (i = 0; i < 8; i++) PRINTFE("%08X", uip_htonl(cke->public_key.x[i]));
                PRINTFE("\n_C_PUB_KEY-Y: ");
                for (i = 0; i < 8; i++) PRINTFE("%08X", uip_htonl(cke->public_key.y[i]));
                PRINTFE("\n");
            #endif

            uint32_t private_key[8];
            getPrivateKey(private_key, src_ip);
            #if DEBUG_ECC
                PRINTFE("Private Key : ");
                for (i = 0; i < 8; i++) PRINTFE("%08X", uip_htonl(private_key[i]));;
                PRINTFE("\n");
            #endif

            uint32_t point[16];
            memcpy(point, cke->public_key.x, 32);
            memcpy(point + 8, cke->public_key.y, 32);
            PRINTF("ECC - START\n");
            ecc_ec_mult(point, point + 8, private_key, buf32, buf32 + 8);
            PRINTF("ECC - ENDE\n");
            #if DEBUG_ECC
                PRINTFE("SECRET_KEY-X: ");
                for (i = 0; i < 32; i++) PRINTFE("%02X", buf08[i]);
                PRINTFE("\nSECRET_KEY-Y: ");
                for (i = 32; i < 64; i++) PRINTFE("%02X", buf08[i]);
                PRINTFE("\n");
            #endif

            ClientKey_t *ck = (ClientKey_t *) buf08;
            ck->index = 0;          
            ck->epoch = 1;
            memcpy(ck->key_block, "ABCDEFGHIJKLMNOPABCDEFGHIJKLMNOP11111111", 40);  
            insertKey(ck);

            DTLSContent_t *c;

            c = (DTLSContent_t *) buffer;
            c->type = c_change_cipher_spec;
            c->len = con_length_8_bit;
            c->payload[0] = 1;
            c->payload[1] = 1;
/*
            c = (DTLSContent_t *) (buffer + 3);
            c->type = c_change_cipher_spec;
            c->len = con_length_8_bit;
            c->payload[0] = 12;
            
            uint8_t mac[16];
            uint8_t tmp[16];
            memset(mac, 0, 16);
            uint8_t rest = stack_size() % 16;
            for (i = 0; i < stack_size() - rest; i+=16) {
                nvm_getVar(tmp, RES_STACK + i, 16);
                cbc_mac_16(mac, tmp, 16);
            }
            printf("Size: %u, Rest: %u, I: %u\n", stack_size(), rest, i);
            nvm_getVar(tmp, RES_STACK + i, rest);
            cbc_mac_16(mac, tmp, 16);
*/

            coap_transaction_t *transaction = NULL;
            if ( (transaction = coap_new_transaction(request_metadata->mid, &request_metadata->addr, request_metadata->port)) ) {
                coap_packet_t response[1];
                coap_separate_resume(response, request_metadata, REST.status.CHANGED);
                coap_set_header_content_type(response, APPLICATION_OCTET_STREAM);
                coap_set_payload(response, buffer, 3);
                // TODO Warning: No check for serialization error.
                transaction->packet_len = coap_serialize_message(response, transaction->packet);
                transaction->callback = NULL;
                coap_send_transaction(transaction);
            }
        } else {
            DTLSContent_t *content = (DTLSContent_t *) payload;

            if (content->type == client_hello) {
                ClientHello_t *clienthello = (ClientHello_t *) (content->payload + content->len);

                uint8_t session_len = clienthello->data[0];
                uint8_t cookie_len = clienthello->data[session_len + 1];
                uint8_t *old_cookie = buf08;
                uint8_t *new_cookie = buf08 + 8;

                if (cookie_len > 0) {
                    // Abspeichern für Finished-Hash
                    stack_init();
                    stack_push((uint8_t *) payload, pay_len);

                    // Übertragenen Cookie in Buffer sichern zum späteren Vergleich
                    memcpy(old_cookie, clienthello->data + session_len + 2, cookie_len);
                }

                generateCookie(new_cookie, content, &pay_len);

                if (cookie_len == 0 || memcmp(old_cookie, new_cookie, 8)) {
                    #if DEBUG
                        if (cookie_len == 0) PRINTF("ClientHello ohne Cookie erhalten\n");
                        else PRINTF("ClientHello mit falschem Cookie erhalten\n");
                    #endif
                    generateHelloVerifyRequest(buffer, new_cookie, 8);

                    REST.set_response_status(response, VERIFY_1_02);
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
        }
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
        PRINTFC("Content Länge Input: 0x");
        for (i = 0; i < data->len; i++) PRINTF("%02X", data->payload[i]);
        PRINTFC(" (MSB)\n");
    #endif
    uint32_t hello_len = 0;
    memcpy(((uint8_t *) &hello_len) + 4 - data->len, data->payload, data->len);
    hello_len = uip_ntohl(hello_len);
    PRINTFC("Content Länge Berechnet: %u\n", hello_len);

    #if DEBUG_COOKIE
        PRINTFC("Content Data (mc): ");
        for (i = 0; i < *data_len; i++) PRINTF("%02X", data[i]);
        PRINTFC("\n");
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
        PRINTFC("Content Data (oc): ");
        for (i = 0; i < *data_len; i++) PRINTF("%02X", data[i]);
        PRINTFC("\n");
    #endif

    uint8_t mac[16];
    memset(mac, 0, 16);
    cbc_mac_16(mac, src_ip, 16);
    cbc_mac_16(mac, data, *data_len);
    memcpy(dst, mac, 8);
}

__attribute__((always_inline)) static void generateServerHello(uint32_t *buf32) {
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
    sh->session_id.len = 8;
    memcpy (sh->session_id.session_id, "IJKLMNOP", 8); // TODO generieren
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

    ClientInfo_t *ci = (ClientInfo_t *) buf32;
    memset(ci, 0, sizeof(ClientInfo_t));
    memcpy(ci->ip, src_ip, 16);
    memcpy(ci->session, "IJKLMNOP", 8);
    ci->epoch = 1;
    ci->pending = 1;
    do {
        random_x((uint8_t *) ci->private_key, 32);
    } while (!ecc_is_valid_key(ci->private_key));
    insertClient(ci);

    #if DEBUG_ECC
        uint8_t i;
        PRINTFE("Private Key : ");
        for (i = 0; i < 8; i++) PRINTFE("%08X", uip_htonl(ci->private_key[i]));;
        PRINTFE("\n");
    #endif
    uint32_t base_x[8];
    uint32_t base_y[8];
    nvm_getVar((void *) base_x, RES_ECC_BASE_X, LEN_ECC_BASE_X);
    nvm_getVar((void *) base_y, RES_ECC_BASE_Y, LEN_ECC_BASE_Y);
    #if DEBUG_ECC
        PRINTFE("BASE_POINT-X: ");
        for (i = 0; i < 8; i++) PRINTFE("%08X", uip_htonl(base_x[i]));
        PRINTFE("\nBASE_POINT-Y: ");
        for (i = 0; i < 8; i++) PRINTFE("%08X", uip_htonl(base_y[i]));
        PRINTFE("\n");
    #endif
    PRINTF("ECC - START\n");
    uint32_t private_key[8];
    getPrivateKey(private_key, src_ip);
    ecc_ec_mult(base_x, base_y, private_key, buf32, buf32 + 8);
    PRINTF("ECC - ENDE\n");
    #if DEBUG_ECC
        uint8_t *buf = (uint8_t *) buf32;
        PRINTFE("_S_PUB_KEY-X: ");
        for (i = 0; i < 32; i++) PRINTFE("%02X", buf[i]);
        PRINTFE("\n_S_PUB_KEY-Y: ");
        for (i = 32; i < 64; i++) PRINTFE("%02X", buf[i]);
        PRINTFE("\n");
    #endif
    stack_push((uint8_t *) buf32, 64);

    //ServerHelloDone
    content->type = server_hello_done;
    content->len = con_length_0;
    stack_push((uint8_t *) buf32, sizeof(DTLSContent_t));
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
