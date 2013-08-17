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


void generateHelloVerifyRequest(uint8_t *dst, DTLSContent_t *data, size_t *data_len);
void generateCookie(uint8_t *dst, DTLSContent_t *data, size_t *data_len);
void generateServerHello(uint8_t *buf);
int8_t readServerHello(void *target, uint8_t offset, uint8_t size);

uint8_t src_ip[16];

uint8_t handshake_step = 0; // 1 Handshake zur Zeit. 1 = created, 2 = changed. zurück auf 0 bei ersten daten
uint16_t created_offset;
uint16_t changed_offset;

/*************************************************************************/
/*  Ressource für den DTLS-Handshake                                     */
/*************************************************************************/
void dtls_handler(void* request, void* response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset) {
    memcpy(src_ip, (uint8_t *) &UIP_IP_BUF->srcipaddr, 16);

    const uint8_t *payload = 0;
    size_t pay_len = REST.get_request_payload(request, &payload);
    if (pay_len && payload) {
        size_t query_session_len = 0;
        const char *query_session = NULL;
        if ((query_session_len = REST.get_query_variable(request, "s", &query_session))) {
            // ClientKeyExchange + ChangeCypherSpec trifft ein -> Antwort generieren:
            PRINTF("Session: %.*s\n", query_session_len, query_session);

            ClientKey_t ck;
            ck.index = 0;          
            ck.epoch = 1;
            memcpy(ck.client_write_key, "ABCDEFGHIJKLMNOP", 16);  
            memcpy(ck.server_write_key, "ABCDEFGHIJKLMNOP", 16);
            memset(ck.client_write_IV, 1, 4);
            memset(ck.server_write_IV, 1, 4);
            insertKey(&ck);

            DTLSContent_t *c = (DTLSContent_t *) buffer;
            c->type = c_change_cipher_spec;
            c->len = con_length_8_bit;
            c->payload[0] = 1;
            c->payload[1] = 1;

            REST.set_response_status(response, CHANGED_2_04);
            REST.set_header_content_type(response, APPLICATION_OCTET_STREAM);
            REST.set_response_payload(response, buffer, 3);
        } else {
            DTLSContent_t *content = (DTLSContent_t *) payload;

            if (content->type == client_hello) {
                ClientHello_t *clienthello = (ClientHello_t *) (content->payload + content->len);

                uint8_t session_len = clienthello->data[0];
                uint8_t cookie_len = clienthello->data[session_len + 1];

                if (cookie_len == 0) {
                    // ClientHello 1 ohne Cookie beantworten
                    PRINTF("ClientHello ohne Cookie erhalten\n");
                    generateHelloVerifyRequest(buffer, (DTLSContent_t *) payload, &pay_len);

                    REST.set_response_status(response, VERIFY_1_02);
                    REST.set_header_content_type(response, APPLICATION_OCTET_STREAM);
                    REST.set_response_payload(response, buffer, 13);
                } else {
                    // Abspeichern für Finished-Hash
                    stack_init();
                    stack_push((uint8_t *) payload, pay_len);

                    // ClientHello 2 mit Cookie beantworten falls Cookie korrekt
                    uint8_t old_cookie[8];
                    uint8_t new_cookie[8];
                    memcpy(old_cookie, clienthello->data + session_len + 2, 8);
                    generateCookie(new_cookie, (DTLSContent_t *) payload, &pay_len);

                    if (memcmp(old_cookie, new_cookie, 8)) {
                        PRINTF("ClientHello mit falschem Cookie erhalten\n");
                        generateHelloVerifyRequest(buffer, (DTLSContent_t *) payload, &pay_len);

                        REST.set_response_status(response, VERIFY_1_02);
                        REST.set_header_content_type(response, APPLICATION_OCTET_STREAM);
                        REST.set_response_payload(response, buffer, 13);

                        return;
                    }
                    PRINTF("ClientHello mit korrektem Cookie erhalten\n");

                    coap_separate_t request_metadata[1];
                    coap_separate_accept(request, request_metadata); // ACK + Anfrageinformationen zwischenspeichern

                    generateServerHello(buffer); // Das dauert nun

                    int8_t read = readServerHello(buffer, 0, preferred_size);
                    uint8_t i = 0;
                    while (read >= 0) {
                        coap_transaction_t *transaction = NULL;
                        if ( (transaction = coap_new_transaction(request_metadata->mid, &request_metadata->addr, request_metadata->port)) ) {
                            coap_packet_t response[1];
                            coap_separate_resume(response, request_metadata, REST.status.CREATED);
                            coap_set_header_content_type(response, APPLICATION_OCTET_STREAM);
                            coap_set_payload(response, buffer, read == 0 ? preferred_size : read);
                            coap_set_header_block2(response, i, read == 0 ? 1 : 0, preferred_size);
                            // TODO Warning: No check for serialization error.
                            transaction->packet_len = coap_serialize_message(response, transaction->packet);
                            coap_send_transaction(transaction);
                            i++;
                            read = readServerHello(buffer, i * preferred_size, preferred_size);
                        }
                    }
                }
            }
        }
    }
}

/* ------------------------------------------------------------------------- */

void generateHelloVerifyRequest(uint8_t *dst, DTLSContent_t *data, size_t *data_len) {
    DTLSContent_t *content = (DTLSContent_t *) dst;

    content->type = hello_verify_request;
    content->len = con_length_8_bit;
    content->payload[0] = 11;

    HelloVerifyRequest_t *answer = (HelloVerifyRequest_t *) (content->payload + 1);
    answer->server_version.major = 3;
    answer->server_version.minor = 3;
    answer->cookie_len = 8;
    generateCookie(answer->cookie, data, data_len);
}

void generateCookie(uint8_t *dst, DTLSContent_t *data, size_t *data_len) {
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

void generateServerHello(uint8_t *buf) {
    #if DEBUG
        if (REST_MAX_CHUNK_SIZE < 64) PRINTF("ACHTUNG - Buffer zu klein!\n");
    #endif

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
    stack_push(buf, sizeof(DTLSContent_t) + 1 + sizeof(ServerHello_t) + 10);

    //ServerKeyExchange
    content->type = server_key_exchange;
    content->len = con_length_8_bit;
    content->payload[0] = sizeof(ServerKeyExchange_t);

    ServerKeyExchange_t *ske = (ServerKeyExchange_t *) (content->payload + content->len);
    ske->curve_params.curve_type = named_curve;
    ske->curve_params.namedcurve = secp256r1;
    ske->public_key.len = 65;
    ske->public_key.type = uncompressed;
    stack_push(buf, sizeof(DTLSContent_t) + 1 + 5);

    ClientInfo_t *ci = (ClientInfo_t *) buf;
    memset(ci, 0, sizeof(ClientInfo_t));
    memcpy(ci->ip, src_ip, 16);
    memcpy(ci->session, "IJKLMNOP", 8);
    ci->epoch = 1;
    ci->pending = 1;
    do {
        random_x((uint8_t *) ci->private_key, 32);
    } while (!ecc_is_valid_key(ci->private_key));
    insertClient(ci);

    uint32_t result[16];
    uint32_t base_x[8];
    uint32_t base_y[8];
    nvm_getVar((void *) base_x, RES_ECC_BASE_X, LEN_ECC_BASE_X);
    nvm_getVar((void *) base_y, RES_ECC_BASE_Y, LEN_ECC_BASE_Y);
    PRINTF("ECC - START\n");
    ecc_ec_mult(base_x, base_y, ci->private_key, result, result + 8);
    PRINTF("ECC - ENDE\n");
    stack_push((uint8_t *) result, 64);

    buf[0] = 0x00; 
    buf[1] = LEN_UUID;
    nvm_getVar(buf + 2, RES_UUID, LEN_UUID);
    stack_push(buf, 2 + LEN_UUID);

    //ServerHelloDone
    content->type = server_hello_done;
    content->len = con_length_0;
    stack_push(buf, sizeof(DTLSContent_t));
}

int8_t readServerHello(void *target, uint8_t offset, uint8_t size) {
    uint8_t length = stack_size() - created_offset;

    if (offset >= length) return -1;

    uint8_t readsize = (length - offset);
    if (size < readsize) readsize = size;

    nvm_getVar(target, RES_STACK + created_offset + offset, readsize);

    return (offset + readsize) >= length ? readsize : 0;
}
