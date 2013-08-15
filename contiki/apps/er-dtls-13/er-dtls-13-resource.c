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

void generateHelloVerifyRequest(uint8_t *dst, DTLSContent_t *data, size_t *data_len);
void generateCookie(uint8_t *dst, DTLSContent_t *data, size_t *data_len);
void generateServerHello(uint8_t *buf);
int8_t readServerHello(void *target, uint8_t offset, uint8_t size);

uint8_t src_ip[16];

static uint8_t separate_active = 0;

uint16_t serverHello_offset;

/*************************************************************************/
/*  Ressource für den DTLS-Handshake                                     */
/*************************************************************************/
void dtls_handler(void* request, void* response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset) {
    memcpy(src_ip, (uint8_t *) &UIP_IP_BUF->srcipaddr, 16);

    if (*offset != 0) {
        printf("OOOHHHHH!\n");
        int8_t read = readServerHello(buffer, *offset, preferred_size);
        PRINTF("Read: %.*s\n", read, buffer);

        REST.set_response_payload(response, buffer, read == 0 ? preferred_size : read);

        if (read == 0) {
            *offset += preferred_size;
        } else {
            *offset = -1;
        }

        return;
    }

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
            c->type = change_cipher_spec;
            c->len = con_length_0;

            REST.set_response_status(response, CHANGED_2_04);
            REST.set_header_content_type(response, APPLICATION_OCTET_STREAM);
            REST.set_response_payload(response, buffer, 1);
        } else {
            DTLSContent_t *content = (DTLSContent_t *) payload;

            if (content->type == client_hello) {
                ClientHello_t *clienthello = (ClientHello_t *) (content->payload + content->len);

                uint8_t session_len = clienthello->data[0];
                uint8_t cookie_len = clienthello->data[session_len + 1];

                if (cookie_len == 0) {
                    // ClientHello 1 ohne Cookie beantworten
                    generateHelloVerifyRequest(buffer, (DTLSContent_t *) payload, &pay_len);

                    REST.set_response_status(response, VERIFY_1_02);
                    REST.set_header_content_type(response, APPLICATION_OCTET_STREAM);
                    REST.set_response_payload(response, buffer, 13);
                } else {
                    // ClientHello 2 mit Cookie beantworten falls Cookie korrekt
                    uint8_t old_cookie[8];
                    uint8_t new_cookie[8];
                    memcpy(old_cookie, clienthello->data + session_len + 2, 8);
                    generateCookie(new_cookie, (DTLSContent_t *) payload, &pay_len);

                    if (memcmp(old_cookie, new_cookie, 8)) {
                        PRINTF("Cookie Falsch!\n");
                        generateHelloVerifyRequest(buffer, (DTLSContent_t *) payload, &pay_len);

                        REST.set_response_status(response, VERIFY_1_02);
                        REST.set_header_content_type(response, APPLICATION_OCTET_STREAM);
                        REST.set_response_payload(response, buffer, 13);

                        return;
                    }
                    PRINTF("Cookie Richtig!\n");

                    // Abspeichern für Finished-Hash
                    stack_init();
                    stack_push((uint8_t *) payload, pay_len);

                    coap_separate_t request_metadata[1];

                    separate_active = 1;
                    coap_separate_accept(request, request_metadata); // ACK + Anfrageinformationen zwischenspeichern

                    generateServerHello(buffer); // Das dauert nun

                    // Erstes Paket senden - START
                    coap_transaction_t *transaction = NULL;
                    if ( (transaction = coap_new_transaction(request_metadata->mid, &request_metadata->addr, request_metadata->port)) ) {
                        coap_packet_t response[1];

                        // Anfrageinformationen wiederherstellen
                        coap_separate_resume(response, request_metadata, REST.status.CREATED);
                        coap_set_header_content_type(response, APPLICATION_OCTET_STREAM);

                        // Payload generieren
                        int8_t read = readServerHello(buffer, 0, preferred_size);
                        coap_set_payload(response, buffer, read == 0 ? preferred_size : read);

                        // Das es sich hier um den ersten von mehreren Blöcken handelt wird die Blockoption gesetzt.
                        coap_set_header_block2(response, 0, 1, preferred_size); // Block 0, Es folgen weiter, Blockgröße 64 = preferred_size
                        //coap_set_header_block2(response, request_metadata->block2_num, 0, request_metadata->block2_size);

                        // TODO Warning: No check for serialization error.
                        transaction->packet_len = coap_serialize_message(response, transaction->packet);
                        coap_send_transaction(transaction);

                        // Payload generieren
                        read = readServerHello(buffer, preferred_size, preferred_size);
                        coap_set_payload(response, buffer, read == 0 ? preferred_size : read);

                        // Das es sich hier um den ersten von mehreren Blöcken handelt wird die Blockoption gesetzt.
                        coap_set_header_block2(response, 1, 0, preferred_size); // Block 0, Es folgen weiter, Blockgröße 64 = preferred_size
                        //coap_set_header_block2(response, request_metadata->block2_num, 0, request_metadata->block2_size);

                        // TODO Warning: No check for serialization error.
                        transaction->packet_len = coap_serialize_message(response, transaction->packet);
                        coap_send_transaction(transaction);
                    }
                    // Erstes Paket senden - ENDE
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

    #if DEBUG
        PRINTF("Content Länge Input: 0x");
        for (i = 0; i < data->len; i++) PRINTF("%02X", data->payload[i]);
        PRINTF(" (MSB)\n");
    #endif
    uint32_t hello_len = 0;
    memcpy(((uint8_t *) &hello_len) + 4 - data->len, data->payload, data->len);
    hello_len = uip_ntohl(hello_len);
    PRINTF("Content Länge Berechnet: %u\n", hello_len);

    #if DEBUG
        PRINTF("Content Data (mc): ");
        for (i = 0; i < *data_len; i++) PRINTF("%02X", data[i]);
        PRINTF("\n");
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
    #if DEBUG
        PRINTF("Content Data (oc): ");
        for (i = 0; i < *data_len; i++) PRINTF("%02X", data[i]);
        PRINTF("\n");
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

    serverHello_offset = stack_size();

    DTLSContent_t *content = (DTLSContent_t *) buf;

    content->type = server_hello;
    content->len = con_length_8_bit;
    content->payload[0] = sizeof(ServerHello_t);

    ServerHello_t *answer = (ServerHello_t *) (content->payload + content->len);
    answer->server_version.major = 3;
    answer->server_version.minor = 3;
    answer->random.gmt_unix_time = uip_htonl(getTime());
    random_x(answer->random.random_bytes, 28);
    answer->session_id.len = 8;
    memcpy (answer->session_id.session_id, "IJKLMNOP", 8); // TODO generieren
    answer->cipher_suite = TLS_ECDH_anon_WITH_AES_128_CCM_8;
    answer->compression_method = null;
    // TODO answer->extensions;
    stack_push(buf, sizeof(DTLSContent_t) + 1 + sizeof(ServerHello_t));

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

    uint32_t result_x[8];
    uint32_t result_y[8];
    uint32_t base_x[8];
    uint32_t base_y[8];
    nvm_getVar((void *) base_x, RES_ECC_BASE_X, LEN_ECC_BASE_X);
    nvm_getVar((void *) base_y, RES_ECC_BASE_Y, LEN_ECC_BASE_Y);
    printf("ECC - START\n");
    ecc_ec_mult(base_x, base_y, ci->private_key, result_x, result_y);
    printf("ECC - ENDE\n");

    memset(buf, 'A', 64);
    stack_push(buf, 64);
}

int8_t readServerHello(void *target, uint8_t offset, uint8_t size) {
    uint8_t length = stack_size() - serverHello_offset;

    if (offset >= length) return -1;

    uint8_t readsize = (length - offset);
    if (size < readsize) readsize = size;

    nvm_getVar(target, RES_STACK + serverHello_offset + offset, readsize);

    return (offset + readsize) >= length ? readsize : 0;
}
