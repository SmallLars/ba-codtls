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

void generateServerHello();
int8_t readServerHello(void *target, uint8_t offset, uint8_t size);

static uint8_t separate_active = 0;

uint16_t serverHello_offset;

/*************************************************************************/
/*  Ressource für den DTLS-Handshake                                     */
/*************************************************************************/
void dtls_handler(void* request, void* response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset) {
    if (*offset != 0) {
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
        size_t session_len = 0;
        const char *session = NULL;
        if ((session_len = REST.get_query_variable(request, "s", &session))) {
            // ClientKeyExchange + ChangeCypherSpec trifft ein -> Antwort generieren:
            PRINTF("Session: %.*s\n", session_len, session);

            ClientKey_t ck;
            ck.index = 0;
            ck.epoch = 1;
            memcpy(ck.key, "ABCDEFGHIJKLMNOP", 16);
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
                    DTLSContent_t *content = (DTLSContent_t *) buffer;

                    content->type = hello_verify_request;
                    content->len = con_length_8_bit;
                    content->payload[0] = 11;

                    HelloVerifyRequest_t *answer = (HelloVerifyRequest_t *) (content->payload + 1);
                    answer->server_version.major = 3;
                    answer->server_version.minor = 3;
                    answer->cookie_len = 8;
                    memcpy(answer->cookie, "ABCDEFGH", 8); // TODO generieren

                    REST.set_response_status(response, VERIFY_1_02);
                    REST.set_header_content_type(response, APPLICATION_OCTET_STREAM);
                    REST.set_response_payload(response, buffer, 13);
                } else {
                    // ClientHello 2 mit Cookie beantworten

                    // Abspeichern für Finished-Hash
                    stack_init();
                    stack_push((uint8_t *) payload, pay_len);

                    uint8_t *cookie = clienthello->data + session_len + 2; // TODO checken

/*
                    coap_separate_t request_metadata[1];

                    separate_active = 1;
                    coap_separate_accept(request, request_metadata); // ACK + Anfrageinformationen zwischenspeichern
*/
                    generateServerHello(buffer); // Das dauert nun

                    int8_t read = readServerHello(buffer, *offset, preferred_size);
                    REST.set_response_status(response, CREATED_2_01);
                    REST.set_header_content_type(response, APPLICATION_OCTET_STREAM);
                    REST.set_response_payload(response, buffer, read == 0 ? preferred_size : read);
/*
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
                        //coap_set_header_block2(response, 0, 1, preferred_size); // Block 0, Es folgen weiter, Blockgröße 64 = preferred_size
                        coap_set_header_block2(response, request_metadata->block2_num, 0, request_metadata->block2_size);

                        // TODO Warning: No check for serialization error.
                        transaction->packet_len = coap_serialize_message(response, transaction->packet);
                        coap_send_transaction(transaction);
                    }
                    // Erstes Paket senden - ENDE
*/
                }
            }
        }
    }
}

/* ------------------------------------------------------------------------- */

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
    memcpy(ci->ip, (uint8_t *) &UIP_IP_BUF->srcipaddr, 16);
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
    //ecc_ec_mult(base_x, base_y, ci->private_key, result_x, result_y);
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
