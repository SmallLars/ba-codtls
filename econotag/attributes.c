#include <string.h>

#include <erbium.h>
#include <er-coap-13.h>
#include <er-coap-13-separate.h>
#include <er-coap-13-transactions.h>

#include "mc1322x.h"
#include "flash-store.h"

/*
static uint8_t separate_active = 0;

void device_handler(void* request, void* response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset) {
    if (separate_active) {
            coap_separate_reject();
    } else {
        if (*offset == 0) {
            coap_separate_t request_metadata[1];

            separate_active = 1;
            coap_separate_accept(request, request_metadata); // ACK + Anfrageinformationen zwischenspeichern

            // Hier wäre möglich: Zeug das dauert

            // Erstes Paket senden - START
            coap_transaction_t *transaction = NULL;
            if ( (transaction = coap_new_transaction(request_metadata->mid, &request_metadata->addr, request_metadata->port)) ) {
                coap_packet_t response[1];

                // Anfrageinformationen wiederherstellen
                coap_separate_resume(response, request_metadata, REST.status.OK);

                // Payload generieren
                memset(buffer, 0x30, preferred_size);
                coap_set_payload(response, buffer, preferred_size);

                // Das es sich hier um den ersten von mehreren Blöcken handelt wird die Blockoption gesetzt.
                coap_set_header_block2(response, 0, 1, preferred_size); // Block 0, Es folgen weitere, Blockgröße 64 = preferred_size

                // TODO Warning: No check for serialization error.
                transaction->packet_len = coap_serialize_message(response, transaction->packet);
                coap_send_transaction(transaction);
            }
            // Erstes Paket senden - ENDE

            separate_active = 0;
        } else {
            int i;
            for (i = 0; i < preferred_size; i+=2) sprintf(buffer + i, "%02X", *offset);
            REST.set_response_payload(response, buffer, preferred_size);
            *offset += preferred_size;
            if (*offset > 250) *offset = -1;
        }
    }
}
*/

void device_handler(void* request, void* response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset) {
    size_t query_len = 0;
    const char *query = NULL;
    if ((query_len = REST.get_query_variable(request, "i", &query))) {

        //*************************************************************************
        //*  DEVICE NAME                                                          *
        //*************************************************************************
        if (query[0] == 'n') {
            nvm_getVar(buffer, RES_NAME, LEN_NAME);
            buffer[REST_MAX_CHUNK_SIZE - 1] = 0;
            REST.set_response_status(response, CONTENT_2_05);
            REST.set_header_content_type(response, TEXT_PLAIN);
            REST.set_response_payload(response, buffer, LEN_NAME);
            /*
            int i;
            for (i = 0; i < preferred_size; i+=2) sprintf(buffer + i, "%02X", *offset);
            REST.set_response_status(response, CONTENT_2_05);
            REST.set_header_content_type(response, TEXT_PLAIN);
            REST.set_response_payload(response, buffer, preferred_size);
            *offset += preferred_size;
            if (*offset > 250) *offset = -1;
            */
        }

        //*************************************************************************
        //*  DEVICE MODEL                                                         *
        //*************************************************************************
        if (query[0] == 'm') {
            nvm_getVar(buffer, RES_MODEL, LEN_MODEL);
            buffer[REST_MAX_CHUNK_SIZE - 1] = 0;
            REST.set_response_status(response, CONTENT_2_05);
            REST.set_header_content_type(response, TEXT_PLAIN);
            REST.set_response_payload(response, buffer, LEN_MODEL);
            return;
        }

        //*************************************************************************
        //*  DEVICE IDENTIFIER                                                    *
        //*************************************************************************
        if (query[0] == 'u') {
            nvm_getVar(buffer, RES_UUID, LEN_UUID);
            buffer[REST_MAX_CHUNK_SIZE - 1] = 0;
            REST.set_response_status(response, CONTENT_2_05);
            REST.set_header_content_type(response, APPLICATION_OCTET_STREAM);
            REST.set_response_payload(response, buffer, LEN_UUID);
        }

        //*************************************************************************
        //*  DEVICE TIME                                                          *
        //*************************************************************************
        if (query[0] == 't') {
            uint32_t time = uip_htonl(getTime());
            memcpy(buffer, &time, 4);
            REST.set_response_status(response, CONTENT_2_05);
            REST.set_header_content_type(response, APPLICATION_OCTET_STREAM);
            REST.set_response_payload(response, buffer, 4);
        }

        //*************************************************************************
        //*  DEVICE PSK                                                           *
        //*************************************************************************
        if (query[0] == 'p') {
            getPSK(buffer);
            buffer[REST_MAX_CHUNK_SIZE - 1] = 0;
            REST.set_response_status(response, CONTENT_2_05);
            REST.set_header_content_type(response, APPLICATION_OCTET_STREAM);
            REST.set_response_payload(response, buffer, LEN_PSK);
        }

        //*************************************************************************
        //*  DEVICE ECC                                                           *
        //*************************************************************************
        if (query[0] == 'e') {
            uint32_t result_x[8];
            uint32_t result_y[8];
            uint32_t base_x[8];
            uint32_t base_y[8];
            nvm_getVar((void *) base_x, RES_ECC_BASE_X, LEN_ECC_BASE_X);
            nvm_getVar((void *) base_y, RES_ECC_BASE_Y, LEN_ECC_BASE_Y);

            uint32_t private_key[8];
            do {
                uint32_t i;
                for (i = 0; i < 32; i++)
                    ((uint8_t *) private_key)[i] = (*MACA_RANDOM) & 0x000000FF;
            } while (!ecc_is_valid_key(private_key));

            uint32_t time = *MACA_CLK;
            printf("ECC - START\n");
            ecc_ec_mult(base_x, base_y, private_key, result_x, result_y);
            printf("ECC - ENDE - %u\n", (*MACA_CLK - time) / 250);
        }
    } else {
        memcpy(buffer, "?i= (n)ame | (m)odel | (u)uid | (t)ime | (p)sk | (e)cc", 54);
        REST.set_response_status(response, CONTENT_2_05);
        REST.set_header_content_type(response, TEXT_PLAIN);
        REST.set_response_payload(response, buffer, 36);
    }
}
