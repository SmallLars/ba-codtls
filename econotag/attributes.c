#include <string.h>

#include <erbium.h>
#include <er-coap-13.h>
#include <er-coap-13-separate.h>
#include <er-coap-13-transactions.h>

#include "mc1322x.h"
#include "flash-store.h"

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
        /*
        if (query[0] == 'p') {
            getPSK(buffer);
            buffer[REST_MAX_CHUNK_SIZE - 1] = 0;
            REST.set_response_status(response, CONTENT_2_05);
            REST.set_header_content_type(response, APPLICATION_OCTET_STREAM);
            REST.set_response_payload(response, buffer, LEN_PSK);
        }
        */
        //*************************************************************************
        //*  DEVICE ECC                                                           *
        //*************************************************************************
        if (query[0] == 'e') {
            coap_separate_t request_metadata[1];
            coap_separate_accept(request, request_metadata);

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

            printf("ECC - START\n");
            uint32_t time = *MACA_CLK;
            ecc_ec_mult(base_x, base_y, private_key, result_x, result_y);
            time = (*MACA_CLK - time) / 250;
            printf("ECC - ENDE\n");

            // Erstes Paket senden - START
            coap_transaction_t *transaction = NULL;
            if ( (transaction = coap_new_transaction(request_metadata->mid, &request_metadata->addr, request_metadata->port)) ) {
                coap_packet_t response[1];
                coap_separate_resume(response, request_metadata, REST.status.OK);
                coap_set_header_content_type(response, APPLICATION_OCTET_STREAM);
                sprintf(buffer, "%5u", time);
                coap_set_payload(response, buffer, 5);
                transaction->packet_len = coap_serialize_message(response, transaction->packet);
                coap_send_transaction(transaction);
            }
            // Erstes Paket senden - ENDE
        }
    } else {
        const uint8_t *payload = 0;
        size_t pay_len = REST.get_request_payload(request, &payload);
        printf("Payload erhalten: %.*s\n", pay_len, payload);

        memcpy(buffer, "?i=(name | model | uuid | time | psk | ecc)", 43);
        REST.set_response_status(response, CONTENT_2_05);
        REST.set_header_content_type(response, TEXT_PLAIN);
        REST.set_response_payload(response, buffer, 43);
    }
}

void printflash() {
    uint8_t buffer[32];
    nvm_read(gNvmInternalInterface_c, gNvmType_SST_c, buffer, 0, 32);
    uint8_t i;
    printf("Flash:");
    for (i = 0; i < 32; i++) printf(" %02X", buffer[i]);
    printf("\n");
}

void firmware_handler(void* request, void* response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset) {
    const uint8_t *payload = 0;
    size_t pay_len = REST.get_request_payload(request, &payload);
    if (pay_len && payload) {
        uint16_t block;
        memcpy(&block, payload, 2);
        if (block == 0xFFFF) {
            printf("\n");
            printflash();
            nvm_init();
            uint32_t reset = 0x80003050;
            uint32_t value;
            asm volatile(
                "ldr %[v], [%[r]] \n\t"
                "str %[v], [%[r]] \n\t"
            : /* out */
                [v] "+r" (value)
            : /* in */
                [r] "r" (reset)
            : /* clobber list */
                "memory"
            );
        } else {
            if (block == 0) {
                printflash();
                printf("Erase: %u\n", nvm_erase(gNvmInternalInterface_c, gNvmType_SST_c, 0x00FFFFFF));
            }
            uint8_t err = nvm_write(gNvmInternalInterface_c, gNvmType_SST_c, (uint8_t *) (payload + 2), block * 64, pay_len - 2);
            printf("\rBlock %4u erhalten und an %5u geschrieben: %u!", block, block * 64, err);
        }
        REST.set_response_status(response, CHANGED_2_04);
    }
}
