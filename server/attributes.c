#include <string.h>

#include <erbium.h>
#include <er-coap-13.h>
#include <er-coap-13-separate.h>
#include <er-coap-13-transactions.h>

#include "mc1322x.h"
#include "flash-store.h"
#include "ecc.h"

void device_handler(void* request, void* response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset) {
    const char *uri_path = NULL;
    uint8_t uri_len = REST.get_url(request, &uri_path);

    if (uri_len == 1) {
        const uint8_t *payload = 0;
        size_t pay_len = REST.get_request_payload(request, &payload);
        printf("Payload erhalten: %.*s\n", pay_len, payload);

        memcpy(buffer, "?i=(name | model | uuid | time | psk)", 37);
        REST.set_response_status(response, CONTENT_2_05);
        REST.set_header_content_type(response, TEXT_PLAIN);
        REST.set_response_payload(response, buffer, 43);
    } else {
        //*************************************************************************
        //*  DEVICE NAME                                                          *
        //*************************************************************************
        if (uri_path[2] == 'n') {
            nvm_getVar(buffer, RES_NAME, LEN_NAME);
            buffer[REST_MAX_CHUNK_SIZE - 1] = 0;
            REST.set_response_status(response, CONTENT_2_05);
            REST.set_header_content_type(response, TEXT_PLAIN);
            REST.set_response_payload(response, buffer, LEN_NAME);
        }

        //*************************************************************************
        //*  DEVICE MODEL                                                         *
        //*************************************************************************
        if (uri_path[2] == 'm') {
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
        if (uri_path[2] == 'u') {
            nvm_getVar(buffer, RES_UUID, LEN_UUID);
            buffer[REST_MAX_CHUNK_SIZE - 1] = 0;
            REST.set_response_status(response, CONTENT_2_05);
            REST.set_header_content_type(response, APPLICATION_OCTET_STREAM);
            REST.set_response_payload(response, buffer, LEN_UUID);
        }

        //*************************************************************************
        //*  DEVICE TIME                                                          *
        //*************************************************************************
        if (uri_path[2] == 't') {
            uint32_t time = uip_htonl(getTime());
            memcpy(buffer, &time, 4);
            REST.set_response_status(response, CONTENT_2_05);
            REST.set_header_content_type(response, APPLICATION_OCTET_STREAM);
            REST.set_response_payload(response, buffer, 4);
        }

        //*************************************************************************
        //*  DEVICE PSK                                                           *
        //*************************************************************************
        if (uri_path[2] == 'p') {
            getPSK(buffer);
            buffer[REST_MAX_CHUNK_SIZE - 1] = 0;
            REST.set_response_status(response, CONTENT_2_05);
            REST.set_header_content_type(response, APPLICATION_OCTET_STREAM);
            REST.set_response_payload(response, buffer, LEN_PSK);
        }
    }
}