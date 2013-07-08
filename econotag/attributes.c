#include "tools.h"
#include "persist.h"

#include <erbium.h>
#include <er-coap-13.h>
#include <string.h>

/*************************************************************************/
/*  DEVICE NAME                                                          */
/*************************************************************************/
void device_name_handler(void* request, void* response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset) {
/*
  nvm_getVar(buffer, RES_NAME, LEN_NAME);
  buffer[REST_MAX_CHUNK_SIZE - 1] = 0;
  set_response(response, CONTENT_2_05, TEXT_PLAIN, buffer, min(LEN_NAME, REST_MAX_CHUNK_SIZE - 1));
*/
  printf("Offset: %i\n", *offset);
  switch (*offset) {
    case 0:
      memset(buffer, 'A', 128);
      REST.set_response_payload(response, buffer, 128);
      *offset = 128;
      break;
    case 128:
      memset(buffer, 'B', 128);
      REST.set_response_payload(response, buffer, 128);
      *offset = 256;
      break;
    case 256:
      memset(buffer, 'C', 128);
      REST.set_response_payload(response, buffer, 128);
      *offset = 384;
      break;
    case 384:
      memset(buffer, 'D', 64);
      REST.set_response_payload(response, buffer, 64);
      *offset = -1;
      break;
  }
}

/*************************************************************************/
/*  DEVICE MODEL                                                         */
/*************************************************************************/
void device_model_handler(void* request, void* response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset) {
  nvm_getVar(buffer, RES_MODEL, LEN_MODEL);
  buffer[REST_MAX_CHUNK_SIZE - 1] = 0;
  set_response(response, CONTENT_2_05, TEXT_PLAIN, buffer, min(LEN_MODEL, REST_MAX_CHUNK_SIZE - 1));
}

/*************************************************************************/
/*  DEVICE IDENTIFIER                                                    */
/*************************************************************************/
void device_uuid_handler(void* request, void* response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset) {
  nvm_getVar(buffer, RES_UUID, LEN_UUID);
  buffer[REST_MAX_CHUNK_SIZE - 1] = 0;
  set_response(response, CONTENT_2_05, APPLICATION_OCTET_STREAM, buffer, min(LEN_UUID, REST_MAX_CHUNK_SIZE - 1));
}
