#include "tools.h"
#include "persist.h"

#include <erbium.h>
#include <er-coap-13.h>
#include <string.h>

#include "mc1322x.h"

/*************************************************************************/
/*  DEVICE NAME                                                          */
/*************************************************************************/
void device_name_handler(void* request, void* response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset) {
  nvm_getVar(buffer, RES_NAME, LEN_NAME);
  buffer[REST_MAX_CHUNK_SIZE - 1] = 0;
  set_response(response, CONTENT_2_05, TEXT_PLAIN, buffer, min(LEN_NAME, REST_MAX_CHUNK_SIZE - 1));

/*
  int i;
  for (i = 0; i < preferred_size; i+=2) sprintf(buffer + i, "%02X", *offset);
  REST.set_response_payload(response, buffer, preferred_size);
  *offset += preferred_size;
  if (*offset > 250) *offset = -1;
*/
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

/*************************************************************************/
/*  DEVICE TIME                                                          */
/*************************************************************************/
void device_time_handler(void* request, void* response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset) {
  uint32_t time = uip_htonl(getTime());
  memcpy(buffer, &time, 4);
  set_response(response, CONTENT_2_05, APPLICATION_OCTET_STREAM, buffer, 4);
}
