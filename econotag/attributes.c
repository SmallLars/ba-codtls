#include "tools.h"
#include "persist.h"

#include <erbium.h>
#include <er-coap-12.h>
#include <string.h>

/*************************************************************************/
/*  DEVICE NAME                                                          */
/*************************************************************************/
void device_name_handler(void* request, void* response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset) {
  const char *device_name = "Name: Server";

  int length = 0;

  buffer[REST_MAX_CHUNK_SIZE-1] = 0;
  memcpy(buffer, device_name, length = min(strlen(device_name), REST_MAX_CHUNK_SIZE-1));

  set_response(response, CONTENT_2_05, TEXT_PLAIN, buffer, length);
}

/*************************************************************************/
/*  DEVICE MODEL                                                         */
/*************************************************************************/
void device_model_handler(void* request, void* response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset) {
  const char *device_model = "Model: Server";
  int length = 0;
  buffer[REST_MAX_CHUNK_SIZE-1] = 0;
  memcpy(buffer,device_model,length = min(strlen(device_model), REST_MAX_CHUNK_SIZE-1));

  set_response(response, CONTENT_2_05, TEXT_PLAIN, buffer, length);
}

/*************************************************************************/
/*  DEVICE IDENTIFIER                                                    */
/*************************************************************************/
void device_identifier_handler(void* request, void* response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset) {
  unsigned char device_identifier[LEN_UUID];
  nvm_getVar(device_identifier, RES_UUID, LEN_UUID);

  int length = 0;
  buffer[REST_MAX_CHUNK_SIZE-1] = 0;
  memcpy(buffer,device_identifier,length = min(LEN_UUID, REST_MAX_CHUNK_SIZE-1));

  set_response(response, CONTENT_2_05, APPLICATION_OCTET_STREAM, buffer, length);
}
