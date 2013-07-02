#include "persist.h"

#include <erbium.h>
#include <er-coap-13.h>
#include <string.h>

/*************************************************************************/
/*  HANDSHAKE                                                            */
/*************************************************************************/
void dtls_post_handler(void* request, void* response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset) {




  nvm_getVar(buffer, RES_NAME, LEN_NAME);
  buffer[REST_MAX_CHUNK_SIZE - 1] = 0;
  set_response(response, CONTENT_2_05, TEXT_PLAIN, buffer, LEN_NAME);
}
