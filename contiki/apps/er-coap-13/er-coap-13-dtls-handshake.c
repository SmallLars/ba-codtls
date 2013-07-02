#include <string.h>

#include "persist.h"
#include "erbium.h"
#include "er-coap-13.h"
#include "er-coap-13-dtls.h"

/*************************************************************************/
/*  HANDSHAKE                                                            */
/*************************************************************************/
void dtls_post_handler(void* request, void* response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset) {
  HelloVerifyRequest *answer = (HelloVerifyRequest *) buffer;
  answer->server_version.major = 3;
  answer->server_version.minor = 3;
  answer->cookie_len = 8;
  memcpy(answer->cookie, "ABCDEFGH", 8);
  set_response(response, CONTENT_2_05, TEXT_PLAIN, buffer, 11);
}
