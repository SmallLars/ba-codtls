#include <string.h>

#include "persist.h"
#include "erbium.h"
#include "er-coap-13.h"
#include "er-coap-13-dtls.h"

/*************************************************************************/
/*  HANDSHAKE                                                            */
/*************************************************************************/
void dtls_post_handler(void* request, void* response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset) {
  const uint8_t *payload = 0;
  int len = REST.get_request_payload(request, &payload);
  if (len && payload) {
    Handshake_t *handshake = (Handshake_t *) payload;

    if (handshake->msg_type == client_hello) {
      ClientHello_t *clienthello = (ClientHello_t *) handshake->payload;

      uint8_t session_len = clienthello->data[0];
      uint8_t cookie_len = clienthello->data[session_len + 1];

      if (cookie_len == 0) {
        Handshake_t *handshake = (Handshake_t *) buffer;

        handshake->msg_type = hello_verify_request;
        handshake->length[0] = 0;
        handshake->length[1] = 0;
        handshake->length[2] = 11;

        HelloVerifyRequest_t *answer = (HelloVerifyRequest_t *) handshake->payload;
        answer->server_version.major = 3;
        answer->server_version.minor = 3;
        answer->cookie_len = 8;
        memcpy(answer->cookie, "ABCDEFGH", 8);
        set_response(response, CONTENT_2_05, APPLICATION_OCTET_STREAM, buffer, 15);
      } else {
        uint8_t *cookie = clienthello->data + session_len + 2;
        set_response(response, CONTENT_2_05, TEXT_PLAIN, "Handshake mit Cookie erhalten.", 30);
      }
    }

  }
}


