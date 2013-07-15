#include <string.h>

#include "persist.h"
#include "erbium.h"
#include "er-coap-13.h"
#include "er-coap-13-dtls.h"
#include "er-coap-13-dtls-data.h"
#include "er-coap-13-dtls-random.h"
#include "../../../econotag/tools.h"

/*************************************************************************/
/*  HANDSHAKE                                                            */
/*************************************************************************/
void dtls_handler(void* request, void* response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset) {
  const uint8_t *payload = 0;
  size_t pay_len = REST.get_request_payload(request, &payload);
  if (pay_len && payload) {
    size_t session_len = 0;
    const char *session = NULL;
    if ((session_len = REST.get_query_variable(request, "s", &session))) {
      PRINTF("Session: %.*s\n", session_len, session);

      ClientKey_t ck;
      ck.index = 0;
      ck.epoch = 1;
      memcpy(ck.key, "ABCDEFGHIJKLMNOP", 16);
      insertKey(&ck);

      buffer[0] = 20;
      set_response(response, CHANGED_2_04, APPLICATION_OCTET_STREAM, buffer, 1);
    } else {
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
          memcpy(answer->cookie, "ABCDEFGH", 8); // TODO generieren
          set_response(response, VERIFY_1_02, APPLICATION_OCTET_STREAM, buffer, 15);
        } else {
          uint8_t *cookie = clienthello->data + session_len + 2; // TODO checken

          Handshake_t *handshake = (Handshake_t *) buffer;

          handshake->msg_type = server_hello;
          handshake->length[0] = 0;
          handshake->length[1] = 0;
          handshake->length[2] = sizeof(ServerHello_t);

          ServerHello_t *answer = (ServerHello_t *) handshake->payload;
          answer->server_version.major = 3;
          answer->server_version.minor = 3;
          answer->random.gmt_unix_time = uip_htonl(getTime());
          random_x(answer->random.random_bytes, 28);
          answer->session_id.len = 8;
          memcpy (answer->session_id.session_id, "IJKLMNOP", 8); // TODO generieren
          answer->cipher_suite = TLS_ECDH_anon_WITH_AES_128_CCM_8;
          answer->compression_method = null;
          // TODO answer->extensions;

          ClientInfo_t ci;
          memset(&ci, 0, 60);
          memcpy(ci.ip, (uint8_t *) &UIP_IP_BUF->srcipaddr, 16);
          memcpy(ci.session, "IJKLMNOP", 8);
          ci.epoch = 1;
          ci.pending = 1;
          do {
            random_x((uint8_t *) ci.private_key, 32);
          } while (!ecc_is_valid_key(ci.private_key));
          insertClient(&ci);

          uint32_t result_x[8];
          uint32_t result_y[8];
          uint32_t base_x[8];
          uint32_t base_y[8];
          nvm_getVar((void *) base_x, RES_ECC_BASE_X, LEN_ECC_BASE_X);
          nvm_getVar((void *) base_y, RES_ECC_BASE_Y, LEN_ECC_BASE_Y);
          printf("ECC - START\n");
          ecc_ec_mult(base_x, base_y, ci.private_key, result_x, result_y);
          printf("ECC - ENDE\n");

          set_response(response, CREATED_2_01, APPLICATION_OCTET_STREAM, buffer, sizeof(ServerHello_t) + 4);
        }
      }
    }
  }
}


