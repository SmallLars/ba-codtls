#include <string.h>

#include "persist.h"
#include "erbium.h"
#include "er-coap-13.h"
#include "er-coap-13-dtls.h"
#include "er-coap-13-dtls-data.h"
#include "er-coap-13-dtls-random.h"

/*************************************************************************/
/*  HANDSHAKE                                                            */
/*************************************************************************/
void dtls_handler(void* request, void* response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset) {
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
        answer->random.gmt_unix_time = 0; // TODO
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
        ci.pending = 0;
        insertClient(&ci);

        ClientKey_t ck;
        ck.index = 0;
        ck.epoch = 1;
        memcpy(ck.key, "ABCDEFGHIJKLMNOP", 16);
        insertKey(&ck);

        uint8_t key[17];
        key[16] = 0;
        getKey(key, (uint8_t *) &UIP_IP_BUF->srcipaddr, 1);
        printf("Key: %s - Ip: ", key);
        int i;
        for (i = 0; i < 16; i++) printf("%02x", ((uint8_t *) &UIP_IP_BUF->srcipaddr)[i]);
        printf("\n");

        set_response(response, CREATED_2_01, APPLICATION_OCTET_STREAM, buffer, sizeof(ServerHello_t) + 4);
      }
    }

  }
}


