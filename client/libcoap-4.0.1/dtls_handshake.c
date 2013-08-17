#include "dtls_handshake.h"

#include "dtls_clientHello.h"

//#include <stdlib.h>
#include <stdio.h>
#include <string.h>
//#include <netinet/in.h>
#include <time.h>

#include "dtls_random.h"
#include "coap_client.h"

#define KEY (uint8_t *) "ABCDEFGHIJKLMNOP"

void dtls_handshake(struct in6_addr *ip) {
  uint8_t len;
  uint8_t message[128];

  time_t my_time = time(NULL);
  uint8_t random[28];
  random_x(random, 28);
  char buffer[256];

  len = makeClientHello(message, my_time, random, NULL, 0, NULL, 0);
  memset(buffer, 0, 256);
  coap_setPayload(message, len);
  coap_setBlock1(0, 1, 1);
  coap_request(ip, COAP_REQUEST_POST, "dtls", buffer);
  coap_setPayload(message, len);
  coap_setBlock1(1, 0, 1);
  coap_request(ip, COAP_REQUEST_POST, "dtls", buffer);
  DTLSContent_t *content = (DTLSContent_t *) buffer;
  HelloVerifyRequest_t *verify = (HelloVerifyRequest_t *) (content->payload + content->len);
  printf("Step 1 done: Cookie erhalten: ");
  uint32_t i;
  for (i = 0; i < verify->cookie_len; i++) printf("%02X", verify->cookie[i]);
  printf("\n");

  len = makeClientHello(message, my_time, random, NULL, 0, verify->cookie, verify->cookie_len);
  printf("Länge: %u\n", len);
  memset(buffer, 0, 256);
  coap_setPayload(message, len);
  coap_setBlock1(0, 1, 1);
  coap_request(ip, COAP_REQUEST_POST, "dtls", buffer);
  coap_setPayload(message, len);
  coap_setBlock1(1, 1, 1);
  coap_request(ip, COAP_REQUEST_POST, "dtls", buffer);
  coap_setPayload(message, len);
  coap_setBlock1(2, 0, 1);
  coap_request(ip, COAP_REQUEST_POST, "dtls", buffer);
  printf("Step 2 done: TODO Session-Id erhalten: XXXXXXXX.\n");

  memset(buffer, 0, 256);
  DTLSContent_t *c = (DTLSContent_t *) buffer;
  c->type = c_change_cipher_spec;
  c->len = con_length_8_bit;
  c->payload[0] = 1;
  c->payload[1] = 1;
  coap_setPayload(message, 3);
  coap_request(ip, COAP_REQUEST_POST, "dtls?s=IJKLMNOP", buffer);
  printf("Step 3 done.\n");
}
