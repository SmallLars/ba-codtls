#include "coap_dtls_handshake.h"

#include "coap_dtls_clientHello.h"

//#include <stdlib.h>
#include <stdio.h>
#include <string.h>
//#include <netinet/in.h>
#include <time.h>

#include "coap_dtls_random.h"
#include "coap_client.h"

#define KEY (uint8_t *) "ABCDEFGHIJKLMNOP"

void dtls_handshake(struct in6_addr *ip) {
  uint8_t len;
  uint8_t message[128];

  time_t my_time = time(NULL);
  uint8_t random[28];
  random_x(random, 28);
  char buffer[128];

  len = makeClientHello(message, my_time, random, NULL, 0, NULL, 0);
  memset(buffer, 0, 128);
  coap_setPayload(message, len);
  coap_request(ip, COAP_REQUEST_POST, "dtls", buffer);
  Content_t *content = (Content_t *) buffer;
  HelloVerifyRequest_t *verify = (HelloVerifyRequest_t *) (content->payload + content->len);
  printf("Step 1 done: Cookie erhalten: %.*s\n", verify->cookie_len, verify->cookie);

  len = makeClientHello(message, my_time, random, NULL, 0, verify->cookie, verify->cookie_len);
  memset(buffer, 0, 128);
  coap_setPayload(message, len);
  coap_request(ip, COAP_REQUEST_POST, "dtls", buffer);
  printf("Step 2 done: TODO Session-Id erhalten: XXXXXXXX.\n");

  memset(buffer, 0, 128);
  message[0] = 20;
  coap_setPayload(message, 1);
  coap_request(ip, COAP_REQUEST_POST, "dtls?s=IJKLMNOP", buffer);
  printf("Step 3 done.\n");
}
