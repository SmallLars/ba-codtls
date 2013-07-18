/* __COAP_DTLS_HANDSHAKE_H__ */
#ifndef __COAP_DTLS_HANDSHAKE_H__
#define __COAP_DTLS_HANDSHAKE_H__

#include <stdint.h>
#include <netinet/in.h>

typedef enum {
  hello_request = 0,
  client_hello = 1,
  server_hello = 2,
  hello_verify_request = 3, 
  certificate = 11,
  server_key_exchange = 12,
  certificate_request = 13,
  server_hello_done = 14,
  certificate_verify = 15,
  client_key_exchange = 16,
  finished = 20,
  change_cipher_spec = 32,
  c_alert = 33,
  // max = 63
} __attribute__ ((packed)) ContentType;

typedef enum {
  length_0 = 0,
  length_8_bit = 1,
  length_16_bit = 2,
  length_48_bit = 3
} Length;

typedef struct {
  ContentType type:6;
  Length len:2;
  uint8_t payload[0];
} __attribute__ ((packed)) Content_t;

/* ------------------------------------------------------------------------- */

void dtls_handshake(struct in6_addr *ip);

#endif /* __COAP_DTLS_HANDSHAKE_H__ */
