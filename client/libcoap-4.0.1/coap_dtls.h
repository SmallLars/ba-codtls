/* __COAP_DTLS_H__ */
#ifndef __COAP_DTLS_H__
#define __COAP_DTLS_H__

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

/* Record Layer Datenstrukturen -------------------------------------------- */

typedef enum {
  none = 0,
  coap = 1
} Protocol;

typedef enum {
  dtls_1_0 = 0,
  version_16_bit = 1,
  dtls_1_2 = 2,
  version_future_use = 3
} Version;

typedef enum {
  epoch_0 = 0,
  epoch_1 = 1,
  epoch_2 = 2,
  epoch_3 = 3,
  epoch_4 = 4,
  epoch_8_bit = 5,
  epoch_16_bit = 6,
  epoch_implicit = 7 // same as previous record in the datagram
} Epoch;

typedef enum {
  length_0 = 0,
  length_8_bit = 1,
  length_16_bit = 2,
  length_implicit = 3 // last record in the datagram
} Length;

typedef struct {
  Protocol protocol:1;    
  Version version:2;
  Epoch epoch:3;
  Length len:2;
  uint8_t length;
  uint8_t payload[0];
} __attribute__ ((packed)) DTLSRecord_t;

/* ------------------------------------------------------------------------- */

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
  alert = 33,
  handshake = 34
  // max = 63
} __attribute__ ((packed)) ContentType;

typedef struct {
  ContentType type:6;
  Length len:2;
  uint8_t length;
  uint8_t payload[0];
} __attribute__ ((packed)) Content_t;

/* Handshake Datenstrukturen ----------------------------------------------- */

typedef struct {
  uint8_t major;
  uint8_t minor;
} __attribute__ ((packed)) ProtocolVersion;

typedef struct {
  uint32_t gmt_unix_time;
  uint8_t random_bytes[28];
} __attribute__ ((packed)) Random;

typedef struct {
  ProtocolVersion client_version;
  Random random;
  uint8_t data[0];
} __attribute__ ((packed)) ClientHello_t;

typedef struct {
  ProtocolVersion server_version;
  uint8_t cookie_len;
  uint8_t cookie[0];
} __attribute__ ((packed)) HelloVerifyRequest_t;

/* ------------------------------------------------------------------------- */

void dtls_handshake(struct in6_addr *ip);

ssize_t dtls_sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen);

ssize_t dtls_recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen);

#endif /* __COAP_DTLS_H__ */
