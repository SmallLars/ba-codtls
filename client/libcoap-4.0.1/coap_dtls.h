/* __COAP_DTLS_H__ */
#ifndef __COAP_DTLS_H__
#define __COAP_DTLS_H__

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

/* Record Layer Datenstrukturen -------------------------------------------- */

/*
protocol: 0 = none
          1 = coap
version:  0 = Version 254.255 (DTLS 1.0)
          1 = 16-bit version field
          2 = Version 254.253 (DTLS 1.2)
          3 = Reserved for future use
epoch:    0 = Epoch 0
          1 = Epoch 1
          2 = Epoch 2
          3 = Epoch 3
          4 = Epoch 4
          5 = 8-bit epoch field
          6 = 16-bit epoch field
          7 = Implicit -- same as previous record in the datagram
len:      0 = Length 0
          1 = 8-bit length field
          2 = 16-bit length field
          3 = Implicit -- last record in the datagram
*/
typedef struct {
  unsigned int protocol:1;    
  unsigned int version:2;
  unsigned int epoch:3;
  unsigned int len:2;
  uint8_t length;
  uint8_t payload[0];
} __attribute__ ((packed)) DTLSRecord_t;

/* ------------------------------------------------------------------------- */

typedef enum {
  change_cipher_spec = 20,
  alert = 21,
  handshake = 22,
  application_data = 23
  // max = 255
} __attribute__ ((packed)) ContentType;

typedef struct {
  ContentType type;
  uint8_t payload[0];
} __attribute__ ((packed)) Content;

/* Handshake Datenstrukturen ----------------------------------------------- */

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
  finished = 20
  // max = 255
} __attribute__ ((packed)) HandshakeType;

typedef struct {
  HandshakeType msg_type;
  uint8_t length[3];
  uint8_t payload[0];
} __attribute__ ((packed)) Handshake_t;

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
