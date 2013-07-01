/* __COAP_DTLS_H__ */
#ifndef __COAP_DTLS_H__
#define __COAP_DTLS_H__

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

// Record Layer Datenstrukturen

typedef struct {
  uint8_t major;
  uint8_t minor;
} __attribute__ ((packed)) ProtocolVersion;

typedef enum {
  change_cipher_spec = 20,
  alert = 21,
  handshake = 22,
  application_data = 23
  // max = 255
} __attribute__ ((packed)) ContentType;

typedef struct {
  ContentType type;
  ProtocolVersion version;
  uint16_t epoch;
  uint8_t sequence_number[3];
  uint16_t length;
  uint8_t payload[0];
} __attribute__ ((packed)) DTLSRecord_t;

// Handshake Datenstrukturen

typedef enum {
  hello_request = 0,
  client_hello = 1,
  server_hello = 2,
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
} __attribute__ ((packed)) Handshake;

// Hilfsstrukturen
typedef struct {
  uint8_t length;
  uint8_t data[0];
} __attribute__ ((packed)) Data8;

typedef struct {
  uint16_t length;
  uint8_t data[0];
} __attribute__ ((packed)) Data16;

// Random
typedef struct {
  uint32_t gmt_unix_time;
  uint8_t random_bytes[28];
} __attribute__ ((packed)) Random;

// TODO suits

// TODO compression

// Extension Type -> Werte sind in Network Byte Order hinterlegt
typedef enum {
  server_name = 0x0000,
  elliptic_curves = 0x0A00,
  ec_point_formats = 0x0B00
  // max = 0xFFFF
} __attribute__ ((packed)) ExtensionType;

typedef struct {
  ExtensionType extension_type;
  uint8_t extension_data[0];
} __attribute__ ((packed)) Extension;

typedef struct {
  ProtocolVersion client_version;
  Random random;
/*
  uint8_t session_id_length;
  SessionID session_id[0];
  uint8_t cookie_len;
  uint8_t cookie[0];
  CipherSuite cipher_suites<2..2^16-1>;
  CompressionMethod compression_methods<1..2^8-1>;
  Extension extensions<0..2^16-1>;                    // optional
*/
} __attribute__ ((packed)) ClientHello;

/* ------------------------------------------------------------------------- */

void dtls_handshake(struct in6_addr *ip);

ssize_t dtls_sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen);

ssize_t dtls_recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen);

#endif /* __COAP_DTLS_H__ */
