/* __AES_UDP_H__ */
#ifndef __AES_UDP_H__
#define __AES_UDP_H__

#include <sys/types.h>
#include <sys/socket.h>

#include "ccm.h"

typedef struct {
  uint8_t major;
  uint8_t minor;
} __attribute__ ((packed)) ProtocolVersion;

typedef enum {
  change_cipher_spec = 20,
  alert = 21,
  handshake = 22,
  application_data = 23,
  empty = 255
} __attribute__ ((packed)) ContentType;

typedef struct {
  ContentType type;
  ProtocolVersion version;
  uint16_t length;
  CCMData_t ccm_fragment;
} __attribute__ ((packed)) DTLSCipher_t;

/* ------------------------------------------------------------------------- */

ssize_t dtls_sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen);

ssize_t dtls_recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen);

#endif /* __AES_UDP_H__ */
