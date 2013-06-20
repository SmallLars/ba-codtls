#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>

#include "coap_dtls.h"

#define SETNONCE(a) memcpy(a, "ABCDEFGH", NONCE_LEN)

ssize_t dtls_sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen) {
  uint8_t *key = (uint8_t *) "ABCDEFGHIJKLMNOP";

  DTLSCipher_t *c = (DTLSCipher_t *) malloc(sizeof(DTLSCipher_t) + len + 8); // 8 = Länge des MAC
  c->type = application_data;
  c->version.major = 3;
  c->version.minor = 3;
  c->length = len + 16;
  memcpy(c->ccm_fragment.nonce_explicit, "ABCDEFGH", 8);
  memcpy(c->ccm_fragment.ccm_ciphered, buf, len);
  encrypt(&(c->ccm_fragment), key, len);

  ssize_t send = sendto(sockfd, c, sizeof(DTLSCipher_t) + len + 8, flags, dest_addr, addrlen) - (sizeof(DTLSCipher_t) + 8);

  free(c);

  return send;
}

ssize_t dtls_recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen) {
  size_t size = recvfrom(sockfd, buf, len, flags, src_addr, addrlen);

  DTLSCipher_t *c = (DTLSCipher_t *) malloc(size);
  memcpy(c, buf, size);

  printf("Type: %u\n", c->type);
  printf("Version major: %u\n", c->version.major);
  printf("Version minor: %u\n", c->version.minor);
  printf("Länge: %u\n", c->length);

  uint8_t oldCode[MAC_LEN];
  memcpy(oldCode, c->ccm_fragment.ccm_ciphered + c->length - 8, 8);

  decrypt(&(c->ccm_fragment), (uint8_t *) "ABCDEFGHIJKLMNOP", c->length - 16);

  uint32_t check = memcmp(oldCode, c->ccm_fragment.ccm_ciphered + c->length - 8, 8);
  if (check) printf("DTLS-MAC fehler. Paket ungültig.\n");
  ssize_t db_len = (check == 0 ? c->length - 16 : 0);
  memcpy(buf, c->ccm_fragment.ccm_ciphered, c->length - 16);

  free(c);

  return db_len;
}
