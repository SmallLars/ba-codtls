#include "er-coap-13-dtls.h"

#include <string.h>

plaintext_t coap_dtls_decrypt(DTLSCipher_t *c) {
  printf("Type: %u\n", c->type);
  printf("Version major: %u\n", c->version.major);
  printf("Version minor: %u\n", c->version.minor);
  printf("Länge: %u\n", c->length);
  printf("Erhaltene NONSE: %c%c%c%c%c%c%c%c\n",
              c->ccm_fragment.nonce_explicit[0],
              c->ccm_fragment.nonce_explicit[1],
              c->ccm_fragment.nonce_explicit[2],
              c->ccm_fragment.nonce_explicit[3],
              c->ccm_fragment.nonce_explicit[4],
              c->ccm_fragment.nonce_explicit[5],
              c->ccm_fragment.nonce_explicit[6],
              c->ccm_fragment.nonce_explicit[7]
  );

  uint8_t oldCode[8];
  memcpy(oldCode, c->ccm_fragment.ccm_ciphered + c->length - 16, 8);

  crypt((uint8_t *) "ABCDEFGHIJKLMNOP", &(c->ccm_fragment), c->length - 16);

  uint8_t authCode[8];
  getAuthCode(authCode, (uint8_t *) "ABCDEFGHIJKLMNOP", &(c->ccm_fragment), c->length - 16);

  uint32_t check = memcmp(oldCode, authCode, 8);
  if (check) printf("DTLS-MAC fehler. Paket ungültig.\n");
  plaintext_t pt = { check == 0 ? 1 : 0, c->ccm_fragment.ccm_ciphered, c->length - 16 };
  return pt;
}
