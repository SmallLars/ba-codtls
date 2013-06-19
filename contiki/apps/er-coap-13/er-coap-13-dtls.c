#include "er-coap-13-dtls.h"

#include <string.h>

plaintext_t coap_dtls_decrypt(DTLSCipher_t *c) {
  printf("Type: %u\n", c->type);
  printf("Version major: %u\n", c->version.major);
  printf("Version minor: %u\n", c->version.minor);
  printf("Länge: %u\n", c->length);

  uint8_t oldCode[8];
  memcpy(oldCode, c->ccm_fragment.ccm_ciphered + c->length - 16, 8);

  crypt((uint8_t *) "ABCDEFGHIJKLMNOP", &(c->ccm_fragment), c->length - 16, 0);
  crypt((uint8_t *) "ABCDEFGHIJKLMNOP", &(c->ccm_fragment), c->length - 16, 1);

  uint32_t check = memcmp(oldCode, c->ccm_fragment.ccm_ciphered + c->length - 16, 8);
  if (check) printf("DTLS-MAC fehler. Paket ungültig.\n");
  plaintext_t pt = { check == 0 ? 1 : 0, c->ccm_fragment.ccm_ciphered, c->length - 16 };
  return pt;
}
