#include "er-coap-13-dtls.h"

plaintext_t coap_dtls_decrypt(uint8_t *data, uint16_t data_len) {
  TLSCiphertext *c = (TLSCiphertext *) data;

/*
  printf("Type: %u\n", c->type);
  printf("Version major: %u\n", c->version.major);
  printf("Version minor: %u\n", c->version.minor);
  printf("Länge: %u\n", c->length);
*/

  plaintext_t pt = { 1, c->aead_fragment.aead_ciphered, c->length - 16 };
  return pt;
}
