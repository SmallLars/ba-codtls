#include "er-coap-13-dtls.h"

plaintext_t coap_dtls_decrypt(uint8_t *data, uint16_t data_len) {
  TLSCiphertext *c = (TLSCiphertext *) data;

  printf("Type: %u\n", c->type);
  printf("Version major: %u\n", c->version.major);
  printf("Version minor: %u\n", c->version.minor);
  printf("Länge: %u\n", c->length);
  printf("Erhaltene MAC: %02X%02X%02X%02X %02X%02X%02X%02X\n",
              c->aead_fragment.aead_ciphered[c->length - 8],
              c->aead_fragment.aead_ciphered[c->length - 7],
              c->aead_fragment.aead_ciphered[c->length - 6],
              c->aead_fragment.aead_ciphered[c->length - 5],
              c->aead_fragment.aead_ciphered[c->length - 4],
              c->aead_fragment.aead_ciphered[c->length - 3],
              c->aead_fragment.aead_ciphered[c->length - 2],
              c->aead_fragment.aead_ciphered[c->length - 1]
  );

  uint8_t authCode[8];
  getAuthCode(authCode, (uint8_t *) "ABCDEFGHIJKLMNOP", c->aead_fragment.aead_ciphered, c->length - 16);
  printf("Berechnete MAC: %02X%02X%02X%02X %02X%02X%02X%02X\n",
              authCode[0],
              authCode[1],
              authCode[2],
              authCode[3],
              authCode[4],
              authCode[5],
              authCode[7],
              authCode[7]
  );

  uint32_t check = memcmp(c->aead_fragment.aead_ciphered + c->length - 16 , authCode, 8);
  printf("Vergleich: %u\n", check);
  plaintext_t pt = { check == 0 ? 1 : 1, c->aead_fragment.aead_ciphered, c->length - 16 };
  return pt;
}
