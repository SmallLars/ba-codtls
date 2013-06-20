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

void dtls_uip_udp_packet_send(struct uip_udp_conn *conn, const void *data, int len) {
    uint8_t cipher[sizeof(DTLSCipher_t) + len + 8];
    DTLSCipher_t *c = (DTLSCipher_t *) cipher;
    c->type = application_data;
    c->version.major = 3;
    c->version.minor = 3;
    c->length = len + 16;
    memcpy(c->ccm_fragment.nonce_explicit, "ABCDEFGH", 8);
    memcpy(c->ccm_fragment.ccm_ciphered, data, len);

    crypt((uint8_t *) "ABCDEFGHIJKLMNOP", &(c->ccm_fragment), len, 0);

    uip_udp_packet_send(conn, cipher, sizeof(DTLSCipher_t) + len + 8);
}
