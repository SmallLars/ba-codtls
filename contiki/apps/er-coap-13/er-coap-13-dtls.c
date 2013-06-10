#include "er-coap-13-dtls.h"

plaintext_t coap_dtls_decrypt(uint8_t *data, uint16_t data_len) {
  plaintext_t pt = { 1, data, data_len };
  return pt;
}
