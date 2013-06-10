/* __ER_COAP_13_DTLS_H__ */
#ifndef __ER_COAP_13_DTLS_H__
#define __ER_COAP_13_DTLS_H__

#include <stdint.h>

typedef struct {
  uint8_t valid;
  uint8_t *data;
  uint16_t data_len;
} plaintext_t;

plaintext_t coap_dtls_decrypt(uint8_t *data, uint16_t data_len);

#endif /* __ER_COAP_13_DTLS_H__ */
