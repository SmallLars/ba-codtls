/* __ER_COAP_13_DTLS_H__ */
#ifndef __ER_COAP_13_DTLS_H__
#define __ER_COAP_13_DTLS_H__

#include <stdint.h>

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
  uint8_t nonce_explicit[8];
  uint8_t aead_ciphered[0];
} __attribute__ ((packed)) GenericAEADCipher;

typedef struct {
  ContentType type;
  ProtocolVersion version;
  uint16_t length;
  GenericAEADCipher aead_fragment;
} __attribute__ ((packed)) TLSCiphertext;

/* ------------------------------------------------------------------------- */

typedef struct {
  uint8_t valid;
  uint8_t *data;
  uint16_t data_len;
} plaintext_t;

plaintext_t coap_dtls_decrypt(uint8_t *data, uint16_t data_len);

#endif /* __ER_COAP_13_DTLS_H__ */
