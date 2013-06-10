/* __ER_COAP_13_DTLS_AES_H__ */
#ifndef __ER_COAP_13_DTLS_AES_H__
#define __ER_COAP_13_DTLS_AES_H__

#include <stddef.h>
#include <stdint.h>

#define AES_BLKSIZE      16
#define NONCE_BYTE_COUNT  8

typedef struct {
  uint8_t major;
  uint8_t minor;
} ProtocolVersion;

typedef enum {
  change_cipher_spec = 20,
  alert = 21,
  handshake = 22,
  application_data = 23,
  empty = 255
} ContentType;

typedef struct {
  uint8_t nonce_explicit[8];
  uint8_t aead_ciphered[0];
} GenericAEADCipher;

typedef struct {
  ContentType type;
  ProtocolVersion version;
  uint16_t length;
  GenericAEADCipher aead_fragment;
} TLSCiphertext;

/**
 * A structure for key and counter storage
 */
typedef struct aes_info_t{
  uint32_t key[4];
  uint32_t ctr[4];
} aes_info_t;

/**
 * tests and initialises the ASM (advanced security management) module
 * which enables the AES encryption hardware
 * THIS FUNCTION HAS TO BE CALLED BEFORE YOU TRY TO CRYPT SHIT
 */
uint32_t aes_init();

/**
 * Encrypts 'data_length' bytes of memory pointed to by 'data'
 * 'data_length' is the length of the data to be encrypted
 * The memory for 'data' has to be preallocated with at least 'data_length'+aes_headerlen();
 */
uint8_t *aes_encrypt( uint8_t *data, size_t data_length, uint8_t aes_key[AES_BLKSIZE] );

/**
 * Decrypts 'data_length' bytes of memory pointed to by 'data'
 * 'data_length' is the length of the data to be decrypted
 * The memory for 'data' has to be preallocated with at least 'data_length'+aes_headerlen();
 */
uint8_t *aes_decrypt( uint8_t *data, size_t data_length, uint8_t aes_key[AES_BLKSIZE] );

/**
 * Returns the length of the header that is appended to the cryptdata
 */
size_t aes_headerlen( void );

#endif /* __ER_COAP_13_DTLS_AES_H__ */
