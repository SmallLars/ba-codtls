/* __ER_COAP_13_DTLS_AES_H__ */
#ifndef __ER_COAP_13_DTLS_AES_H__
#define __ER_COAP_13_DTLS_AES_H__

#include <stddef.h>
#include <stdint.h>

#define AES_BLKSIZE      16
#define NONCE_BYTE_COUNT  8

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
