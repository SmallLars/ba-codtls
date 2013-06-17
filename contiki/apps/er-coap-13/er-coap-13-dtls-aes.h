/* __ER_COAP_13_DTLS_AES_H__ */
#ifndef __ER_COAP_13_DTLS_AES_H__
#define __ER_COAP_13_DTLS_AES_H__

#include <stddef.h>
#include <stdint.h>

#include "er-coap-13-dtls.h"

#define AES_BLKSIZE      16
#define NONCE_BYTE_COUNT  8

uint32_t aes_init();

void getAuthCode(uint8_t *out, uint8_t *key, CCMData_t *data, size_t len);

void crypt(uint8_t *key, CCMData_t *data, size_t len);

/*
uint8_t *aes_encrypt( uint8_t *data, size_t data_length, uint8_t aes_key[AES_BLKSIZE] );

uint8_t *aes_decrypt( uint8_t *data, size_t data_length, uint8_t aes_key[AES_BLKSIZE] );
*/

#endif /* __ER_COAP_13_DTLS_AES_H__ */
