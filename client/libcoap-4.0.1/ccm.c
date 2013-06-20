#include "ccm.h"

#include <string.h>
#include <arpa/inet.h>
#include <openssl/evp.h>

#define min(x,y) ((x)<(y)?(x):(y))

void getKey(uint8_t *out, uint8_t *key, uint8_t *nonce, uint32_t index) {
  uint8_t a[16];
  memset(a, 0, 16);

  a[0] = (LEN_LEN - 1);
  memcpy(a + 1, nonce, NONCE_LEN);
  index = htonl(index);
  memcpy(a + 12, &index, 4);

  EVP_CIPHER_CTX ctx;
  EVP_EncryptInit(&ctx, EVP_aes_128_ecb(), key, 0);
  EVP_CIPHER_CTX_set_padding(&ctx, 0);
  int32_t length;
  EVP_EncryptUpdate(&ctx, out, &length, a, 16);
  EVP_CIPHER_CTX_cleanup(&ctx);
}

void setAuthCode(CCMData_t *c, uint8_t *key, size_t msg_len) {
  // b_0 generieren
  uint8_t b_0[16];
  memset(b_0, 0, 16);
  // Flags
  b_0[0] = (8 * ((MAC_LEN-2)/2)) + (LEN_LEN - 1);
  // Nonce
  memcpy(b_0 + 1, c->nonce_explicit, NONCE_LEN);
  // Länge der Nachricht
  size_t new_len = htonl(msg_len);
  memcpy(b_0 + 12, &new_len, 4);

  uint8_t cypher[16];
  int32_t cypherLen;

  EVP_CIPHER_CTX ctx;
  EVP_CIPHER_CTX_init(&ctx);
  EVP_EncryptInit(&ctx, EVP_aes_128_cbc(), key, NULL);
  EVP_CIPHER_CTX_set_padding(&ctx, 0);

  EVP_EncryptUpdate(&ctx, cypher, &cypherLen, b_0, 16);

  size_t i;
  uint8_t plaintext[16];
  for (i = 0; i < msg_len; i+=16) {
      memset(plaintext, 0, 16);
      memcpy(plaintext, c->ccm_ciphered + i, min(16, msg_len - i));
      EVP_EncryptUpdate(&ctx, cypher, &cypherLen, plaintext, 16);
  }

  memcpy(c->ccm_ciphered + msg_len, cypher, MAC_LEN);
  EVP_CIPHER_CTX_cleanup(&ctx);

  uint8_t s[16];
  // A-Block verschlüssel und mit dem bereits berechneten MAC X-Oren
  getKey(s, key, c->nonce_explicit, 0);
  for (i = 0; i < MAC_LEN; i++) c->ccm_ciphered[msg_len + i] ^= s[i];
}

void crypt(CCMData_t *c, unsigned char *key, size_t len) {
  uint32_t i;
  uint8_t s[16];

  for (i = 0; i < len; i+=16) {
    getKey(s, key, c->nonce_explicit, (i/16)+1);
    size_t j;
    size_t blocklen = min(16, len - i);
    for (j = 0; j < blocklen; j++) c->ccm_ciphered[i+j] ^= s[j];
  }
}

void encrypt(CCMData_t *c, uint8_t *key, size_t len) {
  setAuthCode(c, key, len);
  crypt(c, key, len);
}

void decrypt(CCMData_t *c, uint8_t *key, size_t len) {
  crypt(c, key, len);
  setAuthCode(c, key, len);
}
