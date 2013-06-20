/* __CCM_H__ */
#ifndef __CCM_H__
#define __CCM_H__

#include <stdlib.h>
#include <stdint.h>

#define MAC_LEN 8                 // Länge des Authentication Fields    Element von {4, 6, 8, 10, 12, 14, 16}
#define LEN_LEN 7                 // Länge des Längenfeldes             Element von {2, 3, 4, 5, 6, 7, 8}
#define NONCE_LEN (15-LEN_LEN)    // Es Ergibt sich die Länge der Nonce

typedef struct {
  uint8_t nonce_explicit[8];
  uint8_t ccm_ciphered[0];
} __attribute__ ((packed)) CCMData_t;

void encrypt(CCMData_t *c, uint8_t *key, size_t len);

void decrypt(CCMData_t *c, uint8_t *key, size_t len);

#endif /* __CCM__ */
