#ifndef ECC_ADD_H_
#define ECC_ADD_H_

#include <stdint.h>

uint8_t ecc_add( const uint32_t *x, const uint32_t *y, uint32_t *result, uint8_t length);

#endif /* ECC_ADD_H_ */
