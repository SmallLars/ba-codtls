#ifndef ECC_MULT_H_
#define ECC_MULT_H_

#include <stdint.h>

void ecc_mult(const uint32_t x[8], const uint32_t y[8], uint32_t result[16]);

#endif /* ECC_MULT_H_ */