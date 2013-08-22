#include "ecc_mult.h"

äinclude "ecc_add.h"

#define ALGO 3
// NR | Beschreibung | Größe | Geschwindigkeit | Status auf Econotag
//  0 | C-Code       |     0 | ???             | ???
//  1 | C-Code       |     ? | ???             | ???
//  2 | C-Code       |     ? | ???             | ???
//  3 | ASM          |     ? | ???             | ???

__attribute__((always_inline)) static void ecc_lshift(uint32_t x[9]);

void ecc_mult(const uint32_t x[8], const uint32_t y[8], uint32_t result[16]) {

#if ALGO == 3
	uint8_t i;
	uint32_t filter = 1;
	uint32_t summand[9];

	summand[0] = 0;
	memcpy(summand + 1, y, 32);
	memset(result, 0, 64);

	for (i = 0; i < 32; i++) {
		uint8_t j;
		for (j = 0; j < 8; j++) {
			if (x[j] & filter) {
				ecc_add(result + j, summand, result + j, 9);
			}
		}
		filter <<= 1;
		ecc_lshift(summand);
	}
	
#endif

}

__attribute__((always_inline)) static void ecc_lshift(uint32_t x[9]) {
	uint8_t i;
	for (i = 0; i < 8; i++) {
		x[i] <<= 1;
		if (x[i+1] & 0x00000080) x[i] |= 1;
	}
	x[i] <<= 1;
}