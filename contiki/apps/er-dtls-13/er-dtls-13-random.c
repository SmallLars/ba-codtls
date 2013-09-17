#include "er-dtls-13-random.h"

#include "mc1322x.h"

void random_x(uint8_t *c, size_t len) {
    uint32_t i;
    for (i = 0; i < len; i++) c[i] = random_8();
}

uint32_t random_32(void) {
    return *MACA_RANDOM;
}

uint16_t random_16(void) {
    return (*MACA_RANDOM) & 0x0000FFFF;
}

uint8_t random_8(void) {
    return (*MACA_RANDOM) & 0x000000FF;
}
