#include "random-mc1322x.h"

#include "mc1322x.h"

// these defines below are here only to remind me (marc) of the registers
// for random number generation, I have not yet got anything working
//#define MACA_BASE       (0x80004000)
//#define MACA_KEY0       ((volatile uint32_t *) (MACA_BASE+0x164))
//#define maca_key0       (*((volatile uint32_t *)(0x80004158)))
/*---------------------------------------------------------------------------*/

#define RANDOM random_rand()

uint32_t random_32() {
  return RANDOM | (RANDOM<<16);
}

uint16_t random_16() {
  return RANDOM;
}

uint8_t random_8() {
  return (uint8_t) RANDOM;
}

void doRand (uint8_t *c, size_t len) {
    int i;
    for (i = 0; i < len; i++) c[i] = random_8();
}
