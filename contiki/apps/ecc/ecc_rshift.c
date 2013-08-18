#include "ecc_rshift.h"

#define ALGO 0
// NR | Beschreibung | Größe | Geschwindigkeit
//  0 | C-Code       |     0 | Mittel
//  1 | C-Code       |    -4 | Mittel
//  2 | ASM          |    -4 | Schnell

void ecc_rshift(uint32_t *A) {

#if ALGO == 0
    uint8_t i;
    uint32_t n, nOld = 0;

    for (i = 8; i--;) {
        n = A[i] & 0x1;
        A[i] = nOld<<31 | A[i]>>1;
        nOld = n;
    }
#endif

#if ALGO == 1
    uint8_t i;

    for (i = 0; i < 7; i++) {
        A[i] = (A[i+1] & 0x1)<<31 | A[i]>>1;
    }
    A[7] = A[7]>>1;
#endif

#if ALGO == 2
    uint32_t index;
    uint32_t carry;
    uint32_t value;
    uint32_t result;

    asm volatile(
            "mov %[i], #32 \n\t"            // index = 32
            "mov %[c], #0 \n\t"             // carry = 0
        ".loop: \n\t"
            "sub %[i], %[i], #4 \n\t"       // index -= 4
            "mov %[r], %[c] \n\t"           // result = carry
            "ldr %[v], [%[a],%[i]] \n\t"    // value = a[index]
            "lsl %[c], %[v], #31 \n\t"      // carry = value << 31
            "lsr %[v], %[v], #1 \n\t"       // value >>= 1
            "orr %[r], %[r], %[v] \n\t"     // result |= value
            "str %[r], [%[a],%[i]] \n\t"    // a[index] = result
            "cmp %[i], #0 \n\t"             // index == 0
            "bne .loop \n\t"                // != ? next loop
    : /* out */
        [i] "+r" (index),
        [c] "+r" (carry),
        [v] "+r" (value),
        [r] "+r" (result)
    : /* in */
        [a] "r" (A)
    : /* clobber list */
        "memory"
    );
#endif

}
