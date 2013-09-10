#include "ecc_rshift.h"

#define ALGO 2
// NR | Beschreibung | Größe | Geschwindigkeit | Status auf Econotag
//  0 | C-Code       |     0 | Mittel          | Funktioniert
//  1 | C-Code       |    -4 | Mittel          | Funktioniert
//  2 | ASM          |   -12 | Schnell         | Funktioniert

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
    asm volatile(
            "mov r1, #32 \n\t"          // index = 32
            "mov r2, #0 \n\t"           // carry = 0
        ".loop: \n\t"
            "sub r1, r1, #4 \n\t"       // index -= 4
            "mov r4, r2 \n\t"           // result = carry
            "ldr r3, [%[a],r1] \n\t"    // value = a[index]
            "lsl r2, r3, #31 \n\t"      // carry = value << 31
            "lsr r3, r3, #1 \n\t"       // value >>= 1
            "orr r4, r4, r3 \n\t"       // result |= value
            "str r4, [%[a],r1] \n\t"    // a[index] = result
            "cmp r1, #0 \n\t"           // index == 0
            "bne .loop \n\t"            // != ? next loop
    : /* out */
    : /* in */
        [a] "l" (A)
    : /* clobber list */
        "r1", "r2", "r3", "r4", "memory"
    );
#endif

}
