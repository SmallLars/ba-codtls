#include "ecc_sub.h"

#define ALGO 3
// NR | Beschreibung | Größe | Geschwindigkeit | Status auf Econotag
//  0 | C-Code       |     0 | Langsam         | Funktioniert
//  1 | ASM          |   -20 | Mittel          | Funktioniert
//  2 | ASM          |   +84 | Schnell         | Funktioniert für l=8. Rest ist noch zu testen.
//  3 | ASM fix l=8  |   +12 | Schnell         | Funktioniert

uint8_t ecc_sub( const uint32_t *x, const uint32_t *y, uint32_t *result, uint8_t length) {

#if ALGO == 0
    uint8_t d = 0; // carry
    uint8_t v = 0;

    for(;v<length;v++){
        result[v] = x[v] - y[v];
        if(result[v]>x[v]){
            result[v] -= d;
            d = 1;
        } else {
            if (d==1 && result[v]==0x00000000){
                //d = 1; /omitted, because d is already 1
                result[v] = 0xffffffff;
            } else {
                result[v] -= d;
                d = 0;
            }
        }
    }

    return d;
#endif

#if ALGO == 1
    uint32_t index;
    uint32_t carry;
    uint32_t total;
    uint32_t toSub;

    asm volatile(
            "lsl %[l], #2 \n\t"             // length *= 4 for bytecount
            "mov %[i], #0 \n\t"             // index = 0
            "mov %[c], #0 \n\t"             // carry = 0
        ".loop: \n\t"
            "ldr %[t], [%[x],%[i]] \n\t"    // total = x[index]
            "cmp %[c], #0 \n\t"             // carry == 0
            "beq .nocarry1 \n\t"            // == ? skip carry sub
            "mov %[c], #0 \n\t"             // carry = 0
            "sub %[t], %[t], #1 \n\t"       // total --
            "bcs .nocarry1 \n\t"            // carry == 1 ? skip next
            "mov %[c], #1 \n\t"             // carry = 1
        ".nocarry1: \n\t"
            "ldr %[s], [%[y],%[i]] \n\t"    // toSub = y[index]
            "sub %[t], %[t], %[s] \n\t"     // total -= toAdd
            "bcs .nocarry2 \n\t"            // carry == 1 ? skip next
            "mov %[c], #1 \n\t"             // carry = 1
        ".nocarry2: \n\t"
            "str %[t], [%[r],%[i]] \n\t"    // result[index] = total
            "add %[i], %[i], #4 \n\t"       // index += 4
            "cmp %[i], %[l] \n\t"           // index == length
            "bne .loop \n\t"                // != ? next loop
    : /* out */
        [i] "+r" (index),
        [c] "+r" (carry),
        [t] "+r" (total),
        [s] "+r" (toSub)
    : /* in */
        [x] "r" (x),
        [y] "r" (y),
        [r] "r" (result),
        [l] "r" (length)
    : /* clobber list */
        "memory"
    );
    return carry;
#endif

#if ALGO == 2
    uint32_t total;
    uint32_t toSub;

    asm volatile(
            "cmp %[l], #2 \n\t"
            "beq .sub2 \n\t"
            "bhi .sub4or8 \n\t"
        ".sub1: \n\t"
            "ldr %[t], [%[x],#0] \n\t"
            "ldr %[s], [%[y],#0] \n\t"
            "sub %[t], %[t], %[s] \n\t"
            "str %[t], [%[r],#0] \n\t"
            "b .foot \n\t"
        ".sub2: \n\t"
            "ldr %[t], [%[x],#0] \n\t"
            "ldr %[s], [%[y],#0] \n\t"
            "sub %[t], %[t], %[s] \n\t"
            "str %[t], [%[r],#0] \n\t"
            "ldr %[t], [%[x],#4] \n\t"
            "ldr %[s], [%[y],#4] \n\t"
            "sbc %[t], %[t], %[s] \n\t"
            "str %[t], [%[r],#4] \n\t"
            "b .foot \n\t"
        ".sub4or8: \n\t"
            "cmp %[l], #8 \n\t"
            "beq .sub8 \n\t"
        ".sub4: \n\t"
            "ldr %[t], [%[x],#0] \n\t"
            "ldr %[s], [%[y],#0] \n\t"
            "sub %[t], %[t], %[s] \n\t"
            "str %[t], [%[r],#0] \n\t"
            "ldr %[t], [%[x],#4] \n\t"
            "ldr %[s], [%[y],#4] \n\t"
            "sbc %[t], %[t], %[s] \n\t"
            "str %[t], [%[r],#4] \n\t"
            "ldr %[t], [%[x],#8] \n\t"
            "ldr %[s], [%[y],#8] \n\t"
            "sbc %[t], %[t], %[s] \n\t"
            "str %[t], [%[r],#8] \n\t"
            "ldr %[t], [%[x],#12] \n\t"
            "ldr %[s], [%[y],#12] \n\t"
            "sbc %[t], %[t], %[s] \n\t"
            "str %[t], [%[r],#12] \n\t"
            "b .foot \n\t"
        ".sub8: \n\t"
            "ldr %[t], [%[x],#0] \n\t"
            "ldr %[s], [%[y],#0] \n\t"
            "sub %[t], %[t], %[s] \n\t"
            "str %[t], [%[r],#0] \n\t"
            "ldr %[t], [%[x],#4] \n\t"
            "ldr %[s], [%[y],#4] \n\t"
            "sbc %[t], %[t], %[s] \n\t"
            "str %[t], [%[r],#4] \n\t"
            "ldr %[t], [%[x],#8] \n\t"
            "ldr %[s], [%[y],#8] \n\t"
            "sbc %[t], %[t], %[s] \n\t"
            "str %[t], [%[r],#8] \n\t"
            "ldr %[t], [%[x],#12] \n\t"
            "ldr %[s], [%[y],#12] \n\t"
            "sbc %[t], %[t], %[s] \n\t"
            "str %[t], [%[r],#12] \n\t"
            "ldr %[t], [%[x],#16] \n\t"
            "ldr %[s], [%[y],#16] \n\t"
            "sbc %[t], %[t], %[s] \n\t"
            "str %[t], [%[r],#16] \n\t"
            "ldr %[t], [%[x],#20] \n\t"
            "ldr %[s], [%[y],#20] \n\t"
            "sbc %[t], %[t], %[s] \n\t"
            "str %[t], [%[r],#20] \n\t"
            "ldr %[t], [%[x],#24] \n\t"
            "ldr %[s], [%[y],#24] \n\t"
            "sbc %[t], %[t], %[s] \n\t"
            "str %[t], [%[r],#24] \n\t"
            "ldr %[t], [%[x],#28] \n\t"
            "ldr %[s], [%[y],#28] \n\t"
            "sbc %[t], %[t], %[s] \n\t"
            "str %[t], [%[r],#28] \n\t"
        ".foot: \n\t"
            "bcs .nocarry \n\t"
            "mov %[t], #1 \n\t"
            "b .end \n\t"
        ".nocarry: \n\t"
            "mov %[t], #0 \n\t"
        ".end: \n\t"
    : /* out */
        [t] "+r" (total),
        [s] "+r" (toSub)
    : /* in */
        [x] "r" (x),
        [y] "r" (y),
        [r] "r" (result),
        [l] "r" (length)
    : /* clobber list */
        "memory"
    );

    return total;
#endif

#if ALGO == 3
    uint32_t total;
    uint32_t toSub;

    asm volatile(
            "ldr %[t], [%[x],#0] \n\t"
            "ldr %[s], [%[y],#0] \n\t"
            "sub %[t], %[t], %[s] \n\t"
            "str %[t], [%[r],#0] \n\t"
            "ldr %[t], [%[x],#4] \n\t"
            "ldr %[s], [%[y],#4] \n\t"
            "sbc %[t], %[t], %[s] \n\t"
            "str %[t], [%[r],#4] \n\t"
            "ldr %[t], [%[x],#8] \n\t"
            "ldr %[s], [%[y],#8] \n\t"
            "sbc %[t], %[t], %[s] \n\t"
            "str %[t], [%[r],#8] \n\t"
            "ldr %[t], [%[x],#12] \n\t"
            "ldr %[s], [%[y],#12] \n\t"
            "sbc %[t], %[t], %[s] \n\t"
            "str %[t], [%[r],#12] \n\t"
            "ldr %[t], [%[x],#16] \n\t"
            "ldr %[s], [%[y],#16] \n\t"
            "sbc %[t], %[t], %[s] \n\t"
            "str %[t], [%[r],#16] \n\t"
            "ldr %[t], [%[x],#20] \n\t"
            "ldr %[s], [%[y],#20] \n\t"
            "sbc %[t], %[t], %[s] \n\t"
            "str %[t], [%[r],#20] \n\t"
            "ldr %[t], [%[x],#24] \n\t"
            "ldr %[s], [%[y],#24] \n\t"
            "sbc %[t], %[t], %[s] \n\t"
            "str %[t], [%[r],#24] \n\t"
            "ldr %[t], [%[x],#28] \n\t"
            "ldr %[s], [%[y],#28] \n\t"
            "sbc %[t], %[t], %[s] \n\t"
            "str %[t], [%[r],#28] \n\t"
        ".foot: \n\t"
            "bcs .nocarry \n\t"
            "mov %[t], #1 \n\t"
            "b .end \n\t"
        ".nocarry: \n\t"
            "mov %[t], #0 \n\t"
        ".end: \n\t"
    : /* out */
        [t] "+r" (total),
        [s] "+r" (toSub)
    : /* in */
        [x] "r" (x),
        [y] "r" (y),
        [r] "r" (result),
        [l] "r" (length)
    : /* clobber list */
        "memory"
    );

    return total;
#endif

}
