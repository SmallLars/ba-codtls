#include "ecc_add.h"

#include <string.h>

#define ALGO 3
// NR | Beschreibung | Größe | Geschwindigkeit | Status auf Econotag
//  0 | C-Code       |     0 | Langsam         | Funktioniert
//  1 | ASM          |   -20 | Mittel          | Funktioniert
//  2 | 1,2,4,8,2x8  |  +168 | Schnell         | Funktioniert - Interpolation von 512-bit-Addition durch 2 bis 3 256-bit-Additionen
//  3 | 1,2,4,8,16   |  +212 | Schnell         | Funktioniert
//  4 | ASM nur 8    |   +96 | Schnell         | Funktioniert - Unbrauchbar für ECC da nur 256-bit-Addition nicht ausreicht

uint8_t ecc_add( const uint32_t *x, const uint32_t *y, uint32_t *result, uint8_t length) {

#if ALGO == 0
    uint8_t d = 0; // carry
    uint8_t v = 0;

    for(;v<length;v++){
        result[v] = x[v] + y[v];
        if(result[v]<x[v] || result[v]<y[v]) {
            result[v] += d;
            d = 1;
        } else {
            if (d==1 && result[v]==0xffffffff){
                // d = 1; //omitted, because d is already 1
                result[v] = 0x0;
            } else {
                result[v] += d;
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
    uint32_t toAdd;

    asm volatile(
            "lsl %[l], #2 \n\t"             // length *= 4 for bytecount
            "mov %[i], #0 \n\t"             // index = 0
            "mov %[c], #0 \n\t"             // carry = 0
        ".loop: \n\t"
            "ldr %[t], [%[x],%[i]] \n\t"    // total = x[index]
            "cmp %[c], #0 \n\t"             // carry == 0
            "beq .nocarry1 \n\t"            // == ? skip carry add
            "mov %[c], #0 \n\t"             // carry = 0
            "add %[t], %[t], #1 \n\t"       // total ++
            "bcc .nocarry1 \n\t"            // carry == 0 ? skip next
            "mov %[c], #1 \n\t"             // carry = 1
        ".nocarry1: \n\t"
            "ldr %[s], [%[y],%[i]] \n\t"    // toAdd = y[index]
            "add %[t], %[t], %[s] \n\t"     // total += toAdd
            "bcc .nocarry2 \n\t"            // carry == 0 ? skip next
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
        [s] "+r" (toAdd)
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
    if (length == 16) {
        uint8_t c1 = ecc_add(x, y, result, 8);
        uint8_t c2 = ecc_add(x + 8, y + 8, result + 8, 8);
        if (c1) {
            uint32_t z[8];
            memset(z, 0, 32);
            z[0] = 0x0000001;
            c2 |= ecc_add(result + 8, z, result + 8, 8);
        }
        return c2;
    }

    uint32_t total;
    uint32_t toAdd;

    asm volatile(
            "cmp %[l], #2 \n\t"
            "beq .add2 \n\t"
            "bhi .add4or8 \n\t"
        ".add1: \n\t"
            "ldr %[t], [%[x],#0] \n\t"
            "ldr %[s], [%[y],#0] \n\t"
            "add %[t], %[t], %[s] \n\t"
            "str %[t], [%[r],#0] \n\t"
            "b .foot \n\t"
        ".add2: \n\t"
            "ldr %[t], [%[x],#0] \n\t"
            "ldr %[s], [%[y],#0] \n\t"
            "add %[t], %[t], %[s] \n\t"
            "str %[t], [%[r],#0] \n\t"
            "ldr %[t], [%[x],#4] \n\t"
            "ldr %[s], [%[y],#4] \n\t"
            "adc %[t], %[t], %[s] \n\t"
            "str %[t], [%[r],#4] \n\t"
            "b .foot \n\t"
        ".add4or8: \n\t"
            "cmp %[l], #8 \n\t"
            "beq .add8 \n\t"
        ".add4: \n\t"
            "ldr %[t], [%[x],#0] \n\t"
            "ldr %[s], [%[y],#0] \n\t"
            "add %[t], %[t], %[s] \n\t"
            "str %[t], [%[r],#0] \n\t"
            "ldr %[t], [%[x],#4] \n\t"
            "ldr %[s], [%[y],#4] \n\t"
            "adc %[t], %[t], %[s] \n\t"
            "str %[t], [%[r],#4] \n\t"
            "ldr %[t], [%[x],#8] \n\t"
            "ldr %[s], [%[y],#8] \n\t"
            "adc %[t], %[t], %[s] \n\t"
            "str %[t], [%[r],#8] \n\t"
            "ldr %[t], [%[x],#12] \n\t"
            "ldr %[s], [%[y],#12] \n\t"
            "adc %[t], %[t], %[s] \n\t"
            "str %[t], [%[r],#12] \n\t"
            "b .foot \n\t"
        ".add8: \n\t"
            "ldr %[t], [%[x],#0] \n\t"
            "ldr %[s], [%[y],#0] \n\t"
            "add %[t], %[t], %[s] \n\t"
            "str %[t], [%[r],#0] \n\t"
            "ldr %[t], [%[x],#4] \n\t"
            "ldr %[s], [%[y],#4] \n\t"
            "adc %[t], %[t], %[s] \n\t"
            "str %[t], [%[r],#4] \n\t"
            "ldr %[t], [%[x],#8] \n\t"
            "ldr %[s], [%[y],#8] \n\t"
            "adc %[t], %[t], %[s] \n\t"
            "str %[t], [%[r],#8] \n\t"
            "ldr %[t], [%[x],#12] \n\t"
            "ldr %[s], [%[y],#12] \n\t"
            "adc %[t], %[t], %[s] \n\t"
            "str %[t], [%[r],#12] \n\t"
            "ldr %[t], [%[x],#16] \n\t"
            "ldr %[s], [%[y],#16] \n\t"
            "adc %[t], %[t], %[s] \n\t"
            "str %[t], [%[r],#16] \n\t"
            "ldr %[t], [%[x],#20] \n\t"
            "ldr %[s], [%[y],#20] \n\t"
            "adc %[t], %[t], %[s] \n\t"
            "str %[t], [%[r],#20] \n\t"
            "ldr %[t], [%[x],#24] \n\t"
            "ldr %[s], [%[y],#24] \n\t"
            "adc %[t], %[t], %[s] \n\t"
            "str %[t], [%[r],#24] \n\t"
            "ldr %[t], [%[x],#28] \n\t"
            "ldr %[s], [%[y],#28] \n\t"
            "adc %[t], %[t], %[s] \n\t"
            "str %[t], [%[r],#28] \n\t"
        ".foot: \n\t"
            "bcc .nocarry \n\t"
            "mov %[t], #1 \n\t"
            "b .end \n\t"
        ".nocarry: \n\t"
            "mov %[t], #0 \n\t"
        ".end: \n\t"
    : /* out */
        [t] "+r" (total),
        [s] "+r" (toAdd)
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
    register uint32_t carry asm("r3");

    asm volatile(
            "cmp %[l], #2 \n\t"
            "beq .add2 \n\t"
            "bhi .add4or8or16 \n\t"
        ".add1: \n\t"
            "ldr r3, [%[x],#0] \n\t"
            "ldr r4, [%[y],#0] \n\t"
            "add r3, r3, r4 \n\t"
            "str r3, [%[r],#0] \n\t"
            "b .foot \n\t"
        ".add2: \n\t"
            "ldr r3, [%[x],#0] \n\t"
            "ldr r4, [%[y],#0] \n\t"
            "add r3, r3, r4 \n\t"
            "str r3, [%[r],#0] \n\t"
            "ldr r3, [%[x],#4] \n\t"
            "ldr r4, [%[y],#4] \n\t"
            "adc r3, r3, r4 \n\t"
            "str r3, [%[r],#4] \n\t"
            "b .foot \n\t"
        ".add4or8or16: \n\t"
            "cmp %[l], #8 \n\t"
            "beq .add8 \n\t"
            "bhi .add16 \n\t"
        ".add4: \n\t"
            "ldr r3, [%[x],#0] \n\t"
            "ldr r4, [%[y],#0] \n\t"
            "add r3, r3, r4 \n\t"
            "str r3, [%[r],#0] \n\t"
            "ldr r3, [%[x],#4] \n\t"
            "ldr r4, [%[y],#4] \n\t"
            "adc r3, r3, r4 \n\t"
            "str r3, [%[r],#4] \n\t"
            "ldr r3, [%[x],#8] \n\t"
            "ldr r4, [%[y],#8] \n\t"
            "adc r3, r3, r4 \n\t"
            "str r3, [%[r],#8] \n\t"
            "ldr r3, [%[x],#12] \n\t"
            "ldr r4, [%[y],#12] \n\t"
            "adc r3, r3, r4 \n\t"
            "str r3, [%[r],#12] \n\t"
            "b .foot \n\t"
        ".add8: \n\t"
            "ldr r3, [%[x],#0] \n\t"
            "ldr r4, [%[y],#0] \n\t"
            "add r3, r3, r4 \n\t"
            "str r3, [%[r],#0] \n\t"
            "ldr r3, [%[x],#4] \n\t"
            "ldr r4, [%[y],#4] \n\t"
            "adc r3, r3, r4 \n\t"
            "str r3, [%[r],#4] \n\t"
            "ldr r3, [%[x],#8] \n\t"
            "ldr r4, [%[y],#8] \n\t"
            "adc r3, r3, r4 \n\t"
            "str r3, [%[r],#8] \n\t"
            "ldr r3, [%[x],#12] \n\t"
            "ldr r4, [%[y],#12] \n\t"
            "adc r3, r3, r4 \n\t"
            "str r3, [%[r],#12] \n\t"
            "ldr r3, [%[x],#16] \n\t"
            "ldr r4, [%[y],#16] \n\t"
            "adc r3, r3, r4 \n\t"
            "str r3, [%[r],#16] \n\t"
            "ldr r3, [%[x],#20] \n\t"
            "ldr r4, [%[y],#20] \n\t"
            "adc r3, r3, r4 \n\t"
            "str r3, [%[r],#20] \n\t"
            "ldr r3, [%[x],#24] \n\t"
            "ldr r4, [%[y],#24] \n\t"
            "adc r3, r3, r4 \n\t"
            "str r3, [%[r],#24] \n\t"
            "ldr r3, [%[x],#28] \n\t"
            "ldr r4, [%[y],#28] \n\t"
            "adc r3, r3, r4 \n\t"
            "str r3, [%[r],#28] \n\t"
            "b .foot \n\t"
        ".add16: \n\t"
            "ldr r3, [%[x],#0] \n\t"
            "ldr r4, [%[y],#0] \n\t"
            "add r3, r3, r4 \n\t"
            "str r3, [%[r],#0] \n\t"
            "ldr r3, [%[x],#4] \n\t"
            "ldr r4, [%[y],#4] \n\t"
            "adc r3, r3, r4 \n\t"
            "str r3, [%[r],#4] \n\t"
            "ldr r3, [%[x],#8] \n\t"
            "ldr r4, [%[y],#8] \n\t"
            "adc r3, r3, r4 \n\t"
            "str r3, [%[r],#8] \n\t"
            "ldr r3, [%[x],#12] \n\t"
            "ldr r4, [%[y],#12] \n\t"
            "adc r3, r3, r4 \n\t"
            "str r3, [%[r],#12] \n\t"
            "ldr r3, [%[x],#16] \n\t"
            "ldr r4, [%[y],#16] \n\t"
            "adc r3, r3, r4 \n\t"
            "str r3, [%[r],#16] \n\t"
            "ldr r3, [%[x],#20] \n\t"
            "ldr r4, [%[y],#20] \n\t"
            "adc r3, r3, r4 \n\t"
            "str r3, [%[r],#20] \n\t"
            "ldr r3, [%[x],#24] \n\t"
            "ldr r4, [%[y],#24] \n\t"
            "adc r3, r3, r4 \n\t"
            "str r3, [%[r],#24] \n\t"
            "ldr r3, [%[x],#28] \n\t"
            "ldr r4, [%[y],#28] \n\t"
            "adc r3, r3, r4 \n\t"
            "str r3, [%[r],#28] \n\t"
            "ldr r3, [%[x],#32] \n\t"
            "ldr r4, [%[y],#32] \n\t"
            "adc r3, r3, r4 \n\t"
            "str r3, [%[r],#32] \n\t"
            "ldr r3, [%[x],#36] \n\t"
            "ldr r4, [%[y],#36] \n\t"
            "adc r3, r3, r4 \n\t"
            "str r3, [%[r],#36] \n\t"
            "ldr r3, [%[x],#40] \n\t"
            "ldr r4, [%[y],#40] \n\t"
            "adc r3, r3, r4 \n\t"
            "str r3, [%[r],#40] \n\t"
            "ldr r3, [%[x],#44] \n\t"
            "ldr r4, [%[y],#44] \n\t"
            "adc r3, r3, r4 \n\t"
            "str r3, [%[r],#44] \n\t"
            "ldr r3, [%[x],#48] \n\t"
            "ldr r4, [%[y],#48] \n\t"
            "adc r3, r3, r4 \n\t"
            "str r3, [%[r],#48] \n\t"
            "ldr r3, [%[x],#52] \n\t"
            "ldr r4, [%[y],#52] \n\t"
            "adc r3, r3, r4 \n\t"
            "str r3, [%[r],#52] \n\t"
            "ldr r3, [%[x],#56] \n\t"
            "ldr r4, [%[y],#56] \n\t"
            "adc r3, r3, r4 \n\t"
            "str r3, [%[r],#56] \n\t"
            "ldr r3, [%[x],#60] \n\t"
            "ldr r4, [%[y],#60] \n\t"
            "adc r3, r3, r4 \n\t"
            "str r3, [%[r],#60] \n\t"
        ".foot: \n\t"
            "bcc .nocarry \n\t"
            "mov r3, #1 \n\t"
            "b .end \n\t"
        ".nocarry: \n\t"
            "mov r3, #0 \n\t"
        ".end: \n\t"
    : /* out */
    : /* in */
        [x] "r" (x),
        [y] "r" (y),
        [r] "r" (result),
        [l] "r" (length)
    : /* clobber list */
        "r3", "r4", "memory"
    );

    return carry;
#endif

#if ALGO == 4
    uint32_t total;
    uint32_t toAdd;

    asm volatile(
            "ldr %[t], [%[x],#0] \n\t"
            "ldr %[s], [%[y],#0] \n\t"
            "add %[t], %[t], %[s] \n\t"
            "str %[t], [%[r],#0] \n\t"
            "ldr %[t], [%[x],#4] \n\t"
            "ldr %[s], [%[y],#4] \n\t"
            "adc %[t], %[t], %[s] \n\t"
            "str %[t], [%[r],#4] \n\t"
            "ldr %[t], [%[x],#8] \n\t"
            "ldr %[s], [%[y],#8] \n\t"
            "adc %[t], %[t], %[s] \n\t"
            "str %[t], [%[r],#8] \n\t"
            "ldr %[t], [%[x],#12] \n\t"
            "ldr %[s], [%[y],#12] \n\t"
            "adc %[t], %[t], %[s] \n\t"
            "str %[t], [%[r],#12] \n\t"
            "ldr %[t], [%[x],#16] \n\t"
            "ldr %[s], [%[y],#16] \n\t"
            "adc %[t], %[t], %[s] \n\t"
            "str %[t], [%[r],#16] \n\t"
            "ldr %[t], [%[x],#20] \n\t"
            "ldr %[s], [%[y],#20] \n\t"
            "adc %[t], %[t], %[s] \n\t"
            "str %[t], [%[r],#20] \n\t"
            "ldr %[t], [%[x],#24] \n\t"
            "ldr %[s], [%[y],#24] \n\t"
            "adc %[t], %[t], %[s] \n\t"
            "str %[t], [%[r],#24] \n\t"
            "ldr %[t], [%[x],#28] \n\t"
            "ldr %[s], [%[y],#28] \n\t"
            "adc %[t], %[t], %[s] \n\t"
            "str %[t], [%[r],#28] \n\t"
        ".foot: \n\t"
            "bcc .nocarry \n\t"
            "mov %[t], #1 \n\t"
            "b .end \n\t"
        ".nocarry: \n\t"
            "mov %[t], #0 \n\t"
        ".end: \n\t"
    : /* out */
        [t] "+r" (total),
        [s] "+r" (toAdd)
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
