#include "ecc_add.h"

#include <string.h>

#define ALGO 2
// NR | Beschreibung | Größe | Geschwindigkeit | Status auf Econotag
//  0 | C-Code       |     0 | Langsam         | Funktioniert
//  1 | ASM          |   -20 | Mittel          | Funktioniert
//  2 | ASM 1,2,4,8  |  +168 | Schnell         | Funktioniert
//  3 | ASM nur 8    |   +96 | Schnell         | Unbrauchbar für ECC

uint8_t ecc_add( const uint32_t *x, const uint32_t *y, uint32_t *result, uint8_t length) {

// Unterstützung für 512 Bit Addition bei ALGO 2 und 3 -> + 84 Byte Größe
#if ALGO == 2 || ALGO == 3
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
#endif

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
