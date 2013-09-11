#include "ecc_add.h"

#include <string.h>

#define ALGO 2
// NR | Beschreibung | Größe | Geschwindigkeit | Status auf Econotag
//  0 | C-Code       |     0 | Langsam         | Funktioniert
//  1 | ASM          |   -24 | Mittel          | Funktioniert
//  2 | 1,2,4,8,16   |  +116 | Schnell         | Funktioniert
//  3 | ASM nur 8    |   -24 | Schnell         | Funktioniert - Unbrauchbar für ECC da nur 256-bit-Addition nicht ausreicht

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
        [i] "+l" (index),
        [c] "+l" (carry),
        [t] "+l" (total),
        [s] "+l" (toAdd)
    : /* in */
        [x] "l" (x),
        [y] "l" (y),
        [r] "l" (result),
        [l] "l" (length)
    : /* clobber list */
        "memory"
    );
    return carry;
#endif

#if ALGO == 2
    register uint32_t carry asm("r4");

    asm volatile(
            "cmp %[l], #2 \n\t"
            "beq .add2 \n\t"
            "bhi .add4or8or16 \n\t"
        ".add1: \n\t"
            "ldm %[x], {r4} \n\t"
            "ldm %[y], {r6} \n\t"
            "add r4, r4, r6 \n\t"
            "stm %[r], {r4} \n\t"
            "b .foot \n\t"
        ".add2: \n\t"
            "ldm %[x], {r4,r5} \n\t"
            "ldm %[y], {r6,r7} \n\t"
            "add r4, r4, r6 \n\t"
            "adc r5, r5, r7 \n\t"
            "stm %[r], {r4,r5} \n\t"
            "b .foot \n\t"
        ".add4or8or16: \n\t"
            "cmp %[l], #8 \n\t"
            "beq .add8 \n\t"
            "bhi .add16 \n\t"
        ".add4: \n\t"
            "ldm %[x], {r4,r5} \n\t"
            "ldm %[y], {r6,r7} \n\t"
            "add r4, r4, r6 \n\t"
            "adc r5, r5, r7 \n\t"
            "stm %[r], {r4,r5} \n\t"
            "ldm %[x], {r4,r5} \n\t"
            "ldm %[y], {r6,r7} \n\t"
            "adc r4, r4, r6 \n\t"
            "adc r5, r5, r7 \n\t"
            "stm %[r], {r4,r5} \n\t"
            "b .foot \n\t"
        ".add8: \n\t"
            "ldm %[x], {r4,r5} \n\t"
            "ldm %[y], {r6,r7} \n\t"
            "add r4, r4, r6 \n\t"
            "adc r5, r5, r7 \n\t"
            "stm %[r], {r4,r5} \n\t"
            "ldm %[x], {r4,r5} \n\t"
            "ldm %[y], {r6,r7} \n\t"
            "adc r4, r4, r6 \n\t"
            "adc r5, r5, r7 \n\t"
            "stm %[r], {r4,r5} \n\t"
            "ldm %[x], {r4,r5} \n\t"
            "ldm %[y], {r6,r7} \n\t"
            "adc r4, r4, r6 \n\t"
            "adc r5, r5, r7 \n\t"
            "stm %[r], {r4,r5} \n\t"
            "ldm %[x], {r4,r5} \n\t"
            "ldm %[y], {r6,r7} \n\t"
            "adc r4, r4, r6 \n\t"
            "adc r5, r5, r7 \n\t"
            "stm %[r], {r4,r5} \n\t"
            "b .foot \n\t"
        ".add16: \n\t"
            "ldm %[x], {r4,r5} \n\t"
            "ldm %[y], {r6,r7} \n\t"
            "add r4, r4, r6 \n\t"
            "adc r5, r5, r7 \n\t"
            "stm %[r], {r4,r5} \n\t"
            "ldm %[x], {r4,r5} \n\t"
            "ldm %[y], {r6,r7} \n\t"
            "adc r4, r4, r6 \n\t"
            "adc r5, r5, r7 \n\t"
            "stm %[r], {r4,r5} \n\t"
            "ldm %[x], {r4,r5} \n\t"
            "ldm %[y], {r6,r7} \n\t"
            "adc r4, r4, r6 \n\t"
            "adc r5, r5, r7 \n\t"
            "stm %[r], {r4,r5} \n\t"
            "ldm %[x], {r4,r5} \n\t"
            "ldm %[y], {r6,r7} \n\t"
            "adc r4, r4, r6 \n\t"
            "adc r5, r5, r7 \n\t"
            "stm %[r], {r4,r5} \n\t"
            "ldm %[x], {r4,r5} \n\t"
            "ldm %[y], {r6,r7} \n\t"
            "adc r4, r4, r6 \n\t"
            "adc r5, r5, r7 \n\t"
            "stm %[r], {r4,r5} \n\t"
            "ldm %[x], {r4,r5} \n\t"
            "ldm %[y], {r6,r7} \n\t"
            "adc r4, r4, r6 \n\t"
            "adc r5, r5, r7 \n\t"
            "stm %[r], {r4,r5} \n\t"
            "ldm %[x], {r4,r5} \n\t"
            "ldm %[y], {r6,r7} \n\t"
            "adc r4, r4, r6 \n\t"
            "adc r5, r5, r7 \n\t"
            "stm %[r], {r4,r5} \n\t"
            "ldm %[x], {r4,r5} \n\t"
            "ldm %[y], {r6,r7} \n\t"
            "adc r4, r4, r6 \n\t"
            "adc r5, r5, r7 \n\t"
            "stm %[r], {r4,r5} \n\t"
        ".foot: \n\t"
            "bcc .nocarry \n\t"
            "mov r4, #1 \n\t"
            "b .end \n\t"
        ".nocarry: \n\t"
            "mov r4, #0 \n\t"
        ".end: \n\t"
    : /* out */
    : /* in */
        [x] "l" (x),
        [y] "l" (y),
        [r] "l" (result),
        [l] "l" (length)
    : /* clobber list */
        "r4", "r5", "r6", "r7", "memory"
    );

    return carry;
#endif

#if ALGO == 3
    uint32_t carry;

    asm volatile(
            "ldm %[x], {r4,r5} \n\t"
            "ldm %[y], {r6,r7} \n\t"
            "add r4, r4, r6 \n\t"
            "adc r5, r5, r7 \n\t"
            "stm %[r], {r4,r5} \n\t"
            "ldm %[x], {r4,r5} \n\t"
            "ldm %[y], {r6,r7} \n\t"
            "adc r4, r4, r6 \n\t"
            "adc r5, r5, r7 \n\t"
            "stm %[r], {r4,r5} \n\t"
            "ldm %[x], {r4,r5} \n\t"
            "ldm %[y], {r6,r7} \n\t"
            "adc r4, r4, r6 \n\t"
            "adc r5, r5, r7 \n\t"
            "stm %[r], {r4,r5} \n\t"
            "ldm %[x], {r4,r5} \n\t"
            "ldm %[y], {r6,r7} \n\t"
            "adc r4, r4, r6 \n\t"
            "adc r5, r5, r7 \n\t"
            "stm %[r], {r4,r5} \n\t"
        ".foot: \n\t"
            "bcc .nocarry \n\t"
            "mov %[c], #1 \n\t"
            "b .end \n\t"
        ".nocarry: \n\t"
            "mov %[c], #0 \n\t"
        ".end: \n\t"
    : /* out */
        [c] "=l" (carry)
    : /* in */
        [x] "l" (x),
        [y] "l" (y),
        [r] "l" (result)
    : /* clobber list */
        "r4", "r5", "r6", "r7", "memory"
    );

    return carry;
#endif

}
