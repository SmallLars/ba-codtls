/*
 * Copyright (c) 2009 Chris K Cockrum <ckc@cockrum.net>
 *
 * Copyright (c) 2013 Jens Trillmann <jtrillma@tzi.de>
 * Copyright (c) 2013 Marc Müller-Weinhardt <muewei@tzi.de>
 * Copyright (c) 2013 Lars Schmertmann <lars@tzi.de>
 * Copyright (c) 2013 Hauke Mehrtens <hauke@hauke-m.de>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 *
 * This implementation is based in part on the paper Implementation of an
 * Elliptic Curve Cryptosystem on an 8-bit Microcontroller [0] by
 * Chris K Cockrum <ckc@cockrum.net>.
 *
 * [0]: http://cockrum.net/Implementation_of_ECC_on_an_8-bit_microcontroller.pdf
 *
 * This is a efficient ECC implementation on the secp256r1 curve for 32 Bit CPU
 * architectures. It provides basic operations on the secp256r1 curve and support
 * for ECDH and ECDSA.
 */

#include "ecc.h"

#include <string.h>

#include "ecc_add.h"
#include "ecc_sub.h"
#include "ecc_rshift.h"

/*---------------------------------------------------------------------------*/

#define keyLengthInBytes 32
#define arrayLength 8

//finite field functions FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
const uint32_t ecc_prime_m[8] = {0xffffffff, 0xffffffff, 0xffffffff, 0x00000000, 0x00000000, 0x00000000, 0x00000001, 0xffffffff};

/* This is added after an static byte addition if the answer has a carry in MSB*/
const uint32_t ecc_prime_r[8] = {0x00000001, 0x00000000, 0x00000000, 0xffffffff, 0xffffffff, 0xffffffff, 0xfffffffe, 0x00000000};

/* Private Funktionsprototypen --------------------------------------------- */

//simple functions to work with the big numbers
static void ecc_setZero(uint32_t *A, const uint32_t length);
static void ecc_copy(uint32_t *dst, const uint32_t *src);
static unsigned int ecc_isX(const uint32_t* A, const uint32_t X);
__attribute__((always_inline)) static void ecc_lshift(uint32_t *x, const int32_t length, const int32_t shiftSize);

//ecc_fieldModP-Helper
__attribute__((always_inline)) static void ecc_form_s1(uint32_t *dst, const uint32_t *src);
__attribute__((always_inline)) static void ecc_form_s2(uint32_t *dst, const uint32_t *src);
__attribute__((always_inline)) static void ecc_form_s3(uint32_t *dst, const uint32_t *src);
__attribute__((always_inline)) static void ecc_form_s4(uint32_t *dst, const uint32_t *src);
__attribute__((always_inline)) static void ecc_form_d1(uint32_t *dst, const uint32_t *src);
__attribute__((always_inline)) static void ecc_form_d2(uint32_t *dst, const uint32_t *src);
__attribute__((always_inline)) static void ecc_form_d3(uint32_t *dst, const uint32_t *src);
__attribute__((always_inline)) static void ecc_form_d4(uint32_t *dst, const uint32_t *src);

//field functions for big numbers
int ecc_fieldAdd(const uint32_t *x, const uint32_t *y, const uint32_t *reducer, uint32_t *result);
int ecc_fieldSub(const uint32_t *x, const uint32_t *y, const uint32_t *modulus, uint32_t *result);
int ecc_fieldMult(const uint32_t *x, const uint32_t *y, uint32_t *result, const uint32_t length);
void ecc_fieldModP(uint32_t *A, const uint32_t *B);
static int ecc_fieldAddAndDivide(const uint32_t *x, const uint32_t *modulus, const uint32_t *reducer, uint32_t* result);
void ecc_fieldInv(const uint32_t *A, const uint32_t *modulus, const uint32_t *reducer, uint32_t *B);

//ec Functions
void ecc_ec_add(const uint32_t *px, const uint32_t *py, const uint32_t *qx, const uint32_t *qy, uint32_t *Sx, uint32_t *Sy);
void ecc_ec_double(const uint32_t *px, const uint32_t *py, uint32_t *Dx, uint32_t *Dy);

/* Öffentliche Funktionen -------------------------------------------------- */

signed int ecc_compare(const uint32_t *A, const uint32_t *B) {
    int i;
    for (i = 7; i >= 0; i--) {
        if (A[i] > B[i]) return 1; 
        if (A[i] < B[i]) return -1;
    }
    return 0;
}

void ecc_ec_mult(const uint32_t *px, const uint32_t *py, const uint32_t *secret, uint32_t *resultx, uint32_t *resulty) {
    uint32_t Qx[8];
    uint32_t Qy[8];
    ecc_setZero(Qx, 8);
    ecc_setZero(Qy, 8);

    int i;
    for (i = 256;i--;){
        ecc_ec_double(Qx, Qy, resultx, resulty);
        ecc_copy(Qx, resultx);
        ecc_copy(Qy, resulty);
        if ((((secret[i/32])>>(i%32)) & 0x01) == 1){ //<- TODO quark, muss anders gemacht werden
            ecc_ec_add(Qx, Qy, px, py, resultx, resulty); //eccAdd
            ecc_copy(Qx, resultx);
            ecc_copy(Qy, resulty);
        }
    }
    ecc_copy(resultx, Qx);
    ecc_copy(resulty, Qy);
}

/* Private Funktionen ------------------------------------------------------ */

static void ecc_setZero(uint32_t *A, const uint32_t length) {
/*
    int i;

    for (i = 0; i < length; ++i)
    {
        A[i] = 0;
    }
*/
    asm volatile(
            "mov r2, $0 \n\t"
            "stm %[a], {r2} \n\t"
            "cmp %[l], #1 \n\t"
            "beq .endZero \n\t"
            "stm %[a], {r2} \n\t"
            "cmp %[l], #2 \n\t"
            "beq .endZero \n\t"
            "mov r3, $0 \n\t"
            "stm %[a], {r2, r3} \n\t"
            "cmp %[l], #4 \n\t"
            "beq .endZero \n\t"
            "stm %[a], {r2-r3} \n\t"
            "stm %[a], {r2-r3} \n\t"
        ".endZero: \n\t"
    : // out
    : // in
        [a] "l" (A),
        [l] "l" (length)
    : // clobber list
        "r2", "r3", "memory"
    );
}

/*
 * copy one array to another
 */
static void ecc_copy(uint32_t *dst, const uint32_t *src) {
    asm volatile(
        "ldm %[s], {r2-r5} \n\t"
        "stm %[d], {r2-r5} \n\t"
        "ldm %[s], {r2-r5} \n\t"
        "stm %[d], {r2-r5} \n\t"
    : // out
    : // in
        [d] "l" (dst),
        [s] "l" (src)
    : // clobber list
        "r2", "r3", "r4", "r5", "memory"
    );
}

static unsigned int ecc_isX(const uint32_t* A, const uint32_t X) {
    if (A[0] != X) return 0;

    uint8_t n; 
    for (n = 1; n < 8; n++) 
        if (A[n] != 0) 
            return 0;

    return 1;

/*
    uint8_t result;

    asm volatile(
            "ldm %[a], {r2-r5} \n\t"
            "cmp r2, %[x] \n\t"
            "bne 0f \n\t"
            "cmp r3, #0 \n\t"
            "bne 0f \n\t"
            "cmp r4, #0 \n\t"
            "bne 0f \n\t"
            "cmp r5, #0 \n\t"
            "bne 0f \n\t"
            "ldm %[a], {r2-r5} \n\t"
            "cmp r2, #0 \n\t"
            "bne 0f \n\t"
            "cmp r3, #0 \n\t"
            "bne 0f \n\t"
            "cmp r4, #0 \n\t"
            "bne 0f \n\t"
            "cmp r5, #0 \n\t"
            "bne 0f \n\t"
            "mov %[r], #1 \n\t"
            "bne 1f \n\t"
        "0: \n\t"
            "mov %[r], #0 \n\t"
        "1: \n\t"
    : // out
        [r] "=l" (result)
    : // in
        [a] "l" (A),
        [x] "l" (X)
    : // clobber list
        "r2", "r3", "r4", "r5", "memory"
    );

    return result;
*/
}

__attribute__((always_inline)) static void ecc_lshift(uint32_t *x, const int32_t length, const int32_t shiftSize) {
    int32_t i;
    for(i = ((length/2) + shiftSize)-1; i>=0; --i){
        if(i-shiftSize < 0){
            x[i] = 0;
        } else {
            x[i] = x[i-shiftSize];
        }
    }
}

/*---------------------------------------------------------------------------*/

__attribute__((always_inline)) static void ecc_form_s1(uint32_t *dst, const uint32_t *src) {
    // 0, 0, 0, src[11], src[12], src[13], src[14], src[15]
    asm volatile(
        "mov r2, #0 \n\t"
        "mov r3, #0 \n\t"
        "mov r4, #0 \n\t"
        "stm %[d], {r2-r4} \n\t"
        "add %[s], %[s], #44 \n\t"
        "ldm %[s], {r2-r6} \n\t"
        "stm %[d], {r2-r6} \n\t"
    : // out
        [d] "+l" (dst),
        [s] "+l" (src)
    : // in
    : // clobber list
        "r2", "r3", "r4", "r5", "r6", "memory"
    );
}

__attribute__((always_inline)) static void ecc_form_s2(uint32_t *dst, const uint32_t *src) {
    // 0, 0, 0, src[12], src[13], src[14], src[15], 0
    asm volatile(
        "mov r2, #0 \n\t"
        "mov r3, #0 \n\t"
        "mov r4, #0 \n\t"
        "stm %[d], {r2-r4} \n\t"
        "add %[s], %[s], #48 \n\t"
        "ldm %[s], {r2-r5} \n\t"
        "stm %[d], {r2-r5} \n\t"
        "mov r2, #0 \n\t"
        "stm %[d], {r2} \n\t"
    : // out
        [d] "+l" (dst),
        [s] "+l" (src)
    : // in
    : // clobber list
        "r2", "r3", "r4", "r5", "memory"
    );
}

__attribute__((always_inline)) static void ecc_form_s3(uint32_t *dst, const uint32_t *src) {
    // src[8], src[9], src[10], 0, 0, 0, src[14], src[15]
    asm volatile(
        "add %[s], %[s], #32 \n\t"
        "ldm %[s], {r2-r4} \n\t"
        "mov r5, #0 \n\t"
        "stm %[d], {r2-r5} \n\t"
        "mov r2, #0 \n\t"
        "mov r3, #0 \n\t"
        "add %[s], %[s], #12 \n\t"
        "ldm %[s], {r4,r5} \n\t"
        "stm %[d], {r2-r5} \n\t"
    : // out
        [d] "+l" (dst),
        [s] "+l" (src)
    : // in
    : // clobber list
        "r2", "r3", "r4", "r5", "memory"
    );
}

__attribute__((always_inline)) static void ecc_form_s4(uint32_t *dst, const uint32_t *src) {
    // src[9], src[10], src[11], src[13], src[14], src[15], src[13], src[8]
    asm volatile(
        "add %[s], %[s], #32 \n\t"
        "ldm %[s], {r2-r5} \n\t"
        "stm %[d], {r3-r5} \n\t"
        "add %[s], %[s], #4 \n\t"
        "ldm %[s], {r3-r5} \n\t"
        "stm %[d], {r3-r5} \n\t"
        "mov r4, r2 \n\t"
        "stm %[d], {r3,r4} \n\t"
    : // out
        [d] "+l" (dst),
        [s] "+l" (src)
    : // in
    : // clobber list
        "r2", "r3", "r4", "r5", "memory"
    );
}

__attribute__((always_inline)) static void ecc_form_d1(uint32_t *dst, const uint32_t *src) {
    // src[11], src[12], src[13], 0, 0, 0, src[8], src[10]
    asm volatile(
        "add %[s], %[s], #32 \n\t"
        "ldm %[s], {r2-r7} \n\t"
        "stm %[d], {r5-r7} \n\t"
        "mov r3, #0 \n\t"
        "mov r5, #0 \n\t"
        "mov r6, #0 \n\t"
        "stm %[d], {r3,r5,r6} \n\t"
        "stm %[d], {r2,r4} \n\t"
    : // out
        [d] "+l" (dst),
        [s] "+l" (src)
    : // in
    : // clobber list
        "r2", "r3", "r4", "r5", "r6", "r7", "memory"
    );
}

__attribute__((always_inline)) static void ecc_form_d2(uint32_t *dst, const uint32_t *src) {
    // src[12], src[13], src[14], src[15], 0, 0, src[9], src[11]
    asm volatile(
        "add %[s], %[s], #48 \n\t"
        "ldm %[s], {r2-r5} \n\t"
        "stm %[d], {r2-r5} \n\t"
        "sub %[s], %[s], #28 \n\t"
        "ldm %[s], {r4-r6} \n\t"
        "mov r2, #0 \n\t"
        "mov r3, #0 \n\t"
        "stm %[d], {r2-r4,r6} \n\t"
    : // out
        [d] "+l" (dst),
        [s] "+l" (src)
    : // in
    : // clobber list
        "r2", "r3", "r4", "r5", "r6", "memory"
    );
}

__attribute__((always_inline)) static void ecc_form_d3(uint32_t *dst, const uint32_t *src) {
    // src[13], src[14], src[15], src[8], src[9], src[10], 0, src[12]
    asm volatile(
        "add %[s], %[s], #52 \n\t"
        "ldm %[s], {r2-r4} \n\t"
        "stm %[d], {r2-r4} \n\t"
        "sub %[s], %[s], #32 \n\t"
        "ldm %[s], {r2-r6} \n\t"
        "mov r5, #0 \n\t"
        "stm %[d], {r2-r6} \n\t"
    : // out
        [d] "+l" (dst),
        [s] "+l" (src)
    : // in
    : // clobber list
        "r2", "r3", "r4", "r5", "r6", "memory"
    );
}

__attribute__((always_inline)) static void ecc_form_d4(uint32_t *dst, const uint32_t *src) {
    // src[14], src[15], 0, src[9], src[10], src[11], 0, src[13]
    asm volatile(
        "add %[s], %[s], #56 \n\t"
        "ldm %[s], {r2,r3} \n\t"
        "mov r4, #0 \n\t"
        "stm %[d], {r2-r4} \n\t"
        "sub %[s], %[s], #28 \n\t"
        "ldm %[s], {r2-r6} \n\t"
        "mov r5, #0 \n\t"
        "stm %[d], {r2-r6} \n\t"
    : // out
        [d] "+l" (dst),
        [s] "+l" (src)
    : // in
    : // clobber list
        "r2", "r3", "r4", "r5", "r6", "memory"
    );
}

/*---------------------------------------------------------------------------*/

int ecc_fieldAdd(const uint32_t *x, const uint32_t *y, const uint32_t *reducer, uint32_t *result){
    if(ecc_add(x, y, result, arrayLength)){ //add prime if carry is still set!
        uint32_t temp[8];
        ecc_add(result, reducer, temp, arrayLength);
        ecc_copy(result, temp);
    }
    return 0;
}

int ecc_fieldSub(const uint32_t *x, const uint32_t *y, const uint32_t *modulus, uint32_t *result){
    if(ecc_sub(x, y, result, arrayLength)){ //add modulus if carry is set
        uint32_t temp[8];
        ecc_add(result, modulus, temp, arrayLength);
        ecc_copy(result, temp);
    }
    return 0;
}

int ecc_fieldMult(const uint32_t *x, const uint32_t *y, uint32_t *result, const uint32_t length){
    uint32_t AB[length*2];
    uint32_t C[length*2];
    uint32_t carry;
    if(length==1){
        AB[0] = (x[0]&0x0000FFFF) * (y[0]&0x0000FFFF);
        AB[1] = (x[0]>>16) * (y[0]>>16);
        C[0] = (x[0]>>16) * (y[0]&0x0000FFFF);
        C[1] = (x[0]&0x0000FFFF) * (y[0]>>16);
        carry = ecc_add(&C[0], &C[1], C, 1);
        C[1] = carry << 16 | C[0] >> 16;
        C[0] = C[0] << 16;
        ecc_add(AB, C, result, 2);
    } else {
        ecc_fieldMult(&x[0], &y[0], &AB[0], length/2);
        ecc_fieldMult(&x[length/2], &y[length/2], &AB[length], length/2);
        ecc_fieldMult(&x[0], &y[length/2], &C[0], length/2);
        ecc_fieldMult(&x[length/2], &y[0], &C[length], length/2);
        carry = ecc_add(&C[0], &C[length], &C[0], length);
        ecc_setZero(&C[length], length);
        ecc_lshift(C, length*2, length/2);
        C[length+(length/2)] = carry;
        ecc_add(AB, C, result, length*2);
    }
    return 0;
}

//TODO: maximum:
//fffffffe00000002fffffffe0000000100000001fffffffe00000001fffffffe00000001fffffffefffffffffffffffffffffffe000000000000000000000001_16
void ecc_fieldModP(uint32_t *A, const uint32_t *B) {
    uint32_t tempm[8];
    uint32_t tempm2[8];

    ecc_copy(A, B);                             // A = T
    ecc_form_s1(tempm, B);                      // Form S1
    ecc_fieldAdd(A,tempm,ecc_prime_r,tempm2);   // tempm2 = T + S1
    ecc_fieldAdd(tempm2,tempm,ecc_prime_r,A);   // A = T + S1 + S1
    ecc_form_s2(tempm, B);                      // Form S2
    ecc_fieldAdd(A,tempm,ecc_prime_r,tempm2);   // tempm2 = T + S1 + S1 + S2
    ecc_fieldAdd(tempm2,tempm,ecc_prime_r,A);   // A = T + S1 + S1 + S2 + S2
    ecc_form_s3(tempm, B);                      // Form S3
    ecc_fieldAdd(A,tempm,ecc_prime_r,tempm2);   // tempm2 = T + S1 + S1 + S2 + S2 + S3
    ecc_form_s4(tempm, B);                      // Form S4
    ecc_fieldAdd(tempm2,tempm,ecc_prime_r,A);   // A = T + S1 + S1 + S2 + S2 + S3 + S4
    ecc_form_d1(tempm, B);                      // Form D1
    ecc_fieldSub(A,tempm,ecc_prime_m,tempm2);   // tempm2 = T + S1 + S1 + S2 + S2 + S3 + S4 - D1
    ecc_form_d2(tempm, B);                      // Form D2
    ecc_fieldSub(tempm2,tempm,ecc_prime_m,A);   // A = T + S1 + S1 + S2 + S2 + S3 + S4 - D1 - D2
    ecc_form_d3(tempm, B);                      // Form D3 
    ecc_fieldSub(A,tempm,ecc_prime_m,tempm2);   // tempm2 = T + S1 + S1 + S2 + S2 + S3 + S4 - D1 - D2 - D3
    ecc_form_d4(tempm, B);                      // Form D4
    ecc_fieldSub(tempm2,tempm,ecc_prime_m,A);   // A = T + S1 + S1 + S2 + S2 + S3 + S4 - D1 - D2 - D3 - D4

    if (ecc_compare(A, ecc_prime_m) >= 0) {
        ecc_fieldSub(A, ecc_prime_m, ecc_prime_m, tempm);
        ecc_copy(A, tempm);
    }
}

static int ecc_fieldAddAndDivide(const uint32_t *x, const uint32_t *modulus, const uint32_t *reducer, uint32_t* result){
    uint32_t n = ecc_add(x, modulus, result, arrayLength);
    ecc_rshift(result);
    if (n) { //add prime if carry is still set!
        result[7] |= 0x80000000;//add the carry
        if (ecc_compare(result, modulus) == 1) {
            uint32_t tempas[8];
            ecc_setZero(tempas, 8);
            ecc_add(result, reducer, tempas, 8);
            ecc_copy(result, tempas);
        }
        
    }
    return 0;
}

/*
 * Inverse A and output to B
 */
void ecc_fieldInv(const uint32_t *A, const uint32_t *modulus, const uint32_t *reducer, uint32_t *B){
    uint32_t u[8],v[8],x1[8];
    uint32_t tempm[8];
    ecc_setZero(tempm, 8);
    ecc_setZero(u, 8);
    ecc_setZero(v, 8);

    uint8_t t;
    ecc_copy(u, A); 
    ecc_copy(v, modulus); 
    ecc_setZero(x1, 8);
    ecc_setZero(B, 8);
    x1[0]=1; 
    /* While u !=1 and v !=1 */ 
    while ((ecc_isX(u, 1) || ecc_isX(v, 1))==0) {
        while(!(u[0]&1)) {                  /* While u is even */
            ecc_rshift(u);                      /* divide by 2 */
            if (!(x1[0]&1))                 /*ifx1iseven*/
                ecc_rshift(x1);                 /* Divide by 2 */
            else {
                ecc_fieldAddAndDivide(x1,modulus,reducer,tempm); /* tempm=(x1+p)/2 */
                ecc_copy(x1, tempm);         /* x1=tempm */
            }
        } 
        while(!(v[0]&1)) {                  /* While v is even */
            ecc_rshift(v);                      /* divide by 2 */ 
            if (!(B[0]&1))                  /*if x2 is even*/
                ecc_rshift(B);              /* Divide by 2 */
            else
            {
                ecc_fieldAddAndDivide(B,modulus,reducer,tempm); /* tempm=(x2+p)/2 */
                ecc_copy(B, tempm);          /* x2=tempm */ 
            }
            
        } 
        t=ecc_sub(u,v,tempm,arrayLength);               /* tempm=u-v */
        if (t==0) {                         /* If u > 0 */
            ecc_copy(u, tempm);                  /* u=u-v */
            ecc_fieldSub(x1,B,modulus,tempm);           /* tempm=x1-x2 */
            ecc_copy(x1, tempm);                 /* x1=x1-x2 */
        } else {
            ecc_sub(v,u,tempm,arrayLength);             /* tempm=v-u */
            ecc_copy(v, tempm);                  /* v=v-u */
            ecc_fieldSub(B,x1,modulus,tempm);           /* tempm=x2-x1 */
            ecc_copy(B, tempm);                  /* x2=x2-x1 */
        }
    } 
    if (ecc_isX(u, 1)) {
        ecc_copy(B, x1); 
    }
}


void ecc_ec_add(const uint32_t *px, const uint32_t *py, const uint32_t *qx, const uint32_t *qy, uint32_t *Sx, uint32_t *Sy){
    uint32_t tempC[8];
    uint32_t tempD[16];

    if(ecc_isX(px, 0) && ecc_isX(py, 0)){
        ecc_copy(Sx, qx);
        ecc_copy(Sy, qy);
        return;
    } else if(ecc_isX(qx, 0) && ecc_isX(qy, 0)) {
        ecc_copy(Sx, px);
        ecc_copy(Sy, py);
        return;
    }

    if(!ecc_compare(px, qx)){
        if(ecc_compare(py, qy)){
            ecc_setZero(Sx, 8);
            ecc_setZero(Sy, 8);
            return;
        } else {
            ecc_ec_double(px, py, Sx, Sy);
            return;
        }
    }

    ecc_fieldSub(py, qy, ecc_prime_m, Sx);
    ecc_fieldSub(px, qx, ecc_prime_m, Sy);
    ecc_fieldInv(Sy, ecc_prime_m, ecc_prime_r, Sy);
    ecc_fieldMult(Sx, Sy, tempD, arrayLength); 
    ecc_fieldModP(tempC, tempD); //tempC = lambda

    ecc_fieldMult(tempC, tempC, tempD, arrayLength); //Sx = lambda^2
    ecc_fieldModP(Sx, tempD);
    ecc_fieldSub(Sx, px, ecc_prime_m, Sy); //lambda^2 - Px
    ecc_fieldSub(Sy, qx, ecc_prime_m, Sx); //lambda^2 - Px - Qx

    ecc_fieldSub(qx, Sx, ecc_prime_m, Sy);
    ecc_fieldMult(tempC, Sy, tempD, arrayLength);
    ecc_fieldModP(tempC, tempD);
    ecc_fieldSub(tempC, qy, ecc_prime_m, Sy);
}

void ecc_ec_double(const uint32_t *px, const uint32_t *py, uint32_t *Dx, uint32_t *Dy){
    uint32_t tempB[8];
    uint32_t tempC[8];
    uint32_t tempD[16];

    if(ecc_isX(px, 0) && ecc_isX(py, 0)){
        ecc_copy(Dx, px);
        ecc_copy(Dy, py);
        return;
    }

    ecc_fieldMult(px, px, tempD, arrayLength);
    ecc_fieldModP(Dy, tempD);
    ecc_setZero(tempB, 8);
    tempB[0] = 0x00000001;
    ecc_fieldSub(Dy, tempB, ecc_prime_m, tempC); //tempC = (qx^2-1)
    tempB[0] = 0x00000003;
    ecc_fieldMult(tempC, tempB, tempD, arrayLength);
    ecc_fieldModP(Dy, tempD);//Dy = 3*(qx^2-1)
    ecc_fieldAdd(py, py, ecc_prime_r, tempB); //tempB = 2*qy
    ecc_fieldInv(tempB, ecc_prime_m, ecc_prime_r, tempC); //tempC = 1/(2*qy)
    ecc_fieldMult(Dy, tempC, tempD, arrayLength); //tempB = lambda = (3*(qx^2-1))/(2*qy)
    ecc_fieldModP(tempB, tempD);

    ecc_fieldMult(tempB, tempB, tempD, arrayLength); //tempC = lambda^2
    ecc_fieldModP(tempC, tempD);
    ecc_fieldSub(tempC, px, ecc_prime_m, Dy); //lambda^2 - Px
    ecc_fieldSub(Dy, px, ecc_prime_m, Dx); //lambda^2 - Px - Qx

    ecc_fieldSub(px, Dx, ecc_prime_m, Dy); //Dy = qx-dx
    ecc_fieldMult(tempB, Dy, tempD, arrayLength); //tempC = lambda * (qx-dx)
    ecc_fieldModP(tempC, tempD);
    ecc_fieldSub(tempC, py, ecc_prime_m, Dy); //Dy = lambda * (qx-dx) - px
}
