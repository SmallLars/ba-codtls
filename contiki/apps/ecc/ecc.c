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

//field functions for big numbers
int ecc_fieldAdd(const uint32_t *x, const uint32_t *y, const uint32_t *reducer, uint32_t *result);
int ecc_fieldSub(const uint32_t *x, const uint32_t *y, const uint32_t *modulus, uint32_t *result);
int ecc_fieldMult(const uint32_t *x, const uint32_t *y, uint32_t *result, uint8_t length);
void ecc_fieldModP(uint32_t *A, const uint32_t *B);
void ecc_fieldModO(const uint32_t *A, uint32_t *result, uint8_t length);
void ecc_fieldInv(const uint32_t *A, const uint32_t *modulus, const uint32_t *reducer, uint32_t *B);

//ec Functions
void ecc_ec_add(const uint32_t *px, const uint32_t *py, const uint32_t *qx, const uint32_t *qy, uint32_t *Sx, uint32_t *Sy);
void ecc_ec_double(const uint32_t *px, const uint32_t *py, uint32_t *Dx, uint32_t *Dy);

//simple functions to work with the big numbers
// #define ecc_setZero(target, length) memset(target, 0, 4 * length)
static void ecc_setZero(uint32_t *A, const int length);
static void ecc_copy(const uint32_t *from, uint32_t *to);
__attribute__((always_inline)) static uint8_t ecc_isSame(const uint32_t *A, const uint32_t *B);
__attribute__((always_inline)) static int ecc_isOne(const uint32_t* A);
__attribute__((always_inline)) static int ecc_isZero(const uint32_t* A);

//optimierung
__attribute__((always_inline)) static void ecc_form_s1(uint32_t *dst, const uint32_t *src);
__attribute__((always_inline)) static void ecc_form_s2(uint32_t *dst, const uint32_t *src);
__attribute__((always_inline)) static void ecc_form_s3(uint32_t *dst, const uint32_t *src);
__attribute__((always_inline)) static void ecc_form_s4(uint32_t *dst, const uint32_t *src);
__attribute__((always_inline)) static void ecc_form_d1(uint32_t *dst, const uint32_t *src);
__attribute__((always_inline)) static void ecc_form_d2(uint32_t *dst, const uint32_t *src);
__attribute__((always_inline)) static void ecc_form_d3(uint32_t *dst, const uint32_t *src);
__attribute__((always_inline)) static void ecc_form_d4(uint32_t *dst, const uint32_t *src);

//finite field functions FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
const uint32_t ecc_prime_m[8] = {0xffffffff, 0xffffffff, 0xffffffff, 0x00000000, 0x00000000, 0x00000000, 0x00000001, 0xffffffff};

/* This is added after an static byte addition if the answer has a carry in MSB*/
const uint32_t ecc_prime_r[8] = {0x00000001, 0x00000000, 0x00000000, 0xffffffff, 0xffffffff, 0xffffffff, 0xfffffffe, 0x00000000};

// ----------------------------------------------------------------------------

static void ecc_setZero(uint32_t *A, const int length) {
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
    : /* out */
    : /* in */
        [a] "r" (A),
        [l] "r" (length)
    : /* clobber list */
        "r2", "r3", "memory"
    );
}

/*
 * copy one array to another
 */
static void ecc_copy(const uint32_t *from, uint32_t *to) {
    asm volatile(
        "ldm %[s], {r2-r5} \n\t"
        "stm %[d], {r2-r5} \n\t"
        "ldm %[s], {r2-r5} \n\t"
        "stm %[d], {r2-r5} \n\t"
    : /* out */
        [s] "+r" (from),
        [d] "+r" (to)
    : /* in */
    : /* clobber list */
        "r2", "r3", "r4", "r5", "memory"
    );
}

__attribute__((always_inline)) static uint8_t ecc_isSame(const uint32_t *A, const uint32_t *B) {
    int i;

    for(i = 0; i < 8; i++){
        if (A[i] != B[i])
            return 0;
    }

    return 1;

/*
    uint8_t result;
    
    asm volatile(
            "ldm %[a], {r3,r4} \n\t"
            "ldm %[b], {r5,r6} \n\t"
            "cmp r3, r5 \n\t"
            "bne .falseSame \n\t"
            "cmp r4, r6 \n\t"
            "bne .falseSame \n\t"
            "ldm %[a], {r3,r4} \n\t"
            "ldm %[b], {r5,r6} \n\t"
            "cmp r3, r5 \n\t"
            "bne .falseSame \n\t"
            "cmp r4, r6 \n\t"
            "bne .falseSame \n\t"
            "ldm %[a], {r3,r4} \n\t"
            "ldm %[b], {r5,r6} \n\t"
            "cmp r3, r5 \n\t"
            "bne .falseSame \n\t"
            "cmp r4, r6 \n\t"
            "bne .falseSame \n\t"
            "ldm %[a], {r3,r4} \n\t"
            "ldm %[b], {r5,r6} \n\t"
            "cmp r3, r5 \n\t"
            "bne .falseSame \n\t"
            "cmp r4, r6 \n\t"
            "bne .falseSame \n\t"
            "mov %[r], #1 \n\t"
            "b .endSame \n\t"
        ".falseSame: \n\t"
            "mov %[r], #0 \n\t"
        ".endSame: \n\t"
    : /* out *
        [a] "+r" (A),
        [b] "+r" (B),
        [r] "=r" (result)
    : /* in *
    : /* clobber list *
        "r3", "r4", "r5", "r6", "memory"
    );

    return result;
*/
}

__attribute__((always_inline)) static int ecc_isOne(const uint32_t* A) {
    if (A[0] != 1) return 0;

    uint8_t n; 
    for (n = 1; n < 8; n++) 
        if (A[n] != 0) 
            return 0;

    return 1;

/*
    uint8_t result;

    asm volatile(
            "ldm %[a], {r2-r5} \n\t"
            "cmp r2, #1 \n\t"
            "bne .falseOne \n\t"
            "cmp r3, #0 \n\t"
            "bne .falseOne \n\t"
            "cmp r4, #0 \n\t"
            "bne .falseOne \n\t"
            "cmp r5, #0 \n\t"
            "bne .falseOne \n\t"
            "ldm %[a], {r2-r5} \n\t"
            "cmp r2, #0 \n\t"
            "bne .falseOne \n\t"
            "cmp r3, #0 \n\t"
            "bne .falseOne \n\t"
            "cmp r4, #0 \n\t"
            "bne .falseOne \n\t"
            "cmp r5, #0 \n\t"
            "bne .falseOne \n\t"
            "mov %[r], #1 \n\t"
            "bne .endOne \n\t"
        ".falseOne: \n\t"
            "mov %[r], #0 \n\t"
        ".endOne: \n\t"
    : /* out *
        [a] "+r" (A),
        [r] "=r" (result)
    : /* in *
    : /* clobber list *
        "r2", "r3", "r4", "r5", "memory"
    );

    return result;
*/
}

__attribute__((always_inline)) static int ecc_isZero(const uint32_t* A) {
    uint8_t n; 
    for (n = 0; n < 8; n++) 
        if (A[n] != 0) 
            return 0;

    return 1;
}

// ----------------------------------------------------------------------------

//is A greater than B?
int ecc_isGreater(const uint32_t *A, const uint32_t *B, uint8_t length) {
    if (length != 8) printf("GRRRR greater: %u\n", length);

    int i;
    for (i = length-1; i >= 0; --i)
    {
        if(A[i] > B[i])
            return 1;
        if(A[i] < B[i])
            return -1;
    }
    return 0;
}

// ----------------------------------------------------------------------------

#define SETARRAY(dst,a,b,c,d,e,f,g,h) dst[0]=a;dst[1]=b;dst[2]=c;dst[3]=d;dst[4]=e;dst[5]=f;dst[6]=g;dst[7]=h

__attribute__((always_inline)) static void ecc_form_s1(uint32_t *dst, const uint32_t *src) {
    SETARRAY(dst, 0, 0, 0, src[11], src[12], src[13], src[14], src[15]);
}

__attribute__((always_inline)) static void ecc_form_s2(uint32_t *dst, const uint32_t *src) {
    SETARRAY(dst, 0, 0, 0, src[12], src[13], src[14], src[15], 0);
}

__attribute__((always_inline)) static void ecc_form_s3(uint32_t *dst, const uint32_t *src) {
    SETARRAY(dst, src[8], src[9], src[10], 0, 0, 0, src[14], src[15]);
}

__attribute__((always_inline)) static void ecc_form_s4(uint32_t *dst, const uint32_t *src) {
    SETARRAY(dst, src[9], src[10], src[11], src[13], src[14], src[15], src[13], src[8]);
}

__attribute__((always_inline)) static void ecc_form_d1(uint32_t *dst, const uint32_t *src) {
    SETARRAY(dst, src[11], src[12], src[13], 0, 0, 0, src[8], src[10]);
}

__attribute__((always_inline)) static void ecc_form_d2(uint32_t *dst, const uint32_t *src) {
    SETARRAY(dst, src[12], src[13], src[14], src[15], 0, 0, src[9], src[11]);
}

__attribute__((always_inline)) static void ecc_form_d3(uint32_t *dst, const uint32_t *src) {
    SETARRAY(dst, src[13], src[14], src[15], src[8], src[9], src[10], 0, src[12]);
}

__attribute__((always_inline)) static void ecc_form_d4(uint32_t *dst, const uint32_t *src) {
    SETARRAY(dst, src[14], src[15], 0, src[9], src[10], src[11], 0, src[13]);
}

// ----------------------------------------------------------------------------

int ecc_fieldAdd(const uint32_t *x, const uint32_t *y, const uint32_t *reducer, uint32_t *result){
    if(ecc_add(x, y, result, arrayLength)){ //add prime if carry is still set!
        uint32_t temp[8];
        ecc_add(result, reducer, temp, arrayLength);
        ecc_copy(temp, result);
    }
    return 0;
}

int ecc_fieldSub(const uint32_t *x, const uint32_t *y, const uint32_t *modulus, uint32_t *result){
    if(ecc_sub(x, y, result, arrayLength)){ //add modulus if carry is set
        uint32_t temp[8];
        ecc_add(result, modulus, temp, arrayLength);
        ecc_copy(temp, result);
    }
    return 0;
}

void ecc_lshift(uint32_t *x, int length, int shiftSize){
    uint32_t temp[shiftSize];
    uint32_t oldTemp[shiftSize];
    ecc_setZero(&oldTemp[0], shiftSize);
    int i;
    for(i = 0; i<length; ++i){
        temp[i%shiftSize] = x[i];
        x[i] = oldTemp[i%shiftSize];
        oldTemp[i%shiftSize] = temp[i%shiftSize];
    }
}

int ecc_fieldMult(const uint32_t *x, const uint32_t *y, uint32_t *result, uint8_t length){
    uint32_t AB[length*2];
    uint32_t C[length*2];
    uint8_t carry;
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
        C[length] = carry;
        ecc_lshift(C, length*2, length/2);
        ecc_add(AB, C, result, length*2);
    }
    return 0;
}

//TODO: maximum:
//fffffffe00000002fffffffe0000000100000001fffffffe00000001fffffffe00000001fffffffefffffffffffffffffffffffe000000000000000000000001_16
void ecc_fieldModP(uint32_t *A, const uint32_t *B) {
    uint32_t tempm[8];
    uint32_t tempm2[8];
    /* A = T */ 
    ecc_copy(B,A);
    /* Form S1 */
    ecc_form_s1(tempm, B);
    /* tempm2=T+S1 */ 
    ecc_fieldAdd(A,tempm,ecc_prime_r,tempm2);
    /* A=T+S1+S1 */ 
    ecc_fieldAdd(tempm2,tempm,ecc_prime_r,A);
    /* Form S2 */
    ecc_form_s2(tempm, B);
    /* tempm2=T+S1+S1+S2 */ 
    ecc_fieldAdd(A,tempm,ecc_prime_r,tempm2);
    /* A=T+S1+S1+S2+S2 */ 
    ecc_fieldAdd(tempm2,tempm,ecc_prime_r,A);
    /* Form S3 */
    ecc_form_s3(tempm, B);
    /* tempm2=T+S1+S1+S2+S2+S3 */ 
    ecc_fieldAdd(A,tempm,ecc_prime_r,tempm2);
    /* Form S4 */
    ecc_form_s4(tempm, B);
    /* A=T+S1+S1+S2+S2+S3+S4 */ 
    ecc_fieldAdd(tempm2,tempm,ecc_prime_r,A);
    /* Form D1 */
    ecc_form_d1(tempm, B);
    /* tempm2=T+S1+S1+S2+S2+S3+S4-D1 */ 
    ecc_fieldSub(A,tempm,ecc_prime_m,tempm2);
    /* Form D2 */
    ecc_form_d2(tempm, B);
    /* A=T+S1+S1+S2+S2+S3+S4-D1-D2 */ 
    ecc_fieldSub(tempm2,tempm,ecc_prime_m,A);
    /* Form D3 */
    ecc_form_d3(tempm, B);
    /* tempm2=T+S1+S1+S2+S2+S3+S4-D1-D2-D3 */ 
    ecc_fieldSub(A,tempm,ecc_prime_m,tempm2);
    /* Form D4 */
    ecc_form_d4(tempm, B);
    /* A=T+S1+S1+S2+S2+S3+S4-D1-D2-D3-D4 */ 
    ecc_fieldSub(tempm2,tempm,ecc_prime_m,A);
    if(ecc_isGreater(A, ecc_prime_m, arrayLength) >= 0){
        ecc_fieldSub(A, ecc_prime_m, ecc_prime_m, tempm);
        ecc_copy(tempm, A);
    }
}

static int ecc_fieldAddAndDivide(const uint32_t *x, const uint32_t *modulus, const uint32_t *reducer, uint32_t* result){
    uint32_t n = ecc_add(x, modulus, result, arrayLength);
    ecc_rshift(result);
    if(n){ //add prime if carry is still set!
        result[7] |= 0x80000000;//add the carry
        if (ecc_isGreater(result, modulus, arrayLength) == 1)
        {
            uint32_t tempas[8];
            ecc_setZero(tempas, 8);
            ecc_add(result, reducer, tempas, 8);
            ecc_copy(tempas, result);
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
    ecc_copy(A,u); 
    ecc_copy(modulus,v); 
    ecc_setZero(x1, 8);
    ecc_setZero(B, 8);
    x1[0]=1; 
    /* While u !=1 and v !=1 */ 
    while ((ecc_isOne(u) || ecc_isOne(v))==0) {
        while(!(u[0]&1)) {                  /* While u is even */
            ecc_rshift(u);                      /* divide by 2 */
            if (!(x1[0]&1))                 /*ifx1iseven*/
                ecc_rshift(x1);                 /* Divide by 2 */
            else {
                ecc_fieldAddAndDivide(x1,modulus,reducer,tempm); /* tempm=(x1+p)/2 */
                ecc_copy(tempm,x1);         /* x1=tempm */
            }
        } 
        while(!(v[0]&1)) {                  /* While v is even */
            ecc_rshift(v);                      /* divide by 2 */ 
            if (!(B[0]&1))                  /*if x2 is even*/
                ecc_rshift(B);              /* Divide by 2 */
            else
            {
                ecc_fieldAddAndDivide(B,modulus,reducer,tempm); /* tempm=(x2+p)/2 */
                ecc_copy(tempm,B);          /* x2=tempm */ 
            }
            
        } 
        t=ecc_sub(u,v,tempm,arrayLength);               /* tempm=u-v */
        if (t==0) {                         /* If u > 0 */
            ecc_copy(tempm,u);                  /* u=u-v */
            ecc_fieldSub(x1,B,modulus,tempm);           /* tempm=x1-x2 */
            ecc_copy(tempm,x1);                 /* x1=x1-x2 */
        } else {
            ecc_sub(v,u,tempm,arrayLength);             /* tempm=v-u */
            ecc_copy(tempm,v);                  /* v=v-u */
            ecc_fieldSub(B,x1,modulus,tempm);           /* tempm=x2-x1 */
            ecc_copy(tempm,B);                  /* x2=x2-x1 */
        }
    } 
    if (ecc_isOne(u)) {
        ecc_copy(x1,B); 
    }
}


void ecc_ec_add(const uint32_t *px, const uint32_t *py, const uint32_t *qx, const uint32_t *qy, uint32_t *Sx, uint32_t *Sy){
    uint32_t tempC[8];
    uint32_t tempD[16];

    if(ecc_isZero(px) && ecc_isZero(py)){
        ecc_copy(qx, Sx);
        ecc_copy(qy, Sy);
        return;
    } else if(ecc_isZero(qx) && ecc_isZero(qy)) {
        ecc_copy(px, Sx);
        ecc_copy(py, Sy);
        return;
    }

    if(ecc_isSame(px, qx)){
        if(!ecc_isSame(py, qy)){
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

    if(ecc_isZero(px) && ecc_isZero(py)){
        ecc_copy(px, Dx);
        ecc_copy(py, Dy);
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

void ecc_ec_mult(const uint32_t *px, const uint32_t *py, const uint32_t *secret, uint32_t *resultx, uint32_t *resulty){
    uint32_t Qx[8];
    uint32_t Qy[8];
    ecc_setZero(Qx, 8);
    ecc_setZero(Qy, 8);

    int i;
    for (i = 256;i--;){
        ecc_ec_double(Qx, Qy, resultx, resulty);
        ecc_copy(resultx, Qx);
        ecc_copy(resulty, Qy);
        if ((((secret[i/32])>>(i%32)) & 0x01) == 1){ //<- TODO quark, muss anders gemacht werden
            ecc_ec_add(Qx, Qy, px, py, resultx, resulty); //eccAdd
            ecc_copy(resultx, Qx);
            ecc_copy(resulty, Qy);
        }
    }
    ecc_copy(Qx, resultx);
    ecc_copy(Qy, resulty);
}
