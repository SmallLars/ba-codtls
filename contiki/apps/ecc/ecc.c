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

//simple Functions for addition and substraction of big numbers
uint32_t ecc_add( const uint32_t *x, const uint32_t *y, uint32_t *result, uint8_t length);
uint32_t ecc_sub( const uint32_t *x, const uint32_t *y, uint32_t *result, uint8_t length);

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
void ecc_setZero(uint32_t *A, const int length);
int ecc_isOne(const uint32_t* A);
void ecc_rshift(uint32_t* A);
int ecc_isGreater(const uint32_t *A, const uint32_t *B, uint8_t length);
void ecc_copy(const uint32_t *from, uint32_t *to, uint8_t length);


uint32_t ecc_add( const uint32_t *x, const uint32_t *y, uint32_t *result, uint8_t length){
	uint64_t d = 0; //carry
	int v = 0;
	for(v = 0;v<length;v++){
		//printf("%02x + %02x + %01x = ", x[v], y[v], d);
		d += (uint64_t) x[v] + (uint64_t) y[v];
		//printf("%02x\n", d);
		result[v] = d;
		d = d>>32; //save carry
	}
	
	return (uint32_t)d;
}

uint32_t ecc_sub( const uint32_t *x, const uint32_t *y, uint32_t *result, uint8_t length){
	uint64_t d = 0;
	int v;
	for(v = 0;v < length; v++){
		d = (uint64_t) x[v] - (uint64_t) y[v] - d;
		result[v] = d & 0xFFFFFFFF;
		d = d>>32;
		d &= 0x1;
	}	
	return (uint32_t)d;
}

//finite field functions
//FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
static const uint32_t ecc_prime_m[8] = {0xffffffff, 0xffffffff, 0xffffffff, 0x00000000,
					0x00000000, 0x00000000, 0x00000001, 0xffffffff};

							
/* This is added after an static byte addition if the answer has a carry in MSB*/
static const uint32_t ecc_prime_r[8] = {0x00000001, 0x00000000, 0x00000000, 0xffffffff,
					0xffffffff, 0xffffffff, 0xfffffffe, 0x00000000};

// ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
static const uint32_t ecc_order_m[9] = {0xFC632551, 0xF3B9CAC2, 0xA7179E84, 0xBCE6FAAD,
					0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, 0xFFFFFFFF,
					0x00000000};

static const uint32_t ecc_order_r[8] = {0x039CDAAF, 0x0C46353D, 0x58E8617B, 0x43190552,
					0x00000000, 0x00000000, 0xFFFFFFFF, 0x00000000};

static const uint32_t ecc_order_mu[9] = {0xEEDF9BFE, 0x012FFD85, 0xDF1A6C21, 0x43190552,
					 0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFFFF, 0x00000000,
					 0x00000001};

static const uint8_t ecc_order_k = 8;

const uint32_t ecc_g_point_x[8] = { 0xD898C296, 0xF4A13945, 0x2DEB33A0, 0x77037D81,
				    0x63A440F2, 0xF8BCE6E5, 0xE12C4247, 0x6B17D1F2};
const uint32_t ecc_g_point_y[8] = { 0x37BF51F5, 0xCBB64068, 0x6B315ECE, 0x2BCE3357,
				    0x7C0F9E16, 0x8EE7EB4A, 0xFE1A7F9B, 0x4FE342E2};


void ecc_setZero(uint32_t *A, const int length){
	int i;

	for (i = 0; i < length; ++i)
	{
		A[i] = 0;
	}
}

/*
 * copy one array to another
 */
static void copy(const uint32_t *from, uint32_t *to, uint8_t length){
	int i;
	for (i = 0; i < length; ++i)
	{
		to[i] = from[i];
	}
}

int ecc_isSame(const uint32_t *A, const uint32_t *B, uint8_t length){
	int i;

	for(i = 0; i < length; i++){
		if (A[i] != B[i])
			return 0;
	}
	return 1;
}

//is A greater than B?
static int isGreater(const uint32_t *A, const uint32_t *B, uint8_t length){
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


int ecc_fieldAdd(const uint32_t *x, const uint32_t *y, const uint32_t *reducer, uint32_t *result){
	if(ecc_add(x, y, result, arrayLength)){ //add prime if carry is still set!
		uint32_t tempas[8];
		ecc_setZero(tempas, 8);
		ecc_add(result, reducer, tempas, arrayLength);
		copy(tempas, result, arrayLength);
	}
	return 0;
}

int ecc_fieldSub(const uint32_t *x, const uint32_t *y, const uint32_t *modulus, uint32_t *result){
	if(ecc_sub(x, y, result, arrayLength)){ //add modulus if carry is set
		uint32_t tempas[8];
		ecc_setZero(tempas, 8);
		ecc_add(result, modulus, tempas, arrayLength);
		copy(tempas, result, arrayLength);
	}
	return 0;
}

//finite Field multiplication
//32bit * 32bit = 64bit
int ecc_fieldMult(const uint32_t *x, const uint32_t *y, uint32_t *result, uint8_t length){
	uint32_t temp[length * 2];
	ecc_setZero(temp, length * 2);
	ecc_setZero(result, length * 2);
	uint8_t k, n;
	uint64_t l;
	for (k = 0; k < length; k++){
		for (n = 0; n < length; n++){ 
			l = (uint64_t)x[n]*(uint64_t)y[k];
			temp[n+k] = l&0xFFFFFFFF;
			temp[n+k+1] = l>>32;
			ecc_add(&temp[n+k], &result[n+k], &result[n+k], (length * 2) - (n + k));

			ecc_setZero(temp, length * 2);
		}
	}
	return 0;
}

//TODO: maximum:
//fffffffe00000002fffffffe0000000100000001fffffffe00000001fffffffe00000001fffffffefffffffffffffffffffffffe000000000000000000000001_16
void ecc_fieldModP(uint32_t *A, const uint32_t *B)
{
	uint32_t tempm[8];
	uint32_t tempm2[8];
	uint8_t n;
	ecc_setZero(tempm, 8);
	ecc_setZero(tempm2, 8);
	/* A = T */ 
	copy(B,A,arrayLength);

	/* Form S1 */ 
	for(n=0;n<3;n++) tempm[n]=0; 
	for(n=3;n<8;n++) tempm[n]=B[n+8];

	/* tempm2=T+S1 */ 
	ecc_fieldAdd(A,tempm,ecc_prime_r,tempm2);
	/* A=T+S1+S1 */ 
	ecc_fieldAdd(tempm2,tempm,ecc_prime_r,A);
	/* Form S2 */ 
	for(n=0;n<3;n++) tempm[n]=0; 
	for(n=3;n<7;n++) tempm[n]=B[n+9]; 
	for(n=7;n<8;n++) tempm[n]=0;
	/* tempm2=T+S1+S1+S2 */ 
	ecc_fieldAdd(A,tempm,ecc_prime_r,tempm2);
	/* A=T+S1+S1+S2+S2 */ 
	ecc_fieldAdd(tempm2,tempm,ecc_prime_r,A);
	/* Form S3 */ 
	for(n=0;n<3;n++) tempm[n]=B[n+8]; 
	for(n=3;n<6;n++) tempm[n]=0; 
	for(n=6;n<8;n++) tempm[n]=B[n+8];
	/* tempm2=T+S1+S1+S2+S2+S3 */ 
	ecc_fieldAdd(A,tempm,ecc_prime_r,tempm2);
	/* Form S4 */ 
	for(n=0;n<3;n++) tempm[n]=B[n+9]; 
	for(n=3;n<6;n++) tempm[n]=B[n+10]; 
	for(n=6;n<7;n++) tempm[n]=B[n+7]; 
	for(n=7;n<8;n++) tempm[n]=B[n+1];
	/* A=T+S1+S1+S2+S2+S3+S4 */ 
	ecc_fieldAdd(tempm2,tempm,ecc_prime_r,A);
	/* Form D1 */ 
	for(n=0;n<3;n++) tempm[n]=B[n+11]; 
	for(n=3;n<6;n++) tempm[n]=0; 
	for(n=6;n<7;n++) tempm[n]=B[n+2]; 
	for(n=7;n<8;n++) tempm[n]=B[n+3];
	/* tempm2=T+S1+S1+S2+S2+S3+S4-D1 */ 
	ecc_fieldSub(A,tempm,ecc_prime_m,tempm2);
	/* Form D2 */ 
	for(n=0;n<4;n++) tempm[n]=B[n+12]; 
	for(n=4;n<6;n++) tempm[n]=0; 
	for(n=6;n<7;n++) tempm[n]=B[n+3]; 
	for(n=7;n<8;n++) tempm[n]=B[n+4];
	/* A=T+S1+S1+S2+S2+S3+S4-D1-D2 */ 
	ecc_fieldSub(tempm2,tempm,ecc_prime_m,A);
	/* Form D3 */ 
	for(n=0;n<3;n++) tempm[n]=B[n+13]; 
	for(n=3;n<6;n++) tempm[n]=B[n+5]; 
	for(n=6;n<7;n++) tempm[n]=0; 
	for(n=7;n<8;n++) tempm[n]=B[n+5];
	/* tempm2=T+S1+S1+S2+S2+S3+S4-D1-D2-D3 */ 
	ecc_fieldSub(A,tempm,ecc_prime_m,tempm2);
	/* Form D4 */ 
	for(n=0;n<2;n++) tempm[n]=B[n+14]; 
	for(n=2;n<3;n++) tempm[n]=0; 
	for(n=3;n<6;n++) tempm[n]=B[n+6]; 
	for(n=6;n<7;n++) tempm[n]=0; 
	for(n=7;n<8;n++) tempm[n]=B[n+6];
	/* A=T+S1+S1+S2+S2+S3+S4-D1-D2-D3-D4 */ 
	ecc_fieldSub(tempm2,tempm,ecc_prime_m,A);
	if(isGreater(A, ecc_prime_m, arrayLength) >= 0){
		ecc_fieldSub(A, ecc_prime_m, ecc_prime_m, tempm);
		copy(tempm, A, arrayLength);
	}
}

int ecc_isOne(const uint32_t* A){
	uint8_t n; 
	for(n=1;n<8;n++) 
		if (A[n]!=0) 
			break;

	if ((n==8)&&(A[0]==1)) 
		return 1;
	else 
		return 0;
}

static int ecc_isZero(const uint32_t* A){
	uint8_t n, r=0;
	for(n=0;n<8;n++){
		if (A[n] == 0) r++;
	}
	return r==8;
}

void ecc_rshift(uint32_t* A){
	int n, i, nOld=0;
	for (i = 8; i--;)
	{
		n = A[i]&0x1;
		A[i] = A[i]>>1 | nOld<<31;
		nOld = n;
	}
}

static int ecc_fieldAddAndDivide(const uint32_t *x, const uint32_t *modulus, const uint32_t *reducer, uint32_t* result){
	uint32_t n = ecc_add(x, modulus, result, arrayLength);
	ecc_rshift(result);
	if(n){ //add prime if carry is still set!
		result[7] |= 0x80000000;//add the carry
		if (isGreater(result, modulus, arrayLength) == 1)
		{
			uint32_t tempas[8];
			ecc_setZero(tempas, 8);
			ecc_add(result, reducer, tempas, 8);
			copy(tempas, result, arrayLength);
		}
		
	}
	return 0;
}

/*
 * Inverse A and output to B
 */
void ecc_fieldInv(const uint32_t *A, const uint32_t *modulus, const uint32_t *reducer, uint32_t *B){
	uint32_t u[8],v[8],x1[8],x2[8];
	uint32_t tempm[8];
	uint32_t tempm2[8];
	ecc_setZero(tempm, 8);
	ecc_setZero(tempm2, 8);
	ecc_setZero(u, 8);
	ecc_setZero(v, 8);

	uint8_t t;
	copy(A,u,arrayLength); 
	copy(modulus,v,arrayLength); 
	ecc_setZero(x1, 8);
	ecc_setZero(x2, 8);
	x1[0]=1; 
	/* While u !=1 and v !=1 */ 
	while ((ecc_isOne(u) || ecc_isOne(v))==0) {
		while(!(u[0]&1)) { 					/* While u is even */
			ecc_rshift(u); 						/* divide by 2 */
			if (!(x1[0]&1))					/*ifx1iseven*/
				ecc_rshift(x1);					/* Divide by 2 */
			else {
				ecc_fieldAddAndDivide(x1,modulus,reducer,tempm); /* tempm=x1+p */
				copy(tempm,x1,arrayLength); 		/* x1=tempm */
				//rshift(x1);					/* Divide by 2 */
			}
		} 
		while(!(v[0]&1)) {					/* While v is even */
			ecc_rshift(v); 						/* divide by 2 */ 
			if (!(x2[0]&1))					/*ifx1iseven*/
				ecc_rshift(x2); 				/* Divide by 2 */
			else
			{
				ecc_fieldAddAndDivide(x2,modulus,reducer,tempm);	/* tempm=x1+p */
				copy(tempm,x2,arrayLength); 			/* x1=tempm */ 
				//rshift(x2);					/* Divide by 2 */
			}
			
		} 
		t=ecc_sub(u,v,tempm,arrayLength); 				/* tempm=u-v */
		if (t==0) {							/* If u > 0 */
			copy(tempm,u,arrayLength); 					/* u=u-v */
			ecc_fieldSub(x1,x2,modulus,tempm); 			/* tempm=x1-x2 */
			copy(tempm,x1,arrayLength);					/* x1=x1-x2 */
		} else {
			ecc_sub(v,u,tempm,arrayLength); 			/* tempm=v-u */
			copy(tempm,v,arrayLength); 					/* v=v-u */
			ecc_fieldSub(x2,x1,modulus,tempm); 			/* tempm=x2-x1 */
			copy(tempm,x2,arrayLength);					/* x2=x2-x1 */
		}
	} 
	if (ecc_isOne(u)) {
		copy(x1,B,arrayLength); 
	} else {
		copy(x2,B,arrayLength);
	}
}


void ecc_ec_add(const uint32_t *px, const uint32_t *py, const uint32_t *qx, const uint32_t *qy, uint32_t *Sx, uint32_t *Sy){
	uint32_t tempA[8];
	uint32_t tempB[8];
	uint32_t tempC[8];
	uint32_t tempD[16];

	if(ecc_isZero(px) && ecc_isZero(py)){
		copy(qx, Sx,arrayLength);
		copy(qy, Sy,arrayLength);
		return;
	} else if(ecc_isZero(qx) && ecc_isZero(qy)) {
		copy(px, Sx,arrayLength);
		copy(py, Sy,arrayLength);
		return;
	}

	if(ecc_isSame(px, qx, arrayLength)){
		if(!ecc_isSame(py, qy, arrayLength)){
			ecc_setZero(Sx, 8);
			ecc_setZero(Sy, 8);
			return;
		} else {
			ecc_ec_double(px, py, Sx, Sy);
			return;
		}
	}

	ecc_fieldSub(py, qy, ecc_prime_m, tempA);
	ecc_fieldSub(px, qx, ecc_prime_m, tempB);
	ecc_fieldInv(tempB, ecc_prime_m, ecc_prime_r, tempB);
	ecc_fieldMult(tempA, tempB, tempD, arrayLength); 
	ecc_fieldModP(tempC, tempD); //tempC = lambda

	ecc_fieldMult(tempC, tempC, tempD, arrayLength); //tempA = lambda^2
	ecc_fieldModP(tempA, tempD);
	ecc_fieldSub(tempA, px, ecc_prime_m, tempB); //lambda^2 - Px
	ecc_fieldSub(tempB, qx, ecc_prime_m, Sx); //lambda^2 - Px - Qx

	ecc_fieldSub(qx, Sx, ecc_prime_m, tempB);
	ecc_fieldMult(tempC, tempB, tempD, arrayLength);
	ecc_fieldModP(tempC, tempD);
	ecc_fieldSub(tempC, qy, ecc_prime_m, Sy);
}

void ecc_ec_double(const uint32_t *px, const uint32_t *py, uint32_t *Dx, uint32_t *Dy){
	uint32_t tempA[8];
	uint32_t tempB[8];
	uint32_t tempC[8];
	uint32_t tempD[16];

	if(ecc_isZero(px) && ecc_isZero(py)){
		copy(px, Dx,arrayLength);
		copy(py, Dy,arrayLength);
		return;
	}

	ecc_fieldMult(px, px, tempD, arrayLength);
	ecc_fieldModP(tempA, tempD);
	ecc_setZero(tempB, 8);
	tempB[0] = 0x00000001;
	ecc_fieldSub(tempA, tempB, ecc_prime_m, tempC); //tempC = (qx^2-1)
	tempB[0] = 0x00000003;
	ecc_fieldMult(tempC, tempB, tempD, arrayLength);
	ecc_fieldModP(tempA, tempD);//tempA = 3*(qx^2-1)
	ecc_fieldAdd(py, py, ecc_prime_r, tempB); //tempB = 2*qy
	ecc_fieldInv(tempB, ecc_prime_m, ecc_prime_r, tempC); //tempC = 1/(2*qy)
	ecc_fieldMult(tempA, tempC, tempD, arrayLength); //tempB = lambda = (3*(qx^2-1))/(2*qy)
	ecc_fieldModP(tempB, tempD);

	ecc_fieldMult(tempB, tempB, tempD, arrayLength); //tempC = lambda^2
	ecc_fieldModP(tempC, tempD);
	ecc_fieldSub(tempC, px, ecc_prime_m, tempA); //lambda^2 - Px
	ecc_fieldSub(tempA, px, ecc_prime_m, Dx); //lambda^2 - Px - Qx

	ecc_fieldSub(px, Dx, ecc_prime_m, tempA); //tempA = qx-dx
	ecc_fieldMult(tempB, tempA, tempD, arrayLength); //tempC = lambda * (qx-dx)
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
		copy(resultx, Qx,arrayLength);
		copy(resulty, Qy,arrayLength);
		if ((((secret[i/32])>>(i%32)) & 0x01) == 1){ //<- TODO quark, muss anders gemacht werden
			ecc_ec_add(Qx, Qy, px, py, resultx, resulty); //eccAdd
			copy(resultx, Qx,arrayLength);
			copy(resulty, Qy,arrayLength);
		}
	}
	copy(Qx, resultx,arrayLength);
	copy(Qy, resulty,arrayLength);
}

int ecc_is_valid_key(const uint32_t * priv_key)
{
	return isGreater(ecc_order_m, priv_key, arrayLength) == 1;
}
