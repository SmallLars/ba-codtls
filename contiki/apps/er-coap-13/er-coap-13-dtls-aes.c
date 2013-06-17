#include "er-coap-13-dtls-aes.h"

#include "mc1322x.h"
#include "../../core/net/uip.h"
#include "er-coap-13-dtls-random.h"

#include <string.h>

/*---------------------------------------------------------------------------*/

#define DEBUG 0

#if DEBUG
  #include <stdio.h>
  #define PRINTF(...) printf(__VA_ARGS__)
#else
  #define PRINTF(...)
#endif

#define M 8 // Element von {4, 6, 8, 10, 12, 14, 16} -> Länge des Authentication Fields
#define L 7 // Element von {2, 3, 4, 5, 6, 7, 8} -> Länge des Längenfeldes
#define N (15-L) // Es Ergibt sich die Länge der Nonce

#define min(x,y) ((x)<(y)?(x):(y))

/*---------------------------------------------------------------------------*/

void aes_getData(uint8_t *dest, uint32_t *src, size_t len);
void aes_setData(uint32_t *dest, uint8_t *src, size_t len);
void aes_round();

void printBytes(uint8_t *b, size_t c) {
  int i;
  for (i = 0; i < 16; i++) {
    if (i > 0 && i % 4 == 0) printf(" ");
    printf("%02X", b[i]);
  }
}

/*---------------------------------------------------------------------------*/

// initialize aes module (ASM - advanced security module)
uint32_t aes_init() {
  PRINTF("\n *** AMS self-test ");

  /* ASM module is disabled until self-test passes */
  ASM->CONTROL1bits.ON = 1;
  ASM->CONTROL1bits.SELF_TEST = 1;
  ASM->CONTROL0bits.START = 1;

  /* Wait for self-test to pass */
  while (!ASM->STATUSbits.DONE) {
    #if DEBUG
    static uint32_t count = 0;
    if(!(count & 0xFF)) PRINTF(".");
    #endif
    continue;
  }

  if(!ASM->STATUSbits.TEST_PASS){
    // Test failed
    PRINTF(" TEST FAILED ***\n");
    return -1;
  }

  /* disable self test mode */
  ASM->CONTROL1bits.SELF_TEST = 0;

  /* activate normal mode */
  /* ASM starts in "BOOT" mode which uses an internal secret key
	 * to load encrypted data from an external source */
	/* must set to NORMAL mode */
  ASM->CONTROL1bits.NORMAL_MODE = 1;

  /* setting the bypass bit will disable the encryption */
	/* bypass defaults to off */
  ASM->CONTROL1bits.BYPASS = 0;

	ASM->CONTROL1bits.CTR = 1;
	ASM->CONTROL1bits.CBC = 1;

  ASM->CONTROL0bits.CLEAR = 1;

  PRINTF(" finished ***\n\n");

  return 0;
}

/*---------------------------------------------------------------------------*/

void getAuthCode(uint8_t *out, uint8_t *key, CCMData_t *data, size_t len) {
  uint8_t ab_0[16];

  aes_setData((uint32_t *) &(ASM->KEY0), key, 16);

  // b_0 generieren
  memset(ab_0, 0, 16);
  // Flags
  ab_0[0] = (8 * ((M-2)/2)) + (L - 1);
  // Nonce
  memcpy(ab_0 + 1, data->nonce_explicit, N);
  // Länge der Nachricht
  size_t new_len = UIP_HTONL(len);
  memcpy(ab_0 + 12, &new_len, 4);

  aes_setData((uint32_t *) &(ASM->DATA0), ab_0, 16);
  aes_round();
  size_t i;
  for (i = 0; i < len; i+=16) {
    aes_setData((uint32_t *) &(ASM->DATA0), data->ccm_ciphered + i, min(16, len - i));
    aes_round();
  }

  aes_getData(out, (uint32_t *) &(ASM->CBC0_RESULT), 8);

  // a_0 generieren, zu s_0 verschlüssel und mit CBC-MAC X-Oren
  memset(ab_0, 0, 16);
  aes_setData((uint32_t *) &(ASM->DATA0), ab_0, 16);
  ab_0[0] = (L - 1);
  memcpy(ab_0 + 1, data->nonce_explicit, N);
  aes_setData((uint32_t *) &(ASM->CTR0), ab_0, 16);
  aes_round();
  uint8_t s_0[N];
  aes_getData(s_0, (uint32_t *) &(ASM->CTR0_RESULT), N);
  for (i = 0; i < N; i++) out[i] = out[i] ^ s_0[i];
  // ENDE S_0

  ASM->CONTROL0bits.CLEAR = 1;
}

void crypt(uint8_t *key, CCMData_t *data, size_t len) {
  uint8_t counter[16];
  uint32_t length;

  aes_setData((uint32_t *) &(ASM->KEY0), key, 16);

  memset(counter, 0, 16);
  counter[0] = (L - 1);
  memcpy(counter + 1, data->nonce_explicit, N);

  size_t i;
  for (i = 0; i < len; i+=16) {
    length = UIP_HTONL((i/16)+1);
    memcpy(counter + 12, &length, 4);
    aes_setData((uint32_t *) &(ASM->CTR0), counter, 16);
    aes_setData((uint32_t *) &(ASM->DATA0), data->ccm_ciphered + i, min(16, len - i));
    aes_round();
    aes_getData(data->ccm_ciphered + i, (uint32_t *) &(ASM->CTR0_RESULT), min(16, len - i));
  }

  ASM->CONTROL0bits.CLEAR = 1;
}

void aes_getData(uint8_t *dest, uint32_t *src, size_t len) {
  uint32_t data[4];
  data[0] = UIP_HTONL(src[0]);
  data[1] = UIP_HTONL(src[1]);
  data[2] = UIP_HTONL(src[2]);
  data[3] = UIP_HTONL(src[3]);
  memcpy(dest, data, len);
}

void aes_setData(uint32_t *dest, uint8_t *src, size_t len) {
  uint32_t data[4] = {0, 0, 0, 0};
  memcpy(data, src, len);
  dest[0] = UIP_HTONL(data[0]);
  dest[1] = UIP_HTONL(data[1]);
  dest[2] = UIP_HTONL(data[2]);
  dest[3] = UIP_HTONL(data[3]);
}

void aes_round() {
  ASM->CONTROL0bits.START = 1;
  while (ASM->STATUSbits.DONE == 0) {
    continue;
  }
}

/*---------------------------------------------------------------------------*/


/*---------------------------------------------------------------------------
// do the crypting rounds
uint8_t *aes_crypt ( uint8_t *data, size_t data_length, aes_info_t* aes ) {
  /* activate CTR mode on chip 
  ASM->CONTROL1bits.CTR = 1;

  aes_setkey(aes);
  aes_setctr(aes);

/*
  int k;
  printf("Key: ");
  for (k = 0; k < 16; k++){
    if(!(k%4)) printf(" ");
    printf( "%02x", ((unsigned char*)aes->key)[k]);
  } printf("\n"); 

  int i;
  int fullblocks = data_length/AES_BLKSIZE;
  char* localdata = data;
  for ( i = 0 ; i < fullblocks ; i++ ) {
    aes_setdata ( localdata );
    aes_round ( ) ;

    aes_getresult ( localdata );

    localdata += AES_BLKSIZE;
    aes_incctr(); // counter +1
  }

  /* check if non full blocks are left and encrypt them, too 
  int bytesleft = data_length%AES_BLKSIZE;
  if (bytesleft) {

    char temp[AES_BLKSIZE];
    memset(temp, 0, AES_BLKSIZE);
    memcpy(temp, localdata, bytesleft);

    aes_setdata ( temp );
    aes_round ( ) ;
    aes_getresult ( temp );
    memcpy(localdata, temp, bytesleft);
  }

  /* reset status
  ASM->CONTROL1bits.CTR = 0;
  return data;
}


/*---------------------------------------------------------------------------
uint8_t *aes_encrypt( uint8_t *data, size_t data_length, uint8_t aes_key[AES_BLKSIZE] ) {
  aes_info_t aes_info;

  memcpy(aes_info.key, aes_key, AES_BLKSIZE);

  aes_info.ctr[0] = random_32();
  aes_info.ctr[1] = random_32();
  aes_info.ctr[2] = 0x00000000;
  aes_info.ctr[3] = 0x00000000;

  if(!aes_crypt ( data, data_length, &aes_info)){
    //PRINTF("encrypt error\n");
    return NULL;
  }

  // write nonce to end of data
  memcpy(data+data_length, aes_info.ctr, NONCE_BYTE_COUNT);

  return data;
}


/*---------------------------------------------------------------------------
uint8_t *aes_decrypt( uint8_t *data, size_t data_length, uint8_t aes_key[AES_BLKSIZE] ) {
  aes_info_t aes_info;
  memcpy(aes_info.key, aes_key, AES_BLKSIZE);

  memcpy(aes_info.ctr, data+data_length, NONCE_BYTE_COUNT);
  aes_info.ctr[2] = 0x00000000;
  aes_info.ctr[3] = 0x00000000;

  return aes_crypt ( data, data_length, &aes_info);

}
*/
