#include "aes-mc1322x.h"

#include "mc1322x.h"
#include "random-mc1322x.h"
#include "tools.h"

#include <stdio.h>
#include <string.h>

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

  PRINTF(" finished ***\n");

  return 0;
}

/*---------------------------------------------------------------------------*/
// set aes keys
void aes_setkey( aes_info_t *aes ) {
  // set the keys, copy them into the ASM registers
  ASM->KEY0 = aes->key[0];
  ASM->KEY1 = aes->key[1];
  ASM->KEY2 = aes->key[2];
  ASM->KEY3 = aes->key[3];
}

/*---------------------------------------------------------------------------*/
// set counter registers
void es_setctr( aes_info_t* aes ) {
  ASM->CTR0 = aes->ctr[0];
  ASM->CTR1 = aes->ctr[1];
  ASM->CTR2 = aes->ctr[2];
  ASM->CTR3 = aes->ctr[3];
}

/*---------------------------------------------------------------------------*/
// increase counter registers
void aes_incctr() {
  ASM->CTR3++;
  if (!ASM->CTR3) {
    ASM->CTR2++;
  }
}

/*---------------------------------------------------------------------------*/
// set data registers
void aes_setdata( uint8_t *data ) {
  memcpy((void*) &(ASM->DATA0), data , AES_BLKSIZE);

/*
  ASM->DATA0 = *((uint32_t *)data+0);
  ASM->DATA1 = *((uint32_t *)data+1);
  ASM->DATA2 = *((uint32_t *)data+2);
  ASM->DATA3 = *((uint32_t *)data+3);
*/
}

/*---------------------------------------------------------------------------*/
// read result from registers
void aes_getresult( uint8_t *result ) {
  memcpy( result, (void*)&(ASM->CTR0_RESULT), AES_BLKSIZE);

/*
  result[0] = ASM->CTR0_RESULT;
  result[1] = ASM->CTR1_RESULT;
  result[2] = ASM->CTR2_RESULT;
  result[3] = ASM->CTR3_RESULT;
  */
}

/*---------------------------------------------------------------------------*/
// actually do the AES encryption on the filled registers
void aes_round() {
  /* set control bit to start encryption and wait until it finishes */
  ASM->CONTROL0bits.START = 1;
  while(ASM->STATUSbits.DONE == 0) {
    continue;
  }
}


/*---------------------------------------------------------------------------*/
// do the crypting rounds
uint8_t *aes_crypt ( uint8_t *data, size_t data_length, aes_info_t* aes ) {
  /* activate CTR mode on chip */
  ASM->CONTROL1bits.CTR = 1;

  aes_setkey(aes);
  aes_setctr(aes);

/*
  int k;
  printf("Key: ");
  for (k = 0; k < 16; k++){
    if(!(k%4)) printf(" ");
    printf( "%02x", ((unsigned char*)aes->key)[k]);
  } printf("\n"); */

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

  /* check if non full blocks are left and encrypt them, too */
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

  /* reset status */
  ASM->CONTROL1bits.CTR = 0;
  return data;
}


/*---------------------------------------------------------------------------*/
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


/*---------------------------------------------------------------------------*/
uint8_t *aes_decrypt( uint8_t *data, size_t data_length, uint8_t aes_key[AES_BLKSIZE] ) {
  aes_info_t aes_info;
  memcpy(aes_info.key, aes_key, AES_BLKSIZE);

  memcpy(aes_info.ctr, data+data_length, NONCE_BYTE_COUNT);
  aes_info.ctr[2] = 0x00000000;
  aes_info.ctr[3] = 0x00000000;

  return aes_crypt ( data, data_length, &aes_info);

}

/*---------------------------------------------------------------------------*/
size_t aes_headerlen( void ) {
  return NONCE_BYTE_COUNT;
}
