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
#define SETNONCE(a) memcpy(a, "ABCDEFGH", N)

#define min(x,y) ((x)<(y)?(x):(y))

/*---------------------------------------------------------------------------*/

void aes_round();

void printBytes(uint8_t *b, size_t c) {
  int i;
  for (i = 0; i < c; i++) {
    printf("%02X", b[i]);
  }
  printf("\n");
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

  ASM->CONTROL0bits.CLEAR = 1;

  PRINTF(" finished ***\n\n");

  return 0;
}

/*---------------------------------------------------------------------------*/

void aes_setkey( uint8_t *key ) {
  uint32_t new_key[4];
  memcpy(new_key, key, 16);


  ASM->KEY0 = new_key[0];
  ASM->KEY1 = new_key[1];
  ASM->KEY2 = new_key[2];
  ASM->KEY3 = new_key[3];

  // UIP_HTONL
}

void aes_setdata(uint8_t *data, size_t len) {
  uint32_t new_data[4] = {0, 0, 0, 0};
  memcpy(new_data, data, len);
    
  ASM->DATA0 = UIP_HTONL(new_data[0]);
  ASM->DATA1 = UIP_HTONL(new_data[1]);
  ASM->DATA2 = UIP_HTONL(new_data[2]);
  ASM->DATA3 = UIP_HTONL(new_data[3]);


/*  memcpy((void *) &ASM->KEY3, data +  0, 4);
  memcpy((void *) &ASM->KEY2, data +  4, 4);
  memcpy((void *) &ASM->KEY1, data +  8, 4);
  memcpy((void *) &ASM->KEY0, data + 12, 4);

	ASM->KEY0 = 0xccddeeff;  ffeeddcc
	ASM->KEY1 = 0x8899aabb;  bbaa9988
	ASM->KEY2 = 0x44556677;  77665544
	ASM->KEY3 = 0x00112233;  33221100

  uint32_t new_data[4] = {0, 0, 0, 0};
  memcpy(new_data, data, len);

  ASM->DATA0 = new_data[0];
  ASM->DATA1 = new_data[1];
  ASM->DATA2 = new_data[2];
  ASM->DATA3 = new_data[3];

  printf("Gesetzte ASM Daten 0,1,2,3]:\n    %08X %08X %08X %08X\n",
      (unsigned int) ASM->DATA0, 
      (unsigned int) ASM->DATA1, 
      (unsigned int) ASM->DATA2, 
      (unsigned int) ASM->DATA3); 
*/
}

void getAuthCode(uint8_t *out, uint8_t *key, uint8_t *msg, size_t msg_len) {
  aes_setkey(key);

  ASM->CONTROL1bits.CBC = 1;

  // b_0 generieren
  uint8_t b_0[16];
  memset(b_0, 0, 16);
  // Flags
/*  b_0[0] = (8 * ((M-2)/2)) + (L - 1);
  // Nonce
  SETNONCE(b_0 + 1);
  // Länge der Nachricht
  size_t new_len = UIP_HTONL(msg_len);
  memcpy(b_0 + 12, &new_len, 4);
*/

  printf("1: ");
  printBytes(b_0, 16);
  printf("\n");
  printf("2: ");
  printBytes(msg, msg_len);
  printf("\n");

  aes_setdata(b_0, 16);
  aes_round();
/*  size_t i;
  for (i = 0; i < msg_len; i+=16) {
    aes_setdata(msg + i, min(16, msg_len - i));
    aes_round();
  }
*/
  printf("ASM Result 3,2,1,0]      :\n    %08X %08X %08X %08X\n",
      (unsigned int) ASM->CBC3_RESULT, 
      (unsigned int) ASM->CBC2_RESULT, 
      (unsigned int) ASM->CBC1_RESULT, 
      (unsigned int) ASM->CBC0_RESULT);

  memcpy(out, (void *) &(ASM->CBC0_RESULT), 8);
  // memcpy(out, (void *) &(ASM->CBC0_RESULT) + 8, 8)

  ASM->CONTROL0bits.CLEAR = 1;
  ASM->CONTROL1bits.CBC = 0;  
}

void aes_round() {
  ASM->CONTROL0bits.START = 1;
  while (ASM->STATUSbits.DONE == 0) {
    continue;
  }
}

/*---------------------------------------------------------------------------*/

/*---------------------------------------------------------------------------
// set counter registers
void es_setctr( aes_info_t* aes ) {
  ASM->CTR0 = aes->ctr[0];
  ASM->CTR1 = aes->ctr[1];
  ASM->CTR2 = aes->ctr[2];
  ASM->CTR3 = aes->ctr[3];
}

/*---------------------------------------------------------------------------
// increase counter registers
void aes_incctr() {
  ASM->CTR3++;
  if (!ASM->CTR3) {
    ASM->CTR2++;
  }
}

/*---------------------------------------------------------------------------
// read result from registers
void aes_getresult( uint8_t *result ) {
  memcpy( result, (void*)&(ASM->CTR0_RESULT), AES_BLKSIZE);
}

/*---------------------------------------------------------------------------
// actually do the AES encryption on the filled registers
void aes_round() {
  /* set control bit to start encryption and wait until it finishes
  ASM->CONTROL0bits.START = 1;
  while(ASM->STATUSbits.DONE == 0) {
    continue;
  }
}


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

/*---------------------------------------------------------------------------
size_t aes_headerlen( void ) {
  return NONCE_BYTE_COUNT;
}

*/
