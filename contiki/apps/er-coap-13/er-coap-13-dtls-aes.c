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

#define min(x,y) ((x)<(y)?(x):(y))

/*---------------------------------------------------------------------------*/

void aes_getData(uint8_t *dest, uint32_t *src, size_t len);
void aes_setData(uint32_t *dest, uint8_t *src, size_t len);
void aes_round();

/*---------------------------------------------------------------------------*/

uint32_t aes_init() {
  PRINTF("\n *** AMS self-test ");   // Das ASM-Modul ist deaktiviert bis der Test durchgelaufen ist
  ASM->CONTROL1bits.ON = 1;
  ASM->CONTROL1bits.SELF_TEST = 1;
  ASM->CONTROL0bits.START = 1;

  /* Wait for self-test to pass */
  while (!ASM->STATUSbits.DONE) {
    #if DEBUG
      static uint32_t count = 0;
      if (!(count & 0xFF)) PRINTF(".");
    #endif
    continue;
  }

  if(!ASM->STATUSbits.TEST_PASS){
    PRINTF(" TEST FAILED ***\n");
    return -1;
  }

  ASM->CONTROL1bits.SELF_TEST = 0;   // Test-Modus wieder deaktivieren
  ASM->CONTROL1bits.NORMAL_MODE = 1; // BOOT-Modus mit internem geheimen Schlüssel verlassen
  ASM->CONTROL1bits.BYPASS = 0;      // Bypass würde die Verschlüsselung deaktivieren

	ASM->CONTROL1bits.CTR = 1;
	ASM->CONTROL1bits.CBC = 1;

  PRINTF(" finished ***\n\n");

  return 0;
}

/*---------------------------------------------------------------------------*/

void crypt(uint8_t *key, CCMData_t *data, size_t len, uint8_t nonce_only) {
  uint8_t abs_0[16];    // Für a_0, b_0 und s_0 benötigter Speicher
  uint32_t i, turn_var;

  ASM->CONTROL0bits.CLEAR = 1;

  aes_setData((uint32_t *) &(ASM->KEY0), key, 16);

  // CBC-Initialisierungsblock b_0 generieren und verschlüsseln.
  // Das Ergebnis fließt nicht direkt mit in den Geheimtext ein.
  memset(abs_0, 0, 16);
  abs_0[0] = (8 * ((MAC_LEN-2)/2)) + (LEN_LEN - 1);     // Flags
  memcpy(abs_0 + 1, data->nonce_explicit, NONCE_LEN);   // Nonce
  turn_var = UIP_HTONL(len);                            // Länge der Nachricht
  memcpy(abs_0 + 12, &turn_var, 4);                     // Länge der Nachricht
  aes_setData((uint32_t *) &(ASM->DATA0), abs_0, 16);
  aes_round();

  // CTR-Counter vorbereiten. Die Nonce ist schon enthalten.
  // Der Zähler selbst wird innerhalb der Schleife gesetzt.
  // Muss auch bei nonce_only passieren, da für MAC benötigt.
  abs_0[0] = (LEN_LEN - 1);

  // Zentraler Verschlüsselungprozess
  for (i = 0; i < len; i+=16) {
    if (!nonce_only) {
      turn_var = UIP_HTONL((i/16)+1);                  // Counter
      memcpy(abs_0 + 12, &turn_var, 4);                 // Counter
      aes_setData((uint32_t *) &(ASM->CTR0), abs_0, 16);
    }
    aes_setData((uint32_t *) &(ASM->DATA0), data->ccm_ciphered + i, min(16, len - i));
    aes_round();
    if (!nonce_only) {
      aes_getData(data->ccm_ciphered + i, (uint32_t *) &(ASM->CTR0_RESULT), min(16, len - i));
    }
  }

  // CBC-MAC-Ergebnis auslesen
  aes_getData(data->ccm_ciphered + len, (uint32_t *) &(ASM->CBC0_RESULT), 8);

  // a_0 generieren, zu s_0 verschlüssel und mit CBC-MAC X-Oren
  memset(abs_0 + 12, 0, 4);
  aes_setData((uint32_t *) &(ASM->CTR0), abs_0, 16);
  memset(abs_0, 0, 16);
  aes_setData((uint32_t *) &(ASM->DATA0), abs_0, 16);
  aes_round();
  aes_getData(abs_0, (uint32_t *) &(ASM->CTR0_RESULT), NONCE_LEN);
  for (i = 0; i < NONCE_LEN; i++) data->ccm_ciphered[len + i] = data->ccm_ciphered[len + i] ^ abs_0[i];
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
