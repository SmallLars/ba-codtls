#include "aes.h"

#include "mc1322x.h"
#include "../../core/net/uip.h"

#include <string.h>

/*---------------------------------------------------------------------------*/

#define DEBUG 0

#if DEBUG
    #include <stdio.h>
    #define PRINTF(...) printf(__VA_ARGS__)
    void print_hex(uint8_t *d, uint8_t l) {
        int i;
        for (i = 0; i < l; i++) printf("%02X", d[i]);
    }
#else
    #define PRINTF(...)
#endif

#define min(x,y) ((x)<(y)?(x):(y))

/* Private Funktionsprototypen --------------------------------------------- */

void aes_getData(uint8_t *dest, uint32_t *src, size_t len);
void aes_setData(uint32_t *dest, uint8_t *src, size_t len);
void aes_round();
__attribute__((always_inline)) static void cmac_subkey(uint8_t L[16], uint8_t K);

/* Öffentliche Funktionen -------------------------------------------------- */

uint32_t aes_init() {
    PRINTF("\n *** AMS self-test ");   // Das ASM-Modul ist deaktiviert bis der Test durchgelaufen ist
    ASM->CONTROL1bits.ON = 1;
    ASM->CONTROL1bits.SELF_TEST = 1;
    ASM->CONTROL0bits.START = 1;

    /* Auf Beenden des Selbsttests warten */
    while (!ASM->STATUSbits.DONE) {
        #if DEBUG
            static uint32_t count = 0;
            if (!(count & 0xFF)) PRINTF(".");
        #endif
        continue;
    }

    if (!ASM->STATUSbits.TEST_PASS){
        PRINTF(" TEST FAILED ***\n");
        return -1;
    }

    ASM->CONTROL1bits.SELF_TEST = 0;   // Test-Modus wieder deaktivieren
    ASM->CONTROL1bits.NORMAL_MODE = 1; // Boot-Modus mit internem geheimen Schlüssel verlassen
    ASM->CONTROL1bits.BYPASS = 0;      // Bypass würde die Verschlüsselung deaktivieren

    ASM->CONTROL1bits.CTR = 1;
    ASM->CONTROL1bits.CBC = 1;

    PRINTF(" finished ***\n\n");

    return 0;
}

void aes_crypt(uint8_t data[], size_t data_len, uint8_t key[16], uint8_t nonce[NONCE_LEN], uint8_t mac_only) {
    uint8_t abs_0[16];    // Für a_0, b_0 und s_0 benötigter Speicher
    uint32_t i;

    ASM->CONTROL0bits.CLEAR = 1;

    aes_setData((uint32_t *) &(ASM->KEY0), key, 16);

    // CBC-Initialisierungsblock b_0 generieren und verschlüsseln.
    // Das Ergebnis fließt nicht direkt mit in den Geheimtext ein.
    memset(abs_0, 0, 16);
    abs_0[0] = (8 * ((MAC_LEN-2)/2)) + (LEN_LEN - 1);     // Flags
    i = uip_htonl(data_len);                              // Länge der Nachricht
    memcpy(abs_0 + 12, &i, 4);                            // Länge der Nachricht
    memcpy(abs_0 + 1, nonce, NONCE_LEN);                  // Nonce
    #if DEBUG
        printf("b_0 Block für CCM:");
        print_hex(abs_0, 16);
        printf("\n");
    #endif
    aes_setData((uint32_t *) &(ASM->DATA0), abs_0, 16);
    aes_round();

    // CTR-Counter vorbereiten. Die Nonce ist schon enthalten.
    // Der Zähler selbst wird innerhalb der Schleife gesetzt.
    // Muss auch bei mac_only passieren, da für MAC benötigt.
    abs_0[0] = (LEN_LEN - 1);

    // Zentraler Verschlüsselungprozess
    for (i = 0; i < data_len; i+=16) {
        if (!mac_only) {
            uint8_t j;
            uint32_t index = (i/16) + 1;
            for (j = 15; j > NONCE_LEN; j--) {
                abs_0[j] = (index >> ((15-j)*8)) & 0xFF;
            }
            #if DEBUG
                printf("a[%u] Block für CCM:", index);
                print_hex(abs_0, 16);
                printf("\n");
            #endif
            aes_setData((uint32_t *) &(ASM->CTR0), abs_0, 16);
        }
        aes_setData((uint32_t *) &(ASM->DATA0), data + i, min(16, data_len - i));
        aes_round();
        if (!mac_only) {
            aes_getData(data + i, (uint32_t *) &(ASM->CTR0_RESULT), min(16, data_len - i));
        }
    }

    // CBC-MAC-Ergebnis auslesen
    aes_getData(&data[data_len], (uint32_t *) &(ASM->CBC0_RESULT), 8);

    // a_0 generieren, zu s_0 verschlüsseln und mit CBC-MAC X-Oren
    for (i = 15; i > NONCE_LEN; i--) {
        abs_0[i] = 0;
    }
    #if DEBUG
        printf("a[0] Block für CCM:");
        print_hex(abs_0, 16);
        printf("\n");
    #endif
    aes_setData((uint32_t *) &(ASM->CTR0), abs_0, 16);
    memset(abs_0, 0, 16);
    aes_setData((uint32_t *) &(ASM->DATA0), abs_0, 16);
    aes_round();
    aes_getData(abs_0, (uint32_t *) &(ASM->CTR0_RESULT), MAC_LEN);
    for (i = 0; i < MAC_LEN; i++) data[data_len + i] ^= abs_0[i];
}

void aes_cmac(uint8_t mac[16], uint8_t data[], size_t data_len, uint8_t key[16], uint8_t finish) {
    uint32_t i;

    #if DEBUG
        if (data_len == 0) {
            printf("aes_cmac: Ungültiger Aufruf. data_len == 0 ist nicht zulässig.\n");
            return;
        }
        if (!finish && data_len % 16) {
            printf("aes_cmac: Ungütiger Aufruf. Bei finish == 0 muss data_len ein Vielfaches der Blockgröße sein.\n");
            return;
        }

        printf("Key      ");
        print_hex(key, 16);
        printf("\n");
    #endif

    ASM->CONTROL0bits.CLEAR = 1;
    
    aes_setData((uint32_t *) &(ASM->KEY0), key, 16);

    uint8_t buf[16];
    if (finish) {
        aes_setData((uint32_t *) &(ASM->DATA0), NULL, 0);
        aes_round();
        aes_getData(buf, (uint32_t *) &(ASM->CBC0_RESULT), 16);
        #if DEBUG
            printf("K0       ");
            print_hex(buf, 16);
            printf("\n");
        #endif
    }

    aes_setData((uint32_t *) &(ASM->MAC0), mac, 16);
    ASM->CONTROL0bits.LOAD_MAC = 1;

    for (i = 0; 1; i+=16) {
        if (finish && data_len <= 16) break;

        aes_setData((uint32_t *) &(ASM->DATA0), data + i, 16);
        aes_round();

        data_len -= 16;
        if (data_len == 0) break;
    }

    if (finish) {
        cmac_subkey(buf, data_len == 16 ? 1 : 2);
        #if DEBUG
            printf("KX       ");
            print_hex(buf, 16);
            printf("\n");
        #endif

        uint8_t *last_block = data + i;

        for (i = 0; i < data_len; i++) {
            buf[i] ^= last_block[i];
        }

        if (i < 16) {
            buf[i] ^= 128;
            for (i++; i < 16; i++) {
                buf[i] ^= 0;
            }
        }

        aes_setData((uint32_t *) &(ASM->DATA0), buf, 16);
        aes_round();
    }

    aes_getData(mac, (uint32_t *) &(ASM->CBC0_RESULT), 16);

    #if DEBUG
        printf("AES_CMAC ");
        print_hex(mac, 16);
        printf("\n");
    #endif
}

/* Private Funktionen ------------------------------------------------------ */

void aes_getData(uint8_t *dest, uint32_t *src, size_t len) {
    uint32_t data[4];
    data[0] = uip_htonl(src[0]);
    data[1] = uip_htonl(src[1]);
    data[2] = uip_htonl(src[2]);
    data[3] = uip_htonl(src[3]);
    memcpy(dest, data, len);
}

void aes_setData(uint32_t *dest, uint8_t *src, size_t len) {
    uint32_t data[4] = {0, 0, 0, 0};
    memcpy(data, src, len);
    dest[0] = uip_htonl(data[0]);
    dest[1] = uip_htonl(data[1]);
    dest[2] = uip_htonl(data[2]);
    dest[3] = uip_htonl(data[3]);
}

void aes_round() {
    ASM->CONTROL0bits.START = 1;
    while (ASM->STATUSbits.DONE == 0) {
        continue;
    }
}

__attribute__((always_inline)) static void cmac_subkey(uint8_t L[16], uint8_t K) {
    while (K > 0) {
        uint8_t i, msb = L[0] & 0x80;
        for (i = 0; i < 15; i++) {
            L[i] <<= 1;
            L[i] |= (L[i+1] >> 7);
        }
        L[15] <<= 1;
        if (msb) {
            for (i = 0; i < 15; i++) {
                L[i] ^= 0;
            }
            L[15] ^= 0x87;
        }
        K--;
    }
}
