#include "er-dtls-13-psk.h"

#include "flash-store.h"

/*---------------------------------------------------------------------------*/

#define DEBUG 0

#if DEBUG
    #include <stdio.h>
    #define PRINTF(...) printf(__VA_ARGS__)
#else
    #define PRINTF(...)
#endif

/* Private Funktionsprototypen --------------------------------------------- */

/* Öffentliche Funktionen -------------------------------------------------- */

void getPSK(uint8_t *dst) {
    uint8_t new;
    nvm_getVar(&new, RES_PSK_ISNEW, LEN_PSK_ISNEW);
    if (new == 1) {
        PRINTF("Neuer PSK\n");
        nvm_getVar(dst, RES_NEWPSK, LEN_NEWPSK);
    } else {
        PRINTF("Alter PSK\n");
        nvm_getVar(dst, RES_PSK, LEN_PSK);
    }
}

void newPSK() {
    // Gültige Zeichen: 45, 48 - 57, 65 - 90, 95, 97 - 122
    uint8_t newPSK[LEN_PSK_ISNEW + LEN_NEWPSK];
    newPSK[0] = 1;
    uint8_t i;
    for (i = 1; i <= LEN_NEWPSK; i++) {
        newPSK[i] = 45 + (random_32() % 78);
        PRINTF("%u: %u\n", i, newPSK[i]);
        if (newPSK[i] == 45 || newPSK[i] == 95) continue;
        if (newPSK[i] < 48 || newPSK[i] > 122) {
            i--;
        } else
        if (newPSK[i] > 57 && newPSK[i] < 65) {
            i--;
        } else
        if (newPSK[i] > 90 && newPSK[i] < 97) {
            i--;
        }    
    }
    PRINTF("%.*s\n", LEN_NEWPSK, &newPSK[1]);
    nvm_setVar(newPSK, RES_PSK_ISNEW, LEN_PSK_ISNEW + LEN_NEWPSK);
}

/* Private Funktionen ------------------------------------------------------ */

