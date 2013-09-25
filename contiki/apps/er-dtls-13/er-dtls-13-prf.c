#include "er-dtls-13-prf.h"

#include <string.h>

#include "er-dtls-13-psk.h"

#include "aes.h"

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

void prf(uint8_t *dst, uint8_t len, uint8_t *seed, uint16_t seed_len) {
    uint8_t psk[16];
    getPSK(psk);

    // A(1) generieren
    uint8_t ax[16];
    memset(ax, 0, 16);
    aes_cmac(ax, seed, seed_len, psk, 1);

    while (len > 0) {
        uint8_t result[16];
        memset(result, 0, 16);
        aes_cmac(result, ax, 16, psk, 0);
        aes_cmac(result, seed, seed_len, psk, 1);
        memcpy(dst, result, len < 16 ? len : 16);

        // Falls weitere Daten benötigt werden, wird der Pointer und die
        // Länge entsprechend angepasst und ax weiterentwickelt
        if (len > 16) {
            dst += 16;
            len -= 16;

            uint8_t oldA[16];
            memcpy(oldA, ax, 16);
            memset(ax, 0, 16);
            aes_cmac(ax, oldA, 16, psk, 1);
        } else {
            len = 0;
        }
    }
}

/* Private Funktionen ------------------------------------------------------ */

