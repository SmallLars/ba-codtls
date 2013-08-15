#include "dtls_prf.h"

#include "dtls_ccm.h"

#include <string.h>
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
    // A(1) generieren
    uint8_t ax[16];
    memset(ax, 0, 16);
    cbc_mac_16(ax, seed, seed_len);

    while (len > 0) {
        uint8_t result[16];
        memset(result, 0, 16);
        cbc_mac_16(result, ax, 16);
        cbc_mac_16(result, seed, seed_len);
        memcpy(dst, result, len < 16 ? len : 16);

        // Falls weitere Daten benötigt werden, wird der Pointer und die
        // Länge entsprechend angepasst und ax weiterentwickelt
        if (len > 16) {
            dst += 16;
            len -= 16;

            uint8_t oldA[16];
            memcpy(oldA, ax, 16);
            memset(ax, 0, 16);
            cbc_mac_16(ax, oldA, 16);
        } else {
            len = 0;
        }
    }
}

/* Private Funktionen ------------------------------------------------------ */

