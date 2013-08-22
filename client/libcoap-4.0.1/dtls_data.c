#include "dtls_data.h"

/*---------------------------------------------------------------------------*/

#define DEBUG 0

#if DEBUG
    #include <stdio.h>
    #define PRINTF(...) printf(__VA_ARGS__)
#else
    #define PRINTF(...)
#endif

uint8_t key = 0;

/* Private Funktionsprototypen --------------------------------------------- */

/* Öffentliche Funktionen -------------------------------------------------- */

uint8_t getKey() {
    return key;
}

void setKey() {
    key = 1;
}

/* Private Funktionen ------------------------------------------------------ */

