#include "dtls_data.h"

#include <string.h>

/*---------------------------------------------------------------------------*/

#define DEBUG 0

#if DEBUG
    #include <stdio.h>
    #define PRINTF(...) printf(__VA_ARGS__)
#else
    #define PRINTF(...)
#endif

typedef struct {
    uint8_t uuid[16];
    uint8_t psk[16];
} PSK_t;

Session_t session[1];

/* Private Funktionsprototypen --------------------------------------------- */

int findIP(uint8_t ip[16]);

/* Öffentliche Funktionen -------------------------------------------------- */

int getPSK(uint8_t dst[16], uint8_t uuid[16]) {
    memcpy(dst, "ABCDEFGHIJKLMNOP", 16);
    return 0;
}

void createSession(uint8_t ip[16], uint8_t id[8]) {
    if (findIP(ip) < 0) {
        memcpy(session[0].ip, ip, 16);
        memcpy(session[0].id, id, 8);
        session[0].epoch = 0;
        session[0].seq_num = 1;
        memset(session[0].key_block.key_block, 0, sizeof(KeyBlock_t));
        memset(session[0].key_block_new.key_block, 0, sizeof(KeyBlock_t));
    }
}

uint16_t getEpoch(uint8_t ip[16]) {
    return session[0].epoch;
}

uint32_t getSeqNum(uint8_t ip[16]) {
    return session[0].seq_num++;
}

int insertKeyBlock(uint8_t ip[16], KeyBlock_t *key_block) {
    memcpy(session[0].key_block_new.key_block, key_block, 40);
    return 0;
}

uint8_t *getKeyBlock(uint8_t ip[16], uint16_t epoch) {
    return session[0].key_block.key_block;
}

void increaseEpoch(uint8_t ip[16]) {
    memcpy(session[0].key_block.key_block, session[0].key_block_new.key_block, 40);
    memset(session[0].key_block_new.key_block, 0, 40);
    session[0].epoch++;
    session[0].seq_num = 1;
}

/* Private Funktionen ------------------------------------------------------ */

int findIP(uint8_t ip[16]) {
    int i;
    for (i = 0; i < 1; i++) {
        if (!memcmp(session[i].ip, ip, 16)) return i;
    }
    return -1;
}
