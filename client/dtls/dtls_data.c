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

#define SESSION_LIST_LEN 20

Session_t session[SESSION_LIST_LEN];

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
        session[0].seq_num_w = 1;
        memset(session[0].key_block.key_block, 0, sizeof(KeyBlock_t));
        memset(session[0].key_block_new.key_block, 0, sizeof(KeyBlock_t));
    } else {
        memcpy(session[0].id, id, 8);
    }
}

uint16_t getEpoch(uint8_t ip[16]) {
    int i = findIP(ip);
    if (i < 0) {
        return 0;
    }
    return session[i].epoch;
}

uint32_t getSeqNum(uint8_t ip[16]) {
    int i = findIP(ip);
    if (i < 0) {
        return 0;
    }
    return session[i].seq_num_w++;
}

int insertKeyBlock(uint8_t ip[16], KeyBlock_t *key_block) {
    int i = findIP(ip);
    if (i < 0) {
        return -1;
    }
    memcpy(session[i].key_block_new.key_block, key_block, 40);
    return 0;
}

uint8_t *getKeyBlock(uint8_t ip[16], uint16_t epoch) {
    int i = findIP(ip);
    if (i < 0) {
        return 0;
    }
    if (session[i].epoch == epoch) {
        return session[i].key_block.key_block;
    }
    if (session[i].epoch + 1 == epoch) {
        return session[i].key_block_new.key_block;
    }
    return 0;
}

void increaseEpoch(uint8_t ip[16]) {
    int i = findIP(ip);
    if (i < 0) {
        return;
    }
    memcpy(session[i].key_block.key_block, session[i].key_block_new.key_block, 40);
    memset(session[i].key_block_new.key_block, 0, 40);
    session[i].epoch++;
    session[i].seq_num_w = 1;
}

/* Private Funktionen ------------------------------------------------------ */

int findIP(uint8_t ip[16]) {
    int i;
    for (i = 0; i < SESSION_LIST_LEN; i++) {
        if (!memcmp(session[i].ip, ip, 16)) return i;
    }
    return -1;
}
