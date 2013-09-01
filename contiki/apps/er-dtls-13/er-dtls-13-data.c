#include "er-dtls-13-data.h"

#include <string.h>

#include "ecc.h"
#include "flash-store.h"

/*---------------------------------------------------------------------------*/

#define DEBUG 0

#if DEBUG
    #include <stdio.h>
    #define PRINTF(...) printf(__VA_ARGS__)
    #define PRINTSESSION(i) printSession(i)
    void printSession(uint8_t index);
#else
    #define PRINTF(...)
    #define PRINTSESSION(i)
#endif

/* Private Funktionsprototypen --------------------------------------------- */

int8_t getIndexOf(uint8_t *ip);
void checkEpochIncrease(uint8_t index, uint16_t epoch);

/* Öffentliche Funktionen -------------------------------------------------- */

int8_t createSession(uint32_t *buf, uint8_t ip[16]) {
    nvm_getVar(buf, RES_ECC_ORDER, LEN_ECC_ORDER);
    #if DEBUG
        uint8_t i;
        printf("ECC_ORDER: ");
        for (i = 0; i < 8; i++) printf("%08X", uip_htonl(buf[i]));
        printf("\n");
    #endif
    Session_t *session = (Session_t *) (buf + 8);

    // TODO prüfen ob ip schon enthalten. wenn ja nur private key schreiben
    uint8_t list_len;
    nvm_getVar(&list_len, RES_SESSION_LEN, LEN_SESSION_LEN);
    if (list_len == 10)
        return -1;

    memcpy(session->ip, ip, 16);
    memcpy(session->session, "IJKLMNOP", 8); // TODO session generieren
    session->epoch = 0;
    do {
        random_x((uint8_t *) session->private_key, 32);
    } while (!ecc_is_valid_key(session->private_key, buf));

    Session_t *s = (Session_t *) RES_SESSION_LIST;
    nvm_setVar(session, (uint32_t) &s[list_len], sizeof(Session_t));

    list_len++;
    nvm_setVar(&list_len, RES_SESSION_LEN, LEN_SESSION_LEN);

    PRINTF("Session erstellt:\n");
    PRINTSESSION(list_len - 1);

    return 0;
}

int8_t getSessionData(uint8_t *dst, uint8_t ip[16], SessionDataType type) {
    int8_t i = getIndexOf(ip);
    if (i == -1) {
        PRINTF("getSessionData: Keine Daten zur gesuchten IP gefunden\n");
        return -1;
    }

    Session_t *s = (Session_t *) RES_SESSION_LIST;
    switch (type) {
        case session_id:
            nvm_getVar(dst, (uint32_t) &s[i].session, 8);
            return 8;
        case session_epoch:
            nvm_getVar(dst, (uint32_t) &s[i].epoch, 2);
            return 2;
        case session_key:
            nvm_getVar(dst, (uint32_t) &s[i].private_key, 32);
            return 32;
    }
}

int8_t insertKeyBlock(uint8_t *ip, KeyBlock_t *key_block) {
    int8_t index = getIndexOf(ip);
    if (index == -1) {
        PRINTF("insertKeyBlock: Ip nicht gefunden\n");
        return -1;
    }

    PRINTF("Daten vor Insert KeyBlock:\n");
    PRINTSESSION(index);
    KeyBlock_t *ck = (KeyBlock_t *) RES_KEY_BLOCK_LIST;
    nvm_setVar(key_block, (uint32_t) &ck[(2 * index) + 1], sizeof(KeyBlock_t));
    PRINTF("Daten nach Insert KeyBlock:\n");
    PRINTSESSION(index);
    return 0;
}

uint32_t getKeyBlock(uint8_t *ip, uint16_t epoch, uint8_t update) {
    if (epoch == 0) return 0;

    int8_t index = getIndexOf(ip);
    if (index == -1) return 0;

    if (update) checkEpochIncrease(index, epoch);

    Session_t *s = (Session_t *) RES_SESSION_LIST;
    KeyBlock_t *kb = (KeyBlock_t *) RES_KEY_BLOCK_LIST;
    if (nvm_cmp(&epoch, (uint32_t) &s[index].epoch, 2) == 0) {
        return (uint32_t ) &kb[2 * index];
    }
    epoch--;
    if (nvm_cmp(&epoch, (uint32_t) &s[index].epoch, 2) == 0) {
        return (uint32_t ) &kb[(2 * index) + 1];
    }

    return 0;
}

/* Private Funktionen ------------------------------------------------------ */

int8_t getIndexOf(uint8_t *ip) {
    uint8_t list_len;
    nvm_getVar(&list_len, RES_SESSION_LEN, LEN_SESSION_LEN);

    Session_t *s = (Session_t *) RES_SESSION_LIST;
    uint8_t i;
    for (i = 0; i < list_len; i++) {
        if (nvm_cmp(ip, (uint32_t) s[i].ip, 16) == 0) return i;
    }
    return -1;
}

void checkEpochIncrease(uint8_t index, uint16_t epoch) {
    epoch--;
    Session_t *s = (Session_t *) RES_SESSION_LIST;

    if (nvm_cmp(&epoch, (uint32_t) &s[index].epoch, 2) == 0) {
        PRINTF("Daten vor Epoch-Increase:\n");
        PRINTSESSION(index);

        epoch++;
        nvm_setVar(&epoch, (uint32_t) &s[index].epoch, 2);
        
        uint8_t buf[2 * sizeof(KeyBlock_t)];
        KeyBlock_t *kb = (KeyBlock_t *) RES_KEY_BLOCK_LIST;
        nvm_getVar(buf, (uint32_t) &kb[(2 * index) + 1], sizeof(KeyBlock_t));
        memset(buf + sizeof(KeyBlock_t), 0, sizeof(KeyBlock_t));
        nvm_setVar(buf, (uint32_t) &kb[2 * index], 2 * sizeof(KeyBlock_t));

        PRINTF("Daten nach Epoch-Increase:\n");
        PRINTSESSION(index);
    }
}

#if DEBUG
    void printSession(uint8_t index) {
        uint8_t i;
        uint8_t buffer[sizeof(Session_t)];

        Session_t *session = (Session_t *) buffer;
        Session_t *s = (Session_t *) RES_SESSION_LIST;
        nvm_getVar(buffer, (uint32_t) &s[index], sizeof(Session_t));
        PRINTF("    Index: %u \n    Session-ID: %.*s\n    IP: ",index, 8, session->session);
        for (i = 0; i < 16; i++) PRINTF("%02X", session->ip[i]);
        PRINTF("\n    Epoch: %u\n    Private-Key: ", session->epoch);
        for (i = 0; i < 8; i++) PRINTF("%08X", uip_htonl(session->private_key[i]));

        KeyBlock_t *kb = (KeyBlock_t *) RES_KEY_BLOCK_LIST;
        nvm_getVar(buffer, (uint32_t) &kb[2 * index], sizeof(KeyBlock_t));
        PRINTF("\n        Key-Block 1: ");
        for (i = 0; i < sizeof(KeyBlock_t); i++) PRINTF("%02X", buffer[i]);
        nvm_getVar(buffer, (uint32_t) &kb[(2 * index) + 1], sizeof(KeyBlock_t));
        PRINTF("\n        Key-Block 2: ");
        for (i = 0; i < sizeof(KeyBlock_t); i++) PRINTF("%02X", buffer[i]);
        PRINTF("\n");
    }
#endif
