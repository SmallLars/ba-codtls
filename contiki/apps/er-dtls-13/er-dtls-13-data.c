#include "er-dtls-13-data.h"

#include <string.h>

#include "flash-store.h"

/*---------------------------------------------------------------------------*/

#define DEBUG 0

#if DEBUG
    #include <stdio.h>
    #define PRINTF(...) printf(__VA_ARGS__)
#else
    #define PRINTF(...)
#endif

#define KEY (uint8_t *) "ABCDEFGHIJKLMNOP"

/* Private Funktionsprototypen --------------------------------------------- */

int8_t getIndexOf(uint8_t *ip);

/* Öffentliche Funktionen -------------------------------------------------- */

int8_t insertClient(Client_t *client) {
    uint8_t list_len;
    nvm_getVar(&list_len, RES_CLIENT_INFO_LEN, LEN_CLIENT_INFO_LEN);

    Client_t *ci = (Client_t *) RES_CLIENT_INFO;
    if (list_len < 9) {
        nvm_setVar(client, (uint32_t) &ci[list_len], sizeof(Client_t));
        list_len++;
        nvm_setVar(&list_len, RES_CLIENT_INFO_LEN, LEN_CLIENT_INFO_LEN);

        #if DEBUG
            PRINTF("Eingefügte IP an Index %u:", list_len - 1);
            uint8_t j;
            for (j = 0; j < 16; j++) PRINTF(" %02X", client->ip[j]);
            PRINTF("\n");
        #endif

        return 0;
    }

    return -1;
}

int8_t insertKeyBlock(KeyBlock_t *key_block) {
    uint8_t list_len;
    nvm_getVar(&list_len, RES_CLIENT_KEYS_LEN, LEN_CLIENT_KEYS_LEN);

    KeyBlock_t *ck = (KeyBlock_t *) RES_CLIENT_KEYS;
    if (list_len < 20) {
        nvm_setVar(key_block, (uint32_t) &ck[list_len], sizeof(KeyBlock_t));
        list_len++;
        nvm_setVar(&list_len, RES_CLIENT_KEYS_LEN, LEN_CLIENT_KEYS_LEN);
        return 0;
    }

    return -1;
}

int16_t getEpoch(uint8_t *ip) {
    int8_t index = getIndexOf(ip);
    PRINTF("Index der gesuchten IP: %i\n", getIndexOf(ip));
    if (index == -1) return -1;

    Client_t *ci = (Client_t *) RES_CLIENT_INFO;

    uint16_t epoch;
    nvm_getVar(&epoch, (uint32_t) &ci[index].epoch, 2);

    return epoch;
}

int8_t getPrivateKey(uint32_t *key, uint8_t *ip) {
    int8_t index = getIndexOf(ip);
    PRINTF("Index der gesuchten IP: %i\n", getIndexOf(ip));
    if (index == -1) return -1;

    Client_t *ci = (Client_t *) RES_CLIENT_INFO;
    nvm_getVar(key, (uint32_t) &ci[index].private_key, 32);

    return 0;
}

KeyBlock_t *getKeyBlock(uint8_t *ip, uint8_t epoch) {
    if (epoch == 0) return 0;

    int8_t index = getIndexOf(ip);
    if (index == -1) return 0;

    uint8_t list_len;
    nvm_getVar(&list_len, RES_CLIENT_KEYS_LEN, LEN_CLIENT_KEYS_LEN);

    KeyBlock_t *ck = (KeyBlock_t *) RES_CLIENT_KEYS;
    int i;
    for (i = 0; i < list_len; i++) {
        if (nvm_cmp(&index, (uint32_t) &ck[i].index, 1) == 0) {
            if (nvm_cmp(&epoch, (uint32_t) &ck[i].epoch, 1) == 0) {
                return &ck[i];
            }
        }
    }

    return 0;
}

void checkEpochIncrease(uint8_t *ip, uint16_t epoch) {
    if (epoch == 0) return;
    epoch--;

    int8_t index = getIndexOf(ip);
    if (index == -1) return;

    Client_t *ci = (Client_t *) RES_CLIENT_INFO;
    if (nvm_cmp(&epoch, (uint32_t) &ci[index].epoch, 2) == 0) {
        epoch++;
        nvm_setVar(&epoch, (uint32_t) &ci[index].epoch, 2);
        // TODO daten der alten epoche entfernen
    }
}

int8_t updateIp(uint8_t *session, uint8_t *ip) {
//    nvmErr_t nvm_cmp(void *src, uint32_t address, uint32_t numBytes);
}

/* Private Funktionen ------------------------------------------------------ */

int8_t getIndexOf(uint8_t *ip) {
    #if DEBUG
        PRINTF("Suche nach IP:");
        uint8_t j;
        for (j = 0; j < 16; j++) PRINTF(" %02X", ip[j]);
        PRINTF("\n");
    #endif

    uint8_t list_len;
    nvm_getVar(&list_len, RES_CLIENT_INFO_LEN, LEN_CLIENT_INFO_LEN);

    Client_t *ci = (Client_t *) RES_CLIENT_INFO;
    uint8_t i;
    for (i = 0; i < list_len; i++) {
        if (nvm_cmp(ip, (uint32_t) ci[i].ip, 16) == 0) return i;
    }
    return -1;
}
