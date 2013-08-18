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

int8_t insertClient(ClientInfo_t *clientInfo) {
    uint8_t list_len;
    nvm_getVar(&list_len, RES_CLIENT_INFO_LEN, LEN_CLIENT_INFO_LEN);

    ClientInfo_t *ci = (ClientInfo_t *) RES_CLIENT_INFO;
    if (list_len < 9) {
        nvm_setVar(clientInfo, (uint32_t) &ci[list_len], sizeof(ClientInfo_t));
        list_len++;
        nvm_setVar(&list_len, RES_CLIENT_INFO_LEN, LEN_CLIENT_INFO_LEN);

        #if DEBUG
            PRINTF("Eingefügte IP an Index %u:", list_len - 1);
            uint8_t j;
            for (j = 0; j < 16; j++) PRINTF(" %02X", clientInfo->ip[j]);
            PRINTF("\n");
        #endif

        return 0;
    }

    return -1;
}

int8_t insertKey(ClientKey_t *clientKey) {
    uint8_t list_len;
    nvm_getVar(&list_len, RES_CLIENT_KEYS_LEN, LEN_CLIENT_KEYS_LEN);

    ClientKey_t *ck = (ClientKey_t *) RES_CLIENT_KEYS;
    if (list_len < 20) {
        nvm_setVar(clientKey, (uint32_t) &ck[list_len], sizeof(ClientKey_t));
        list_len++;
        nvm_setVar(&list_len, RES_CLIENT_KEYS_LEN, LEN_CLIENT_KEYS_LEN);
        return 0;
    }

    return -1;
}

int8_t getEpoch(uint8_t *ip) {
    int8_t index = getIndexOf(ip);
    PRINTF("Index der gesuchten IP: %i\n", getIndexOf(ip));
    if (index == -1) return -1;

    ClientInfo_t *ci = (ClientInfo_t *) RES_CLIENT_INFO;

    uint8_t epoch;
    nvm_getVar(&epoch, (uint32_t) &ci[index].epoch, 1);

    uint8_t pending;
    nvm_getVar(&pending, (uint32_t) &ci[index].pending, 1);

    return epoch == 0 ? 0 : epoch - pending;
}

int8_t getPrivateKey(uint32_t *key, uint8_t *ip) {
    int8_t index = getIndexOf(ip);
    PRINTF("Index der gesuchten IP: %i\n", getIndexOf(ip));
    if (index == -1) return -1;

    ClientInfo_t *ci = (ClientInfo_t *) RES_CLIENT_INFO;
    nvm_getVar(key, (uint32_t) &ci[index].private_key, 32);

    return 0;
}

int8_t getKey(uint8_t *key, uint8_t *ip, uint8_t epoch) {
    if (epoch == 0) return -1;

    int8_t index = getIndexOf(ip);
    if (index == -1) return -1;

    uint8_t list_len;
    nvm_getVar(&list_len, RES_CLIENT_KEYS_LEN, LEN_CLIENT_KEYS_LEN);

    ClientKey_t *ck = (ClientKey_t *) RES_CLIENT_KEYS;
    int i;
    for (i = 0; i < list_len; i++) {
        if (nvm_cmp(&index, (uint32_t) &ck[i].index, 1) == 0) {
            if (nvm_cmp(&epoch, (uint32_t) &ck[i].epoch, 1) == 0) {
                if (key != NULL) nvm_getVar(key, (uint32_t) ck[i].server_write_key, 16);
                return 0;
            }
        }
    }

    return -1;
}

int8_t changeIfPending(uint8_t *ip) {
    int8_t index = getIndexOf(ip);
    if (index == -1) return -1;

    uint8_t pending = 1;
    ClientInfo_t *ci = (ClientInfo_t *) RES_CLIENT_INFO;
    if (nvm_cmp(&pending, (uint32_t) &ci[index].pending, 1) == 0) {
        uint8_t epoch;
        nvm_getVar(&epoch, (uint32_t) &ci[index].epoch, 1);
        if (getKey(NULL, ip, epoch) == 0) {
            pending = 0;
            nvm_setVar(&pending, (uint32_t) &ci[index].pending, 1);
        }
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

    ClientInfo_t *ci = (ClientInfo_t *) RES_CLIENT_INFO;
    uint8_t i;
    for (i = 0; i < list_len; i++) {
        if (nvm_cmp(ip, (uint32_t) ci[i].ip, 16) == 0) return i;
    }
    return -1;
}
