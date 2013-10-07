#include "er-dtls-13-data.h"

#include <string.h>

#include "ecc.h"
#include "flash-store.h"
#include "er-dtls-13-random.h"
#include "er-dtls-13-psk.h"

/*---------------------------------------------------------------------------*/

uint32_t seq_num_r[SESSION_LIST_LEN];
uint32_t seq_num_w[SESSION_LIST_LEN];

#define DEBUG 0

#if DEBUG
    #include <stdio.h>
    #define PRINTF(...) printf(__VA_ARGS__)
    #define PRINTSESSION(i) printSession(i)
    void printSession(uint8_t index) {
        uint8_t i;
        uint8_t buffer[sizeof(Session_t)];

        Session_t *session = (Session_t *) buffer;
        Session_t *s = (Session_t *) RES_SESSION_LIST;
        nvm_getVar(buffer, (fpoint_t) &s[index], sizeof(Session_t));
        printf("    Index: %u \n    Session-ID: %.*s\n    IP: ", index, 8, session->session);
        for (i = 0; i < 16; i++) printf("%02X", ((uint8_t *) &session->addr)[i]);
        printf("\n    Epoch: %u\n    Valid: %u\n    Private-Key: ", session->epoch, session->valid);
        for (i = 0; i < 8; i++) printf("%08X", uip_htonl(session->private_key[i]));
        printf("\n    Sequenznummer: Read: %u Write %u", seq_num_r[index], seq_num_w[index]);

        KeyBlock_t *kb = (KeyBlock_t *) RES_KEY_BLOCK_LIST;
        nvm_getVar(buffer, (fpoint_t) &kb[2 * index], sizeof(KeyBlock_t));
        printf("\n        Key-Block 1: ");
        for (i = 0; i < sizeof(KeyBlock_t); i++) printf("%02X", buffer[i]);
        nvm_getVar(buffer, (fpoint_t) &kb[(2 * index) + 1], sizeof(KeyBlock_t));
        printf("\n        Key-Block 2: ");
        for (i = 0; i < sizeof(KeyBlock_t); i++) printf("%02X", buffer[i]);
        printf("\n");
    }
#else
    #define PRINTF(...)
    #define PRINTSESSION(i)
#endif

/* Private Funktionsprototypen --------------------------------------------- */

static int getIndexOf(uip_ipaddr_t *addr);
__attribute__((always_inline)) static void checkEpochIncrease(unsigned int index, uint16_t epoch);

/* Öffentliche Funktionen -------------------------------------------------- */

int createSession(uint32_t *buf, uip_ipaddr_t *addr) {
    uint32_t i;

    Session_t *session = (Session_t *) (buf + 8);
    Session_t *s = (Session_t *) RES_SESSION_LIST; // Pointer auf Flashspeicher
    int index = getIndexOf(addr);

    // Ein neuer private Key für ECDH wird in jedem Fall generiert
    nvm_getVar(buf, RES_ECC_ORDER, LEN_ECC_ORDER);
    #if DEBUG
        printf("ECC_ORDER: ");
        for (i = 0; i < 8; i++) printf("%08X", uip_htonl(buf[i]));
        printf("\n");
    #endif
    do {
        random_x((uint8_t *) session->private_key, 32);
    } while (!ecc_is_valid_key(session->private_key, buf));

    // Falls schon ein Eintrag existiert wird die Session durch
    // setzten des neuen private Keys weiterentwickelt. Ansonsten
    // wird alles gesetzt.
    if (index >= 0) {
        nvm_setVar(session->private_key, (fpoint_t) s[index].private_key, 32);
        PRINTF("Session aktualisiert:\n");
        PRINTSESSION(index);
    } else {
        index = getIndexOf(NULL);;
        if (index < 0)
            return -1;

        uip_ipaddr_copy(&session->addr, addr);
        for (i = 0; i < 8; i++) {
            nvm_getVar(session->session + i, RES_ANSCHARS + (random_8() & 0x3F), 1);
        } // TODO session-id auf doppel prüfen
        session->epoch = 0;
        session->valid = 1;

        nvm_setVar(session, (fpoint_t) &s[index], sizeof(Session_t));
        PRINTF("Session erstellt:\n");
        PRINTSESSION(index);
        seq_num_r[index] = 1;
        seq_num_w[index] = 1;
    }

    return 0;
}

int getSessionData(uint8_t *dst, uip_ipaddr_t *addr, SessionDataType type) {
    int i = getIndexOf(addr);
    if (i == -1) {
        PRINTF("getSessionData: Keine Daten zur gesuchten IP gefunden\n");
        return -1;
    }

    uint16_t epo_buf;
    uint32_t num_buf;
    Session_t *s = (Session_t *) RES_SESSION_LIST;
    switch (type) {
        case session_id:
            nvm_getVar(dst, (fpoint_t) &s[i].session, 8);
            return 8;
        case session_epoch:
            nvm_getVar(&epo_buf, (fpoint_t) &s[i].epoch, 2);
            epo_buf = uip_htons(epo_buf);
            memcpy(dst, &epo_buf, 2);
            return 2;
        case session_key:
            nvm_getVar(dst, (fpoint_t) &s[i].private_key, 32);
            return 32;
        case session_num_write:
            num_buf = uip_htonl(seq_num_w[i]);
            memcpy(dst + 2, &num_buf, 4);
            seq_num_w[i]++;
            return 6;
    }
    return 0;
}

int checkReadNum(uip_ipaddr_t *addr, uint8_t seq_num[6]) {
    int index = getIndexOf(addr);
    if (index == -1) {
        PRINTF("checkReadNum: Keine Daten zur gesuchten IP gefunden\n");
        // Ohne Session ist Epoch 0. seq_num irrelevant -> immer ok
        return 0;
    }

    // Überlauf bei Subtraktion produziert große Zahl
    uint32_t diff = 0;
    diff += (seq_num[2] << 24);
    diff += (seq_num[3] << 16);
    diff += (seq_num[4] <<  8);
    diff += (seq_num[5] <<  0);
    diff -= seq_num_r[index];
    PRINTF("checkReadNum: diff: %u\n", diff + 10);
    if ((diff + 10) > 110) return -1; // Gültig ist  (seq_num_r - 10) bis (seq_num_r + 100)

    seq_num_r[index] += (diff + 1);
    return 0;
}

int deleteSession(uip_ipaddr_t *addr) {
    int index = getIndexOf(addr);
    if (index == -1) {
        PRINTF("delete Session: Ip nicht gefunden\n");
        return -1;
    }

    uint16_t valid = 0;
    Session_t *s = (Session_t *) RES_SESSION_LIST; // Pointer auf Flashspeicher
    nvm_setVar(&valid, (fpoint_t) &s[index].valid, 2);
    return 0;
}

int insertKeyBlock(uip_ipaddr_t *addr, KeyBlock_t *key_block) {
    int index = getIndexOf(addr);
    if (index == -1) {
        PRINTF("insertKeyBlock: Ip nicht gefunden\n");
        return -1;
    }

    PRINTF("Daten vor Insert KeyBlock:\n");
    PRINTSESSION(index);
    KeyBlock_t *ck = (KeyBlock_t *) RES_KEY_BLOCK_LIST;
    nvm_setVar(key_block, (fpoint_t) &ck[(2 * index) + 1], sizeof(KeyBlock_t));
    PRINTF("Daten nach Insert KeyBlock:\n");
    PRINTSESSION(index);
    return 0;
}

fpoint_t getKeyBlock(uip_ipaddr_t *addr, uint16_t epoch, int update) {
    if (epoch == 0) return 0;

    int index = getIndexOf(addr);
    if (index == -1) return 0;

    if (update) checkEpochIncrease(index, epoch);

    Session_t *s = (Session_t *) RES_SESSION_LIST;
    KeyBlock_t *kb = (KeyBlock_t *) RES_KEY_BLOCK_LIST;
    if (nvm_cmp(&epoch, (fpoint_t) &s[index].epoch, 2) == 0) {
        return (fpoint_t) &kb[2 * index];
    }
    epoch--;
    if (nvm_cmp(&epoch, (fpoint_t) &s[index].epoch, 2) == 0) {
        return (fpoint_t) &kb[(2 * index) + 1];
    }

    return 0;
}

/* Private Funktionen ------------------------------------------------------ */

static int getIndexOf(uip_ipaddr_t *addr) {
    Session_t *s = (Session_t *) RES_SESSION_LIST;
    uint16_t valid = (addr == NULL ? 0 : 1);

    unsigned int i;
    for (i = 0; i < SESSION_LIST_LEN; i++) {
        if (nvm_cmp(&valid, (fpoint_t) &s[i].valid, 2) == 0) {
            if (addr == NULL) return i;
            if (nvm_cmp(addr, (fpoint_t) &s[i].addr, sizeof(uip_ipaddr_t)) == 0) {
                return i;
            }
        }
    }
    return -1;
}

__attribute__((always_inline)) static void checkEpochIncrease(unsigned int index, uint16_t epoch) {
    epoch--;
    Session_t *s = (Session_t *) RES_SESSION_LIST;

    if (nvm_cmp(&epoch, (fpoint_t) &s[index].epoch, 2) == 0) {
        PRINTF("Daten vor Epoch-Increase:\n");
        PRINTSESSION(index);

        epoch++;
        nvm_setVar(&epoch, (fpoint_t) &s[index].epoch, 2);
        
        uint8_t buf[2 * sizeof(KeyBlock_t)];
        KeyBlock_t *kb = (KeyBlock_t *) RES_KEY_BLOCK_LIST;
        nvm_getVar(buf, (fpoint_t) &kb[(2 * index) + 1], sizeof(KeyBlock_t));
        memset(buf + sizeof(KeyBlock_t), 0, sizeof(KeyBlock_t));
        nvm_setVar(buf, (fpoint_t) &kb[2 * index], 2 * sizeof(KeyBlock_t));

        seq_num_r[index] = 1;
        seq_num_w[index] = 1;

        PRINTF("Daten nach Epoch-Increase:\n");
        PRINTSESSION(index);

        // TODO aktivieren: newPSK();
    }
}
