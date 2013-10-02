/* __DTLS_DATA_H__ */
#ifndef __DTLS_DATA_H__
#define __DTLS_DATA_H__

#include <stdint.h>

typedef union {
    uint8_t key_block[40];
    struct {
//      uint8_t client_MAC[0];
//      uint8_t server_MAC[0];
        uint8_t client_key[16];
        uint8_t server_key[16];
        uint8_t client_IV[4];
        uint8_t server_IV[4];
    } write;
} __attribute__ ((packed)) KeyBlock_t;

#define KEY_BLOCK_CLIENT_KEY  0
#define KEY_BLOCK_SERVER_KEY 16
#define KEY_BLOCK_CLIENT_IV  32
#define KEY_BLOCK_SERVER_IV  36

typedef struct { // 16 + 8 + 2 + 32 = 58
    uint8_t ip[16];
    uint8_t id[8];
    uint16_t epoch;
    uint32_t seq_num_w;
    KeyBlock_t key_block;
    KeyBlock_t key_block_new;
} __attribute__ ((packed)) Session_t;

/*---------------------------------------------------------------------------*/

int getPSK(uint8_t dst[16], uint8_t uuid[16]);

/*---------------------------------------------------------------------------*/

void createSession(uint8_t ip[16], uint8_t id[8]);

uint16_t getEpoch(uint8_t ip[16]);

uint32_t getSeqNum(uint8_t ip[16]);

/*---------------------------------------------------------------------------*/

int insertKeyBlock(uint8_t ip[16], KeyBlock_t *key_block);

uint8_t *getKeyBlock(uint8_t ip[16], uint16_t epoch);

void increaseEpoch(uint8_t ip[16]);

#endif /* __DTLS_DATA_H__ */


