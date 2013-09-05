/* __ER_DTLS_13_DATA_H__ */
#ifndef __ER_DTLS_13_DATA_H__
#define __ER_DTLS_13_DATA_H__

#include <stddef.h>
#include <stdint.h>

typedef struct { // 16 + 8 + 2 + 32 = 58
    uint8_t ip[16];
    uint8_t session[8];
    uint16_t epoch;
    uint32_t private_key[8];
}  __attribute__ ((packed)) Session_t;

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
}  __attribute__ ((packed)) KeyBlock_t;

#define KEY_BLOCK_CLIENT_KEY  0
#define KEY_BLOCK_SERVER_KEY 16
#define KEY_BLOCK_CLIENT_IV  32
#define KEY_BLOCK_SERVER_IV  36

typedef enum {
    session_id = 0,
    session_epoch = 1,
    session_key = 2,
    session_num_write = 3
} SessionDataType;

// ----------------------------------------------------------------------------

int8_t createSession(uint32_t *buf, uint8_t ip[16]);

int8_t getSessionData(uint8_t *dst, uint8_t ip[16], SessionDataType type);

// ----------------------------------------------------------------------------

int8_t insertKeyBlock(uint8_t ip[16], KeyBlock_t *key_block);

uint32_t getKeyBlock(uint8_t ip[16], uint16_t epoch, uint8_t update);

#endif /* __ER_DTLS_13_DATA_H__ */
