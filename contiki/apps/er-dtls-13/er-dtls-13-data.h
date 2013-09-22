/* __ER_DTLS_13_DATA_H__ */
#ifndef __ER_DTLS_13_DATA_H__
#define __ER_DTLS_13_DATA_H__

#include <stddef.h>
#include <stdint.h>

#include "flash-store.h"
#include "contiki-net.h"

typedef struct { // 16 + 8 + 2 + 2 + 32 = 60
    uip_ipaddr_t addr;
    uint8_t session[8];
    uint16_t epoch;
    uint16_t valid;    // Platz ist frei oder wird benutzt
    uint32_t private_key[8];
}  __attribute__ ((packed)) Session_t;
// valid ist 16 Bit groß und steht nicht vorne, um eine
// Ausrichtung der Werte an 32-bit-Blöcken sicherzustellen

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

int createSession(uint32_t *buf, uip_ipaddr_t *addr);

int getSessionData(uint8_t *dst, uip_ipaddr_t *addr, SessionDataType type);

int checkReadNum(uip_ipaddr_t *addr, uint8_t seq_num[6]);

int deleteSession(uip_ipaddr_t *addr);

// ----------------------------------------------------------------------------

int insertKeyBlock(uip_ipaddr_t *addr, KeyBlock_t *key_block);

fpoint_t getKeyBlock(uip_ipaddr_t *addr, uint16_t epoch, int update);

#endif /* __ER_DTLS_13_DATA_H__ */
