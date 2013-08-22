/* __ER_DTLS_13_DATA_H__ */
#ifndef __ER_DTLS_13_DATA_H__
#define __ER_DTLS_13_DATA_H__

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint8_t ip[16];
    uint8_t session[8];
    uint8_t epoch;
    uint8_t pending;
    uint32_t private_key[8];
}  __attribute__ ((packed)) ClientInfo_t;

typedef struct {
    uint8_t index;
    uint8_t epoch;
    union {
        uint8_t key_block[40];
        struct {
//            uint8_t client_MAC[0];
//            uint8_t server_MAC[0];
            uint8_t client_key[16];
            uint8_t server_key[16];
            uint8_t client_IV[4];
            uint8_t server_IV[4];
        } write;
    };
}  __attribute__ ((packed)) ClientKey_t;

int8_t insertClient(ClientInfo_t *clientInfo);

int8_t insertKey(ClientKey_t *clientkey);

int8_t getEpoch(uint8_t *ip);

int8_t getPrivateKey(uint32_t *key, uint8_t *ip);

ClientKey_t *getKey(uint8_t *ip, uint8_t epoch);

int8_t changeIfPending(uint8_t *ip);

int8_t updateIp(uint8_t *session, uint8_t *ip);

#endif /* __ER_DTLS_13_DATA_H__ */
