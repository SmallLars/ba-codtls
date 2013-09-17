/* __DTLS_CLIENTHELLO_H__ */
#ifndef __DTLS_CLIENTHELLO_H__
#define __DTLS_CLIENTHELLO_H__

#include <stddef.h>
#include <stdint.h>
#include <time.h>

typedef struct {
    uint8_t major;
    uint8_t minor;
} __attribute__ ((packed)) ProtocolVersion;

typedef struct {
    uint32_t gmt_unix_time;
    uint8_t random_bytes[28];
} __attribute__ ((packed)) Random;

typedef struct {
    ProtocolVersion client_version;
    Random random;
    uint8_t data[0];
} __attribute__ ((packed)) ClientHello_t;

typedef struct {
    ProtocolVersion server_version;
    uint8_t cookie_len;
    uint8_t cookie[0];
} __attribute__ ((packed)) HelloVerifyRequest_t;

size_t makeClientHello(uint8_t *target, time_t time, uint8_t *random, uint8_t *cookie, uint8_t cookie_len);

#endif /* __DTLS_CLIENTHELLO_H__ */
