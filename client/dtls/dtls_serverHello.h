/* __DTLS_SERVERHELLO_H__ */
#ifndef __DTLS_SERVERHELLO_H__
#define __DTLS_SERVERHELLO_H__

#include <stdint.h>

#include "dtls_clientHello.h"

typedef struct {
    uint8_t len;
    uint8_t session_id[8];
} __attribute__ ((packed)) SessionID;

// Schon in Network Byte Order hinterlegt
typedef enum {
    TLS_ECDH_anon_WITH_AES_128_CCM = 0x01ff,
    TLS_ECDH_anon_WITH_AES_256_CCM = 0x02ff,
    TLS_ECDH_anon_WITH_AES_128_CCM_8 = 0x03ff,
    TLS_ECDH_anon_WITH_AES_256_CCM_8 = 0x04ff
    // max = 0xffff
} __attribute__ ((packed)) CipherSuite;

typedef enum {
    null = 0,
    // max = 255
} __attribute__ ((packed)) CompressionMethod;

typedef struct {
    ProtocolVersion server_version;
    Random random;
    SessionID session_id;
    CipherSuite cipher_suite;
    CompressionMethod compression_method;
    uint8_t extensions[0];
} __attribute__ ((packed)) ServerHello_t;

#endif /* __DTLS_SERVERHELLO_H__ */
