/* __ER_DTLS_13_RESOURCE_H__ */
#ifndef __ER_DTLS_13_RESOURCE_H__
#define __ER_DTLS_13_RESOURCE_H__

#include <stdint.h>

#include "erbium.h"

typedef enum {
    hello_request = 0,
    client_hello = 1,
    server_hello = 2,
    hello_verify_request = 3, 
    certificate = 11,
    server_key_exchange = 12,
    certificate_request = 13,
    server_hello_done = 14,
    certificate_verify = 15,
    client_key_exchange = 16,
    finished = 20,
    c_change_cipher_spec = 32,
    c_alert = 33,
    // max = 63
} __attribute__ ((packed)) ContentType;

typedef enum {
    con_length_0 = 0,
    con_length_8_bit = 1,
    con_length_16_bit = 2,
    con_length_24_bit = 3
} ContentLength;

typedef struct {
    ContentLength len:2;
    ContentType type:6;
    uint8_t payload[0];
} __attribute__ ((packed)) DTLSContent_t;

/* Handshake Datenstrukturen ----------------------------------------------- */

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

/*
struct {
    ProtocolVersion client_version;
    Random random;
    opaque cookie<0..2^8-1>;
    CipherSuite cipher_suites<2..2^16-2>;
    CompressionMethod compression_methods<1..2^8-1>;
    select (extensions_present) {
        case false:
            struct {};
        case true:
            Extension extensions<0..2^16-1>;
    };
} ClientHello;
*/
typedef struct {
    ProtocolVersion server_version;
    uint8_t cookie_len;
    uint8_t cookie[0];
} __attribute__ ((packed)) HelloVerifyRequest_t;

typedef struct {
    uint8_t len;
    uint8_t session_id[8];
} __attribute__ ((packed)) SessionID;

typedef enum {
    TLS_PSK_ECDH_WITH_AES_128_CCM_8 = 0xFF01
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

typedef enum {
    explicit_prime = 1,
    explicit_char2 = 2,
    named_curve = 3
    // reserved(248..255)
    // max = 255
} __attribute__ ((packed)) ECCurveType;

typedef enum {
    sect163k1 = 0x0001,
    sect163r1 = 0x0002,
    sect163r2 = 0x0003,
    sect193r1 = 0x0004,
    sect193r2 = 0x0005,
    sect233k1 = 0x0006,
    sect233r1 = 0x0007,
    sect239k1 = 0x0008,
    sect283k1 = 0x0009,
    sect283r1 = 0x0010,
    sect409k1 = 0x0011,
    sect409r1 = 0x0012,
    sect571k1 = 0x0013,
    sect571r1 = 0x0014,
    secp160k1 = 0x0015,
    secp160r1 = 0x0016,
    secp160r2 = 0x0017,
    secp192k1 = 0x0018,
    secp192r1 = 0x0019,
    secp224k1 = 0x0020,
    secp224r1 = 0x0021,
    secp256k1 = 0x0022,
    secp256r1 = 0x0023,
    secp384r1 = 0x0024,
    secp521r1 = 0x0025,
    // reserved = 0xFE00..0xFEFF
    arbitrary_explicit_prime_curves = 0xFF01,
    arbitrary_explicit_char2_curves = 0xFF02,
    // max = 0xFFFF
} __attribute__ ((packed)) NamedCurve;

typedef struct {
    ECCurveType curve_type;
    NamedCurve namedcurve;
} __attribute__ ((packed)) ECParameters;

typedef enum {
    compressed = 2,
    uncompressed = 4,
    hybrid = 6
} __attribute__ ((packed)) PointType;

typedef struct {
    uint8_t len;     // 0x41 = 65 Lang
    PointType type;  // 0x04 uncompressed
    uint32_t x[8];
    uint32_t y[8];
} __attribute__ ((packed)) ECPoint;

typedef struct { // 2 + 16 + 3 + 66 = 87 Byte groß
    uint16_t pskHint_len;   // 16
    uint8_t pskHint[16];
    ECParameters curve_params;
    ECPoint public_key;
} __attribute__ ((packed)) KeyExchange_t;

#endif /* __ER_DTLS_13_RESOURCE_H__ */
