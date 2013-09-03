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
    ContentType type:6;
    ContentLength len:2;
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
    SessionID session_id;
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

typedef enum {
    explicit_prime = 1,
    explicit_char2 = 2,
    named_curve = 3
    // reserved(248..255)
    // max = 255
} __attribute__ ((packed)) ECCurveType;

// Schon in Network Byte Order hinterlegt
typedef enum {
    sect163k1 = 0x0100,
    sect163r1 = 0x0200,
    sect163r2 = 0x0300,
    sect193r1 = 0x0400,
    sect193r2 = 0x0500,
    sect233k1 = 0x0600,
    sect233r1 = 0x0700,
    sect239k1 = 0x0800,
    sect283k1 = 0x0900,
    sect283r1 = 0x1000,
    sect409k1 = 0x1100,
    sect409r1 = 0x1200,
    sect571k1 = 0x1300,
    sect571r1 = 0x1400,
    secp160k1 = 0x1500,
    secp160r1 = 0x1600,
    secp160r2 = 0x1700,
    secp192k1 = 0x1800,
    secp192r1 = 0x1900,
    secp224k1 = 0x2000,
    secp224r1 = 0x2100,
    secp256k1 = 0x2200,
    secp256r1 = 0x2300,
    secp384r1 = 0x2400,
    secp521r1 = 0x2500,
    // reserved = 0x00fe..0xfffe     0xAABB AA zählt hoch wegen NBO
    arbitrary_explicit_prime_curves = 0x01ff,
    arbitrary_explicit_char2_curves = 0x02ff,
    // max = 0xffff
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
