/* __ER_COAP_13_DTLS_H__ */
#ifndef __ER_COAP_13_DTLS_H__
#define __ER_COAP_13_DTLS_H__

#include <stdint.h>

#include "contiki-net.h"

/* Record Layer Datenstrukturen -------------------------------------------- */

typedef enum {
  none = 0,
  coap = 1
} Protocol;

typedef enum {
  dtls_1_0 = 0,
  version_16_bit = 1,
  dtls_1_2 = 2,
  version_future_use = 3
} Version;

typedef enum {
  epoch_0 = 0,
  epoch_1 = 1,
  epoch_2 = 2,
  epoch_3 = 3,
  epoch_4 = 4,
  epoch_8_bit = 5,
  epoch_16_bit = 6,
  epoch_implicit = 7 // same as previous record in the datagram
} Epoch;

typedef enum {
  length_0 = 0,
  length_8_bit = 1,
  length_16_bit = 2,
  length_48_bit = 3
} Length;

typedef struct {
  Protocol protocol:1;    
  Version version:2;
  Epoch epoch:3;
  Length len:2;
  uint8_t length;
  uint8_t payload[0];
} __attribute__ ((packed)) DTLSRecord_t;

/* ------------------------------------------------------------------------- */

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
  change_cipher_spec = 32,
  alert = 33,
  handshake = 34
  // max = 63
} __attribute__ ((packed)) ContentType;

typedef struct {
  ContentType type:6;
  Length len:2;
  uint8_t length;
  uint8_t payload[0];
} __attribute__ ((packed)) Content_t;

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
} __attribute__ ((packed))  ECCurveType;

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
  uint8_t x[32];
  uint8_t y[32];
} __attribute__ ((packed)) ECPoint;

typedef struct {
  ECParameters curve_params;
  ECPoint public_key;
//  Signature       signed_params;  // fehlt wegen ECDH_anon -> SignatureAlgorithm = anonymous = 0
} __attribute__ ((packed)) ServerKeyExchange;

/* ------------------------------------------------------------------------- */

typedef struct {
  uint8_t valid;
  uint8_t *data;
  uint8_t data_len;
} CoapData_t;

/**
  * \brief    Auswertung eines DTLS-Records
  *
  *           Wertet den übergebenen DTLS-Record aus und hinterlegt den Pointer
  *           und die Länge der enthaltenen Daten in coapdata ab. Falls Daten
  *           enthalten sind wird valid ind coapdata auf 1 gesetzt; Ansonsten
  *           bleibt valid unverändert.
  *
  * \param    ip         Zeiger auf die 16 Byte lange IP-Adresse des Senders
  * \param    record     Zeiger auf die auszuwertenden Daten
  * \param    coapdata   Zeiger auf die Struktur in der das Ergebnis abgelegt wird
  */
void dtls_parse_message(uint8_t *ip, DTLSRecord_t *record, CoapData_t *coapdata);

/**
  * \brief    Datenversand über DTLS
  *
  *           Verpackt die Daten gemäß Zustand der Verbindung. Während des
  *           Handshakes werden die Daten im Klartext angehängt. Im Application-
  *           Data Mode werden die Daten per CCM verschlüsselt und angehangen.
  *
  * \param    conn   Zeiger auf die Verbindungsdaten von CoAP
  * \param    data   Zeiger auf die zu versendenden Daten
  * \param    len    Länge der zu versendenden Daten
  */
void dtls_send_message(struct uip_udp_conn *conn, const void *data, int len);

#endif /* __ER_COAP_13_DTLS_H__ */
