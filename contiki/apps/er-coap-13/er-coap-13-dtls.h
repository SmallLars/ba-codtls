/* __ER_COAP_13_DTLS_H__ */
#ifndef __ER_COAP_13_DTLS_H__
#define __ER_COAP_13_DTLS_H__

#include <stdint.h>

#include "contiki-net.h"

/* Record Layer Datenstrukturen -------------------------------------------- */

typedef struct {
  uint8_t major;
  uint8_t minor;
} __attribute__ ((packed)) ProtocolVersion;

typedef enum {
  change_cipher_spec = 20,
  alert = 21,
  handshake = 22,
  application_data = 23
  // max = 255
} __attribute__ ((packed)) ContentType;

typedef struct {
  ContentType type;
  ProtocolVersion version;
  uint16_t epoch;
  uint8_t sequence_number[3];
  uint16_t length;
  uint8_t payload[0];
} __attribute__ ((packed)) DTLSRecord_t;

/* Handshake Datenstrukturen ----------------------------------------------- */

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
  finished = 20
  // max = 255
} __attribute__ ((packed)) HandshakeType;

typedef struct {
  HandshakeType msg_type;
  uint8_t length[3];
  uint8_t payload[0];
} __attribute__ ((packed)) Handshake_t;

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

typedef enum {
  TLS_ECDH_anon_WITH_AES_128_CCM = 0xff01,
  TLS_ECDH_anon_WITH_AES_256_CCM = 0xff02,
  TLS_ECDH_anon_WITH_AES_128_CCM_8 = 0xff03,
  TLS_ECDH_anon_WITH_AES_256_CCM_8 = 0xff04
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

/* ------------------------------------------------------------------------- */

typedef struct {
  uint8_t valid;
  uint8_t *data;
  uint16_t data_len;
} CoapData_t;

/**
  * \brief    Auswertung eines DTLS-Records
  *
  *           Wertet den übergebenen DTLS-Record aus und hinterlegt den Pointer
  *           und die Länge der enthaltenen Daten in coapdata ab. Falls Daten
  *           enthalten sind wird valid ind coapdata auf 1 gesetzt; Ansonsten
  *           bleibt valid unverändert.
  *
  * \param    record     Zeiger auf die auszuwertenden Daten
  * \param    coapdata   Zeiger auf die Struktur in der das Ergebnis abgelegt wird
  */
void dtls_parse_message(DTLSRecord_t *record, CoapData_t *coapdata);

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
