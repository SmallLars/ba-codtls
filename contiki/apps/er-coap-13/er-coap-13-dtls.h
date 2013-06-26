/* __ER_COAP_13_DTLS_H__ */
#ifndef __ER_COAP_13_DTLS_H__
#define __ER_COAP_13_DTLS_H__

#include <stdint.h>

#include "contiki-net.h"

typedef struct {
  uint8_t major;
  uint8_t minor;
} __attribute__ ((packed)) ProtocolVersion;

typedef enum {
  change_cipher_spec = 20,
  alert = 21,
  handshake = 22,
  application_data = 23,
  empty = 255
} __attribute__ ((packed)) ContentType;

typedef struct {
  ContentType type;
  ProtocolVersion version;
  uint16_t length;
  uint8_t payload[0];
} __attribute__ ((packed)) DTLSRecord_t;

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
