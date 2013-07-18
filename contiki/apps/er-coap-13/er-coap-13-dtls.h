/* __ER_COAP_13_DTLS_H__ */
#ifndef __ER_COAP_13_DTLS_H__
#define __ER_COAP_13_DTLS_H__

#include <stdint.h>

#include "contiki-net.h"

/* Record Layer Datenstrukturen -------------------------------------------- */

typedef enum {
  alert = 0,
  handshake = 1,
  application_data = 2
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

typedef struct {
  Protocol protocol:2;
  Version version:2;
  Epoch epoch:3;
  uint8_t unused:1;
  uint8_t payload[0];
} __attribute__ ((packed)) DTLSRecord_t;

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
  *           enthalten sind wird valid in coapdata auf 1 gesetzt; Ansonsten
  *           bleibt valid unverändert.
  *
  * \param    ip         Zeiger auf die 16 Byte lange IP-Adresse des Senders
  * \param    record     Zeiger auf die auszuwertenden Daten
  * \param    coapdata   Zeiger auf die Struktur in der das Ergebnis abgelegt wird
  */
void dtls_parse_message(uint8_t *ip, DTLSRecord_t *record, uint8_t len, CoapData_t *coapdata);

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
void dtls_send_message(struct uip_udp_conn *conn, const void *data, uint8_t len);

#endif /* __ER_COAP_13_DTLS_H__ */
