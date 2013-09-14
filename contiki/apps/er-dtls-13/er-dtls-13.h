/* __ER_DTLS_13_H__ */
#ifndef __ER_DTLS_13_H__
#define __ER_DTLS_13_H__

#include <stdint.h>

#include "contiki-net.h"

/* Record Layer Datenstrukturen -------------------------------------------- */

typedef enum {
    type_8_bit = 0,
    alert = 1,
    handshake = 2,
    application_data = 3
} RecordType;

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
    snr_0 = 0,
    snr_8_bit = 1,
    snr_16_bit = 2,
    snr_24_bit = 3,
    snr_32_bit = 4,
    snr_40_bit = 5,
    snr_48_bit = 6,
    snr_implicit = 7 // number of previous record in the datagram + 1
} SequenceNumber;

typedef enum {
    rec_length_0 = 0,
    rec_length_8_bit = 1,
    rec_length_16_bit = 2,
    rec_length_implicit = 3 // datagram size - sizeof(DTLSRecord_t) or last datagram in record
} RecordLength;

typedef struct {
    Epoch epoch:3;
    Version version:2;
    RecordType type:2;
    uint8_t u1:1; // unbenutzt
    RecordLength length:2;
    SequenceNumber snr:3;
    uint8_t u2:3; // unbenutzt
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
  * \param    record     Zeiger auf die auszuwertenden Daten
  * \param    len        Länge der auszuwertenden Daten
  * \param    coapdata   Zeiger auf die Struktur in der das Ergebnis abgelegt wird
  */
void dtls_parse_message(DTLSRecord_t *record, uint8_t len, CoapData_t *coapdata);

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

#endif /* __ER_DTLS_13_H__ */
