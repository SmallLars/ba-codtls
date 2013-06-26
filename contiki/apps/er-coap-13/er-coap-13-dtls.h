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

CoapData_t dtls_parse_message(DTLSRecord_t *data);

void dtls_send_message(struct uip_udp_conn *c, const void *data, int len);

#endif /* __ER_COAP_13_DTLS_H__ */
