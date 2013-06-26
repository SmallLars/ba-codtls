#include "er-coap-13-dtls.h"

#include <string.h>

#include "er-coap-13-dtls-ccm.h"
#include "er-coap-13-dtls-random.h"

CoapData_t dtls_parse_message(DTLSRecord_t *record) {
  // TODO Versionprüfung
  //   printf("Version major: %u\n", record->version.major);
  //   printf("Version minor: %u\n", record->version.minor);

  record->length = uip_ntohs(record->length);

  printf("Type: %u\n", record->type);
  printf("Länge: %u\n", record->length);

  CCMData_t *ccmdata = (CCMData_t*) record->payload;

  uint8_t oldCode[MAC_LEN];
  memcpy(oldCode, getMAC(ccmdata, record->length), MAC_LEN);

  crypt((uint8_t *) "ABCDEFGHIJKLMNOP", ccmdata, record->length, 0);
  crypt((uint8_t *) "ABCDEFGHIJKLMNOP", ccmdata, record->length, 1);

  uint32_t check = memcmp(oldCode, getMAC(ccmdata, record->length), MAC_LEN);
  if (check) printf("DTLS-MAC fehler. Paket ungültig.\n");
  CoapData_t coapdata = { check == 0 ? 1 : 0, ccmdata->ccm_ciphered, record->length - sizeof(CCMData_t) - MAC_LEN };
  return coapdata;
}

void dtls_send_message(struct uip_udp_conn *conn, const void *data, int len) {
  uint16_t payload_length = sizeof(CCMData_t) + len + MAC_LEN;

  uint8_t packet[sizeof(DTLSRecord_t) + payload_length];
  DTLSRecord_t *record = (DTLSRecord_t *) packet;
  record->type = application_data;
  record->version.major = 3;
  record->version.minor = 3;
  record->length = uip_htons(payload_length);

  CCMData_t *ccmdata = (CCMData_t*) record->payload;

  random_x(ccmdata->nonce_explicit, NONCE_LEN);
  memcpy(ccmdata->ccm_ciphered, data, len);

  crypt((uint8_t *) "ABCDEFGHIJKLMNOP", ccmdata, payload_length, 0);

  uip_udp_packet_send(conn, packet, sizeof(DTLSRecord_t) + payload_length);
}
