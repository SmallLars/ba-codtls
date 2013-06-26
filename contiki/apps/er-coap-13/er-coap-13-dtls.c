#include "er-coap-13-dtls.h"

#include <string.h>

#include "er-coap-13-dtls-ccm.h"
#include "er-coap-13-dtls-random.h"

#define KEY (uint8_t *) "ABCDEFGHIJKLMNOP"

CoapData_t dtls_parse_message(DTLSRecord_t *record) {
  // TODO Versionprüfung
  //   printf("Version major: %u\n", record->version.major);
  //   printf("Version minor: %u\n", record->version.minor);

  record->length = uip_ntohs(record->length);

  CoapData_t coapdata = {0, NULL, 0};
  switch (record->type) {
    case alert:
      printf("Record-Type: Alert.\n");
      break;
    case handshake:
      printf("Record-Type: Handshake.\n");
      coapdata.valid = 1;
      coapdata.data = record->payload;
      coapdata.data_len = record->length;
      break;
    case change_cipher_spec:
      printf("Record-Type: Change Cipher Spec.\n");
      break;
    case application_data:
      printf("Record-Type: Application Data.\n");
      CCMData_t *ccmdata = (CCMData_t*) record->payload;

      uint8_t oldCode[MAC_LEN];
      memcpy(oldCode, getMAC(ccmdata, record->length), MAC_LEN);

      crypt(KEY, ccmdata, record->length, 0);
      crypt(KEY, ccmdata, record->length, 1);

      uint32_t check = memcmp(oldCode, getMAC(ccmdata, record->length), MAC_LEN);
      if (check) printf("DTLS-MAC fehler. Paket ungültig.\n");
      coapdata.valid = (check == 0 ? 1 : 0);
      coapdata.data = ccmdata->ccm_ciphered;
      coapdata.data_len = record->length - sizeof(CCMData_t) - MAC_LEN;
      break;
    default:
      printf("Unbekannter Record-Type.\n");
  }
  return coapdata;
}

void dtls_send_message(struct uip_udp_conn *conn, const void *data, int len) {
  if (1) {
    // Klartext für Handshake
    uint8_t packet[sizeof(DTLSRecord_t) + len];
    DTLSRecord_t *record = (DTLSRecord_t *) packet;
    record->type = handshake;
    record->version.major = 3;
    record->version.minor = 3;
    record->length = uip_htons(len);

    memcpy(record->payload, data, len);

    uip_udp_packet_send(conn, packet, sizeof(DTLSRecord_t) + len);
  } else {
    // Geheimtext für Application Data
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

    crypt(KEY, ccmdata, payload_length, 0);

    uip_udp_packet_send(conn, packet, sizeof(DTLSRecord_t) + payload_length);
  }
}
