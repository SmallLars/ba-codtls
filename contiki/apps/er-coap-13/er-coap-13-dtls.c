#include "er-coap-13-dtls.h"

#include <string.h>

#include "er-coap-13-dtls-data.h"
#include "er-coap-13-dtls-ccm.h"
#include "er-coap-13-dtls-random.h"

/* Private Funktionsprototypen --------------------------------------------- */


/* Öffentliche Funktionen -------------------------------------------------- */

void dtls_parse_message(uint8_t *ip, DTLSRecord_t *record, CoapData_t *coapdata) {
  // TODO Versionprüfung
  //   printf("Version: %u\n", record->version);

  // Bei Bedarf entschlüsseln
  uint8_t key[16];
  if (getKey(key, ip, record->epoch) == 0) {
    CCMData_t *ccmdata = (CCMData_t*) record->payload;

    uint8_t oldCode[MAC_LEN];
    memcpy(oldCode, getMAC(ccmdata, record->length), MAC_LEN);

    crypt(key, ccmdata, record->length, 0);
    crypt(key, ccmdata, record->length, 1);

    uint32_t check = memcmp(oldCode, getMAC(ccmdata, record->length), MAC_LEN);
    if (check) printf("DTLS-MAC fehler. Paket ungültig.\n");
    coapdata->valid = (check == 0 ? 1 : 0);
    coapdata->data = ccmdata->ccm_ciphered;
    coapdata->data_len = record->length - sizeof(CCMData_t) - MAC_LEN;
  } else {
    coapdata->valid = 1;
    coapdata->data = record->payload;
    coapdata->data_len = record->length;
  }

  if (record->protocol == 0) {
    printf("Alert erhalten.\n");
    // TODO Alert-Auswertung
    coapdata->valid = 0;
  }
}

void dtls_send_message(struct uip_udp_conn *conn, const void *data, int len) {
  // Bei Bedarf verschlüsseln
  int8_t epoch = getEpoch(conn->ripaddr.u8);
  uint8_t key[16];
  if (getKey(key, conn->ripaddr.u8, epoch) == 0) {
    uint8_t payload_length = sizeof(CCMData_t) + len + MAC_LEN;

    uint8_t packet[sizeof(DTLSRecord_t) + payload_length];
    DTLSRecord_t *record = (DTLSRecord_t *) packet;
    record->protocol = 1;
    record->version= 2;
    record->epoch = 0;
    record->len = 1;
    record->length = payload_length;

    CCMData_t *ccmdata = (CCMData_t*) record->payload;

    random_x(ccmdata->nonce_explicit, NONCE_LEN);
    memcpy(ccmdata->ccm_ciphered, data, len);

    crypt(key, ccmdata, payload_length, 0);

    uip_udp_packet_send(conn, packet, sizeof(DTLSRecord_t) + payload_length);
  } else {
    uint8_t packet[sizeof(DTLSRecord_t) + len];
    DTLSRecord_t *record = (DTLSRecord_t *) packet;
    record->protocol = 1;
    record->version= 2;
    record->epoch = 0;
    record->len = 1;
    record->length = len;

    memcpy(record->payload, data, len);

    uip_udp_packet_send(conn, packet, sizeof(DTLSRecord_t) + len);
  }
}

/* Private Funktionen ------------------------------------------------------ */
