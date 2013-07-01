#include "coap_dtls.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>

#include "coap_ccm.h"
#include "coap_random.h"
#include "coap_client.h"

#define KEY (uint8_t *) "ABCDEFGHIJKLMNOP"

void dtls_handshake(struct in6_addr *ip) {
  uint8_t clientHello[512];
  clientHello[0] = 3;            // ProtocolVersion major
  clientHello[1] = 3;            // ProtocolVersion minor
  clientHello[2] = 0x51;         // Random Time
  clientHello[3] = 0xcc;         // Random Time
  clientHello[4] = 0x2d;         // Random Time
  clientHello[5] = 0x77;         // Random Time
  random_x(clientHello + 6, 28); // Random Wert
  clientHello[34] = 0;           // Länge von Session ID ist 0
  clientHello[35] = 0;           // Länge von Cookie ist 0

  char buffer[512];
  memset(buffer, 0, 512);
  coap_request(ip, COAP_REQUEST_POST, "dtls", buffer);
  printf("Handshake: %s\n", buffer);


/*
  typedef struct {
    ProtocolVersion client_version
    Random random
    Data8 session_id
    Data8 cookie
    Data16 cipher_suites
    Data8 compression_methods
    Data16 extensions                 (elliptic_curves = 0x0A00    und    ec_point_formats = 0x0B00)
  } __attribute__ ((packed)) ClientHello;
*/

}

ssize_t dtls_sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen) {
  if (1) {
    // Klartext für Handshake
    DTLSRecord_t *record = (DTLSRecord_t *) malloc(sizeof(DTLSRecord_t) + len);
    record->type = handshake;
    record->version.major = 3;
    record->version.minor = 3;
    record->length = htons(len);

    memcpy(record->payload, buf, len);

    ssize_t send = sendto(sockfd, record, sizeof(DTLSRecord_t) + len, flags, dest_addr, addrlen);
    send -= sizeof(DTLSRecord_t);

    free(record);

    return send;
  } else {
    // Geheimtext für Application Data
    uint16_t payload_length = sizeof(CCMData_t) + len + MAC_LEN;

    DTLSRecord_t *record = (DTLSRecord_t *) malloc(sizeof(DTLSRecord_t) + payload_length);
    record->type = application_data;
    record->version.major = 3;
    record->version.minor = 3;
    record->length = htons(payload_length);

    CCMData_t *ccmdata = (CCMData_t*) record->payload;

    random_x(ccmdata->nonce_explicit, NONCE_LEN);
    memcpy(ccmdata->ccm_ciphered, buf, len);

    encrypt(ccmdata, KEY, payload_length);

    ssize_t send = sendto(sockfd, record, sizeof(DTLSRecord_t) + payload_length, flags, dest_addr, addrlen);
    send -= (sizeof(DTLSRecord_t) + sizeof(CCMData_t) + MAC_LEN);

    free(record);

    return send;
  }
}

ssize_t dtls_recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen) {
  size_t size = recvfrom(sockfd, buf, len, flags, src_addr, addrlen);

  DTLSRecord_t *record = (DTLSRecord_t *) malloc(size);
  memcpy(record, buf, size);

  // TODO Versionprüfung
  //   printf("Version major: %u\n", record->version.major);
  //   printf("Version minor: %u\n", record->version.minor);

  record->length = ntohs(record->length);

  switch (record->type) {
    case alert:
      printf("Record-Type: Alert.\n");
      return 0;
    case handshake:
      printf("Record-Type: Handshake.\n");
      memcpy(buf, record->payload, record->length);
      return record->length;
    case change_cipher_spec:
      printf("Record-Type: Change Cipher Spec.\n");
      return 0;
    case application_data:
      printf("Record-Type: Application Data.\n");
      CCMData_t *ccmdata = (CCMData_t*) record->payload;

      uint8_t oldCode[MAC_LEN];
      memcpy(oldCode, getMAC(ccmdata, record->length), MAC_LEN);

      decrypt(ccmdata, KEY, record->length);

      uint32_t check = memcmp(oldCode, getMAC(ccmdata, record->length), MAC_LEN);
      if (check) printf("DTLS-MAC fehler. Paket ungültig.\n");
      ssize_t db_len = (check == 0 ? record->length - sizeof(CCMData_t) - MAC_LEN : 0);
      memcpy(buf, ccmdata->ccm_ciphered, db_len);

      free(record);

      return db_len;
    default:
      printf("Unbekannter Record-Type.\n");
      return 0;
  }
}
