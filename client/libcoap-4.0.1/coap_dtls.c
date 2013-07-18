#include "coap_dtls.h"

// #include <stdlib.h>
// #include <stdio.h>
// #include <string.h>
// #include <netinet/in.h>
// #include <time.h>

#include "random.h"
#include "coap_ccm.h"
#include "coap_client.h"

#define KEY (uint8_t *) "ABCDEFGHIJKLMNOP"

ssize_t dtls_sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen) {
  // Bei Bedarf verschlüsseln
  if (0) {
    uint8_t payload_length = sizeof(CCMData_t) + len + MAC_LEN;

    DTLSRecord_t *record = (DTLSRecord_t *) malloc(sizeof(DTLSRecord_t) + payload_length);
    memset(record, 0, sizeof(DTLSRecord_t) + payload_length);
    record->protocol = application_data;
    record->version= dtls_1_2;
    record->epoch = 0;

    CCMData_t *ccmdata = (CCMData_t*) record->payload;

    random_x(ccmdata->nonce_explicit, NONCE_LEN);
    memcpy(ccmdata->ccm_ciphered, buf, len);

    encrypt(ccmdata, KEY, payload_length);

    ssize_t send = sendto(sockfd, record, sizeof(DTLSRecord_t) + payload_length, flags, dest_addr, addrlen);
    send -= (sizeof(DTLSRecord_t) + sizeof(CCMData_t) + MAC_LEN);

    free(record);

    return send;
  } else {
    DTLSRecord_t *record = (DTLSRecord_t *) malloc(sizeof(DTLSRecord_t) + len);
    memset(record, 0, sizeof(DTLSRecord_t) + len);
    record->protocol = application_data;
    record->version= dtls_1_2;
    record->epoch = 0;

    memcpy(record->payload, buf, len);

    ssize_t send = sendto(sockfd, record, sizeof(DTLSRecord_t) + len, flags, dest_addr, addrlen);
    send -= sizeof(DTLSRecord_t);

    free(record);

    return send;
  }
}

ssize_t dtls_recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen) {
  size_t size = recvfrom(sockfd, buf, len, flags, src_addr, addrlen);

  DTLSRecord_t *record = (DTLSRecord_t *) malloc(size);
  memcpy(record, buf, size);

  ssize_t db_len;

  // TODO Versionprüfung
  //   printf("Version: %u\n", record->version);

  // Bei Bedarf entschlüsseln
  if (record->epoch) {
    CCMData_t *ccmdata = (CCMData_t*) record->payload;

    uint8_t oldCode[MAC_LEN];
    memcpy(oldCode, getMAC(ccmdata, size - sizeof(DTLSRecord_t)), MAC_LEN);

    decrypt(ccmdata, KEY, size - sizeof(DTLSRecord_t));

    uint32_t check = memcmp(oldCode, getMAC(ccmdata, size - sizeof(DTLSRecord_t)), MAC_LEN);
    if (check) printf("DTLS-MAC fehler. Paket ungültig.\n");
    db_len = (check == 0 ? size - sizeof(DTLSRecord_t) - sizeof(CCMData_t) - MAC_LEN : 0);
    memcpy(buf, ccmdata->ccm_ciphered, db_len);
  } else {
    memcpy(buf, record->payload, size - sizeof(DTLSRecord_t));
    db_len = size - sizeof(DTLSRecord_t);
  }

  if (record->protocol == alert) {
    printf("Alert erhalten.\n");
    // TODO Alert-Auswertung
    db_len = 0;
  }

  free(record);

  return db_len;
}
