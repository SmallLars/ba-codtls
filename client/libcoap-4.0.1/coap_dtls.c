#include "coap_dtls.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <time.h>

#include "coap_ccm.h"
#include "coap_random.h"
#include "coap_client.h"

#define KEY (uint8_t *) "ABCDEFGHIJKLMNOP"

uint8_t makeClientHello(uint8_t *target, time_t time, uint8_t *random, uint8_t *sessionID, uint8_t session_len, uint8_t *cookie, uint8_t cookie_len) {
  Handshake_t *handshake = (Handshake_t *) target;

  handshake->msg_type = client_hello;
  handshake->length[0] = 0;
  handshake->length[1] = 0;
  handshake->length[2] = 0;

  ClientHello_t *clientHello = (ClientHello_t *) handshake->payload;
  clientHello->client_version.major = 3;
  clientHello->client_version.minor = 3;
  clientHello->random.gmt_unix_time = htonl(time);
  memcpy(clientHello->random.random_bytes, random, 28);
  handshake->length[2] += sizeof(ClientHello_t);

  uint32_t data_index = 0;

  if (sessionID && session_len) {
    clientHello->data[data_index++] = session_len;
    memcpy(clientHello->data + data_index, sessionID, session_len);
    data_index += session_len;
  } else {
    clientHello->data[data_index++] = 0;
  }

  if (cookie && cookie_len) {
    clientHello->data[data_index++] = cookie_len;
    memcpy(clientHello->data + data_index, cookie, cookie_len);
    data_index += cookie_len;
  } else {
    clientHello->data[data_index++] = 0;
  }

  clientHello->data[data_index++] = 0x00;        // Länge der Cyphersuits
  clientHello->data[data_index++] = 0x02;        // Länge der Cyphersuits
  clientHello->data[data_index++] = 0xff;        // Cyphersuit: TLS_ECDH_anon_WITH_AES_128_CCM_8
  clientHello->data[data_index++] = 0x03;        // Cyphersuit: TLS_ECDH_anon_WITH_AES_128_CCM_8
  clientHello->data[data_index++] = 0x01;        // Länge der Compression Methods
  clientHello->data[data_index++] = 0x00;        // Keine Compression
  clientHello->data[data_index++] = 0x00;        // Länge der Extensions
  clientHello->data[data_index++] = 0x0e;        // Länge der Extensions
  clientHello->data[data_index++] = 0x00;        // Supported Elliptic Curves Extension
  clientHello->data[data_index++] = 0x0a;        // Supported Elliptic Curves Extension
  clientHello->data[data_index++] = 0x00;        // Länge der Supported Elliptic Curves Extension Daten
  clientHello->data[data_index++] = 0x04;        // Länge der Supported Elliptic Curves Extension Daten
  clientHello->data[data_index++] = 0x00;        // Länge des Elliptic Curves Arrays
  clientHello->data[data_index++] = 0x02;        // Länge des Elliptic Curves Arrays
  clientHello->data[data_index++] = 0x00;        // Elliptic Curve secp256r1 = 23
  clientHello->data[data_index++] = 0x17;        // Elliptic Curve secp256r1 = 23
  clientHello->data[data_index++] = 0x00;        // Supported Point Formats Extension
  clientHello->data[data_index++] = 0x0b;        // Supported Point Formats Extension
  clientHello->data[data_index++] = 0x00;        // Länge der Supported Point Formats Extension Daten
  clientHello->data[data_index++] = 0x02;        // Länge der Supported Point Formats Extension Daten
  clientHello->data[data_index++] = 0x01;        // Länge des Point Formats Arrays
  clientHello->data[data_index++] = 0x00;        // Uncompressed Point = 0
  handshake->length[2] += data_index;

  return sizeof(Handshake_t) + handshake->length[2];
}

void dtls_handshake(struct in6_addr *ip) {
  uint8_t len;
  uint8_t message[128];

  time_t my_time = time(NULL);
  uint8_t random[28];
  random_x(random, 28);

  len = makeClientHello(message, my_time, random, NULL, 0, NULL, 0);

  char buffer[128];
  memset(buffer, 0, 128);
  coap_setPayload(message, len);
  coap_request(ip, COAP_REQUEST_POST, "dtls", buffer);

  Handshake_t *handshake = (Handshake_t *) buffer;
  HelloVerifyRequest_t *verify = (HelloVerifyRequest_t *) handshake->payload;
  len = makeClientHello(message, my_time, random, NULL, 0, verify->cookie, verify->cookie_len);

  memset(buffer, 0, 128);
  coap_setPayload(message, len);
  coap_request(ip, COAP_REQUEST_POST, "dtls", buffer);

  printf("Server Hello erhalten.\n");
}

ssize_t dtls_sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen) {
  // Bei Bedarf verschlüsseln
  if (0) {
    uint8_t payload_length = sizeof(CCMData_t) + len + MAC_LEN;

    DTLSRecord_t *record = (DTLSRecord_t *) malloc(sizeof(DTLSRecord_t) + payload_length);
    memset(record, 0, sizeof(DTLSRecord_t) + payload_length);
    record->protocol = 1;
    record->version= 2;
    record->epoch = 0;
    record->len = 1;
    record->length = payload_length;

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
    record->protocol = 1;
    record->version= 2;
    record->epoch = 0;
    record->len = 1;
    record->length = len;

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
  //   printf("Version major: %u\n", record->version);

  // Bei Bedarf entschlüsseln
  if (0) {
    CCMData_t *ccmdata = (CCMData_t*) record->payload;

    uint8_t oldCode[MAC_LEN];
    memcpy(oldCode, getMAC(ccmdata, record->length), MAC_LEN);

    decrypt(ccmdata, KEY, record->length);

    uint32_t check = memcmp(oldCode, getMAC(ccmdata, record->length), MAC_LEN);
    if (check) printf("DTLS-MAC fehler. Paket ungültig.\n");
    db_len = (check == 0 ? record->length - sizeof(CCMData_t) - MAC_LEN : 0);
    memcpy(buf, ccmdata->ccm_ciphered, db_len);
  } else {
    memcpy(buf, record->payload, record->length);
    db_len = record->length;
  }

  if (record->protocol == 0) {
    printf("Alert erhalten.\n");
    // TODO Alert-Auswertung
    db_len = 0;
  }

  free(record);

  return db_len;
}
