#include "coap_dtls_clientHello.h"

#include "coap_dtls_handshake.h"


//#include <stdlib.h>
//#include <stdio.h>
#include <string.h>
//#include <netinet/in.h>

//#include "coap_ccm.h"
//#include "coap_random.h"
//#include "coap_client.h"


uint8_t makeClientHello(uint8_t *target, time_t time, uint8_t *random, uint8_t *sessionID, uint8_t session_len, uint8_t *cookie, uint8_t cookie_len) {
  Content_t *content = (Content_t *) target;

  content->type = client_hello;
  content->len = con_length_8_bit;
  content->payload[0] = 0;

  ClientHello_t *clientHello = (ClientHello_t *) (content->payload + content->len);
  clientHello->client_version.major = 3;
  clientHello->client_version.minor = 3;
  clientHello->random.gmt_unix_time = htonl(time);
  memcpy(clientHello->random.random_bytes, random, 28);
  content->payload[0] += sizeof(ClientHello_t);

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
  content->payload[0] += data_index;

  return sizeof(Content_t) + content->len + content->payload[0];
}
