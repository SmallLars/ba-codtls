#include "dtls_clientHello.h"

#include <string.h>

#include "dtls_content.h"

size_t makeClientHello(uint8_t *target, time_t time, uint8_t *random, uint8_t *cookie, uint8_t cookie_len) {
    uint8_t buffer[128];
    ClientHello_t *clientHello = (ClientHello_t *) buffer;
    clientHello->client_version.major = 3;
    clientHello->client_version.minor = 3;
    clientHello->random.gmt_unix_time = htonl(time);
    memcpy(clientHello->random.random_bytes, random, 28);

    uint32_t data_index = 0;
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
    clientHello->data[data_index++] = 0x00;        // Elliptic Curve secp256r1
    clientHello->data[data_index++] = 0x23;        // Elliptic Curve secp256r1
    clientHello->data[data_index++] = 0x00;        // Supported Point Formats Extension
    clientHello->data[data_index++] = 0x0b;        // Supported Point Formats Extension
    clientHello->data[data_index++] = 0x00;        // Länge der Supported Point Formats Extension Daten
    clientHello->data[data_index++] = 0x02;        // Länge der Supported Point Formats Extension Daten
    clientHello->data[data_index++] = 0x01;        // Länge des Point Formats Arrays
    clientHello->data[data_index++] = 0x00;        // Uncompressed Point

    return makeContent(target, client_hello, buffer, sizeof(ClientHello_t) + data_index);
}
