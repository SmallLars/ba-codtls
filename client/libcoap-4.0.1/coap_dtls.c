#include "coap_dtls.h"

#include <stdio.h>
#include <arpa/inet.h>

#include "coap_dtls_random.h"
#include "coap_dtls_ccm.h"
#include "coap_client.h"

/*---------------------------------------------------------------------------*/

#define DEBUG 1

#if DEBUG
    #include <stdio.h>
    #define PRINTF(...) printf(__VA_ARGS__)
#else
    #define PRINTF(...)
#endif

#define KEY (uint8_t *) "ABCDEFGHIJKLMNOP"

ssize_t dtls_sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen) {
  // Bei Bedarf verschlüsseln
  if (0) {
/*
    uint8_t payload_length = len + MAC_LEN;

    DTLSRecord_t *record = (DTLSRecord_t *) malloc(sizeof(DTLSRecord_t) + 13 + payload_length); // 13 = maximaler Header-Anhang
    memset(record, 0, sizeof(DTLSRecord_t) + payload_length);
    record->type = application_data;
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
*/
  } else {
    DTLSRecord_t *record = (DTLSRecord_t *) malloc(sizeof(DTLSRecord_t) + 1 + len);
    memset(record, 0, sizeof(DTLSRecord_t) + len);
    record->type = application_data;
    record->version= dtls_1_2;
    record->epoch = 0;
    record->snr = snr_8_bit;
    record->payload[0] = 5;
    record->length = rec_length_implicit;

    memcpy(record->payload + 1, buf, len);

    ssize_t send = sendto(sockfd, record, sizeof(DTLSRecord_t) + 1 + len, flags, dest_addr, addrlen);
    send -= (sizeof(DTLSRecord_t) + 1);

    free(record);

    return send;
  }
}

ssize_t dtls_recvfrom(int sockfd, void *buf, size_t max_len, int flags, struct sockaddr *src_addr, socklen_t *addrlen) {
    ssize_t len = recvfrom(sockfd, buf, max_len, flags, src_addr, addrlen);

    DTLSRecord_t *record = (DTLSRecord_t *) malloc(len);
    memcpy(record, buf, len);

    len -= sizeof(DTLSRecord_t);
    uint8_t type = record->type;
    uint8_t *payload = record->payload;
    uint8_t nonce[8] = {0, record->epoch, 0, 0, 0, 0, 0, 0};

    if (record->type == type_8_bit) {
        type = payload[0];
        len -= 1;
        payload += 1;
    }
    if (record->version == version_16_bit) {
        // TODO auslesen
        len -= 2;
        payload += 2;
    }
    if (record->epoch == epoch_8_bit || record->epoch == epoch_16_bit) {
        uint8_t epoch_len = record->epoch - 4;
        memcpy(nonce + 2 - epoch_len, payload, epoch_len);
        len -= epoch_len;
        payload += epoch_len;
    }
    if (record->snr < snr_implicit) {
        memcpy(nonce + 8 - record->snr, payload, record->snr);
        len -= record->snr;
        payload += record->snr;
    }
    if (record->length < rec_length_implicit) {
        len -= record->length;
        payload += record->length;
    }

    #if DEBUG
        uint32_t i;
        PRINTF("Nonce:");
        for (i = 0; i < 8; i++) PRINTF(" %02X", nonce[i]);
        PRINTF("\nEpoch: %u\n", ntohs(*((uint16_t *) nonce)));
    #endif

  // Bei Bedarf entschlüsseln
  if (record->epoch) {
    len -= MAC_LEN;

    uint8_t oldCode[MAC_LEN];
    memcpy(oldCode, payload + len, MAC_LEN);

    decrypt(payload, len, KEY, nonce);

    uint32_t check = memcmp(oldCode, payload + len, MAC_LEN);
    if (check) printf("DTLS-MAC fehler. Paket ungültig.\n");
    if (check != 0) len = 0;
    memcpy(buf, payload, len);
  }

  // In jedem Fall Daten nun in den Buffer kopieren
  memcpy(buf, payload, len);

  if (type == 21) { // Alert
    printf("Alert erhalten.\n");
    // TODO Alert-Auswertung
    len = 0;
  }

  free(record);

  return len;
}
