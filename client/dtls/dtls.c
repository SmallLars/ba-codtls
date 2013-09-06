#include "dtls.h"

#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "dtls_random.h"
#include "dtls_aes.h"
#include "dtls_data.h"

/*---------------------------------------------------------------------------*/

#define DEBUG 0

#if DEBUG
    #include <stdio.h>
    #define PRINTF(...) printf(__VA_ARGS__)
#else
    #define PRINTF(...)
#endif

uint8_t isHandshakeMessage = 0;

/*---------------------------------------------------------------------------*/

ssize_t dtls_sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen) {
    uint8_t *ip = ((struct sockaddr_in6 *) dest_addr)->sin6_addr.s6_addr;

    uint8_t nonce[12];

    uint16_t epoch = getEpoch(ip);
    nonce[4] = (epoch & 0xFF00) >> 8;
    nonce[5] = (epoch & 0x00FF) >> 0;

    uint32_t seq_num = getSeqNum(ip);
    nonce[6]  = 0;
    nonce[7]  = 0;
    nonce[8]  = (seq_num & 0xFF000000) >> 24;
    nonce[9]  = (seq_num & 0x00FF0000) >> 16;
    nonce[10] = (seq_num & 0x0000FF00) >>  8;
    nonce[11] = (seq_num & 0x000000FF) >>  0;

    uint8_t *key_block = getKeyBlock(ip, epoch);
    memcpy(nonce, key_block + KEY_BLOCK_CLIENT_IV, 4);

    DTLSRecord_t *record = (DTLSRecord_t *) malloc(sizeof(DTLSRecord_t) + 13 + len + MAC_LEN); // 13 = maximaler Header-Anhang

    uint32_t headerAdd = 0;
    record->u1 = 0;
    record->type = (isHandshakeMessage ? handshake : application_data);
    record->version= dtls_1_2;
    record->epoch = nonce[5]; // TODO
    record->snr = snr_8_bit;
    record->u2 = 6;
    record->payload[0] = nonce[11]; // TODO
    headerAdd++;
    record->length = rec_length_implicit;

    memcpy(record->payload + headerAdd, buf, len);

    // Bei Bedarf verschlüsseln
    if (epoch) {
        uint8_t key[16];
        memcpy(key, key_block + KEY_BLOCK_CLIENT_KEY, 16);

        aes_encrypt(record->payload + headerAdd, len, key, nonce);
        headerAdd += MAC_LEN;
    }

    ssize_t send = sendto(sockfd, record, sizeof(DTLSRecord_t) + headerAdd + len, flags, dest_addr, addrlen);
    send -= (sizeof(DTLSRecord_t) + headerAdd);

    free(record);

    return send;
}

ssize_t dtls_recvfrom(int sockfd, void *buf, size_t max_len, int flags, struct sockaddr *src_addr, socklen_t *addrlen) {
    ssize_t len = recvfrom(sockfd, buf, max_len, flags, src_addr, addrlen);

    uint8_t *ip = ((struct sockaddr_in6 *) src_addr)->sin6_addr.s6_addr;

    DTLSRecord_t *record = (DTLSRecord_t *) malloc(len);
    memcpy(record, buf, len);

    len -= sizeof(DTLSRecord_t);
    uint8_t type = record->type;
    uint8_t *payload = record->payload;
    uint8_t nonce[12] = {0, 0, 0, 0, 0, record->epoch, 0, 0, 0, 0, 0, 0};

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
        memcpy(nonce + 6 - epoch_len, payload, epoch_len);
        len -= epoch_len;
        payload += epoch_len;
    }
    if (record->snr < snr_implicit) {
        memcpy(nonce + 12 - record->snr, payload, record->snr);
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
        for (i = 0; i < 12; i++) PRINTF(" %02X", nonce[i]);
        PRINTF("\nEpoch: %u\n", ntohs(*((uint16_t *) (nonce + 4))));
    #endif

    // Bei Bedarf entschlüsseln
    if (record->epoch) {
        len -= MAC_LEN;

        uint8_t oldCode[MAC_LEN];
        memcpy(oldCode, payload + len, MAC_LEN);

        uint8_t *key_block = getKeyBlock(ip, record->epoch);
        memcpy(nonce, key_block + KEY_BLOCK_SERVER_IV, 4);

        uint8_t key[16];
        memcpy(key, key_block + KEY_BLOCK_SERVER_KEY, 16);
        
        aes_decrypt(payload, len, key, nonce);

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
