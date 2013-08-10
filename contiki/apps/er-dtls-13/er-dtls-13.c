#include "er-dtls-13.h"

#include <string.h>

#include "er-dtls-13-data.h"
#include "er-dtls-13-ccm.h"

/*---------------------------------------------------------------------------*/

#define DEBUG 1

#if DEBUG
    #include <stdio.h>
    #define PRINTF(...) printf(__VA_ARGS__)
#else
    #define PRINTF(...)
#endif

/* Private Funktionsprototypen --------------------------------------------- */


/* Öffentliche Funktionen -------------------------------------------------- */

void dtls_parse_message(uint8_t *ip, DTLSRecord_t *record, uint8_t len, CoapData_t *coapdata) {
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
        PRINTF("\nEpoch: %u\n", uip_htons(*((uint16_t *) nonce)));
    #endif

    // Bei Bedarf entschlüsseln
    uint8_t key[16];
    if (getKey(key, ip, uip_htons(*((uint16_t *) nonce))) == 0) { // TODO
        len -= MAC_LEN;
        uint8_t oldMAC[MAC_LEN];
        memcpy(oldMAC, payload + len, MAC_LEN);
        crypt(payload, len, key, nonce, 0);
        crypt(payload, len, key, nonce, 1);
        uint32_t check = memcmp(oldMAC, payload + len, MAC_LEN);
        if (check) printf("DTLS-MAC fehler. Paket ungültig.\n");
        coapdata->valid = (check == 0 ? 1 : 0);
        coapdata->data = payload;
        coapdata->data_len = len;
    } else {
        coapdata->valid = 1;
        coapdata->data = payload;
        coapdata->data_len = len;
    }

    if (type == 21) { // Alert
        printf("Alert erhalten.\n");
        // TODO Alert-Auswertung
        coapdata->valid = 0;
    }
}

void dtls_send_message(struct uip_udp_conn *conn, const void *data, uint8_t len) {
    // Bei Bedarf verschlüsseln
    printf("Es wird gesendet!\n");

    int8_t epoch = getEpoch(conn->ripaddr.u8);
    uint8_t key[16];
    if (getKey(key, conn->ripaddr.u8, epoch) == 0) {
        printf("Verschlüsselt!\n");
        uint8_t packet[sizeof(DTLSRecord_t) + 13 + len + MAC_LEN]; // 13 = maximaler Header-Anhang

        uint8_t headerAdd = 0;
        DTLSRecord_t *record = (DTLSRecord_t *) packet;
        record->type = application_data;
        record->version= dtls_1_2;
        record->epoch = 1;
        record->snr = snr_8_bit;
        record->payload[0] = 5;
        headerAdd++;
        record->length = rec_length_implicit;
        memcpy(record->payload + headerAdd, data, len);

        uint8_t nonce[8];
        nonce[1] = 1;
        nonce[7] = 5;

        crypt(record->payload + headerAdd, len, key, nonce, 0);

        uip_udp_packet_send(conn, packet, sizeof(DTLSRecord_t) + headerAdd + len + MAC_LEN);
    } else {
        printf("Unverschlüsselt!\n");
        uint8_t packet[sizeof(DTLSRecord_t) + 1 + len];
        DTLSRecord_t *record = (DTLSRecord_t *) packet;
        record->type = application_data;
        record->version= dtls_1_2;
        record->epoch = 0;
        record->snr = snr_8_bit;
        record->payload[0] = 5;
        record->length = rec_length_implicit;

        memcpy(record->payload + 1, data, len);

        printf("Größe: %u\n", sizeof(DTLSRecord_t) + 1 + len);
        uip_udp_packet_send(conn, packet, sizeof(DTLSRecord_t) + 1 + len);
    }

    changeIfPending(conn->ripaddr.u8);
}

/* Private Funktionen ------------------------------------------------------ */
