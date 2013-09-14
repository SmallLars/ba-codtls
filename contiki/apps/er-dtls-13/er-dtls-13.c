#include "er-dtls-13.h"

#include <string.h>

#include "er-coap-13.h"
#include "er-dtls-13-data.h"
#include "er-dtls-13-aes.h"
#include "er-dtls-13-alert.h"

/*---------------------------------------------------------------------------*/

#define DEBUG 0

#if DEBUG
    #include <stdio.h>
    #define PRINTF(...) printf(__VA_ARGS__)
#else
    #define PRINTF(...)
#endif

#define EPOCH ((nonce[4] << 8) + nonce[5])

RecordType returnType;

/* Private Funktionsprototypen --------------------------------------------- */

/* Öffentliche Funktionen -------------------------------------------------- */

void dtls_parse_message(DTLSRecord_t *record, uint8_t len, CoapData_t *coapdata) {
    uip_ipaddr_t *addr = &UIP_IP_BUF->srcipaddr;

    len -= sizeof(DTLSRecord_t);
    uint8_t type = record->type;
    uint8_t *payload = record->payload;
    uint8_t nonce[12] = {0, 0, 0, 0, 0, record->epoch, 0, 0, 0, 0, 0, 0};

    returnType = record->type;

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

    // Bei Bedarf entschlüsseln
    uint32_t key_block;
    if ((key_block = getKeyBlock((uint8_t *) addr, EPOCH, 1))) { // TODO cast weg -> pointer anpassen
        len -= MAC_LEN;
        uint8_t oldMAC[MAC_LEN];
        memcpy(oldMAC, payload + len, MAC_LEN);
        uint8_t key[16];
        nvm_getVar(key, key_block + KEY_BLOCK_CLIENT_KEY, 16);
        nvm_getVar(nonce, key_block + KEY_BLOCK_CLIENT_IV, 4);
        #if DEBUG
            uint32_t i;
            PRINTF("Bei Paketempfang berechnete Nonce:");
            for (i = 0; i < 12; i++) PRINTF(" %02X", nonce[i]);
            PRINTF("\n");
        #endif
        aes_crypt(payload, len, key, nonce, 0);
        aes_crypt(payload, len, key, nonce, 1);
        uint32_t check = memcmp(oldMAC, payload + len, MAC_LEN);
        if (check) {
            PRINTF("DTLS-MAC fehler. Paket ungültig.\n");
            sendAlert(addr, UIP_UDP_BUF->srcport, fatal, bad_record_mac);
        } else {
            coapdata->data = payload;
            coapdata->data_len = len;
        }
        coapdata->valid = (check == 0 ? 1 : 0);
    } else {
        if (EPOCH == 0) {
            if (type == handshake) {
                // TODO check auf korrekte resource: /dtls       -> fatal, illegal_parameter
                coapdata->valid = 1;
                coapdata->data = payload;
                coapdata->data_len = len;
            } else {
                sendAlert(addr, UIP_UDP_BUF->srcport, fatal, unexpected_message);
            }
        } else {
            sendAlert(addr, UIP_UDP_BUF->srcport, fatal, decode_error);
        }
    }

    if (type == alert) {
        PRINTF("Alert erhalten.\n");
        // TODO Alert-Auswertung
        coapdata->valid = 0;
    }
}

void dtls_send_message(struct uip_udp_conn *conn, const void *data, uint8_t len) {

    uint8_t nonce[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

    getSessionData(nonce + 4, conn->ripaddr.u8, session_epoch);

    uint32_t key_block;
    key_block = getKeyBlock(conn->ripaddr.u8, EPOCH, 0);

    getSessionData(nonce + 6, conn->ripaddr.u8, session_num_write);

    uint8_t packet[sizeof(DTLSRecord_t) + 13 + len + MAC_LEN]; // 13 = maximaler Header-Anhang

    uint8_t headerAdd = 0;
    DTLSRecord_t *record = (DTLSRecord_t *) packet;
    record->u1 = 0;
    record->type = returnType;
    record->version= dtls_1_2;
    if (nonce[4] || nonce[5] > 4) {
        if (nonce[4]) {
            record->payload[headerAdd] = nonce[4];
            headerAdd++;
        }
        record->payload[headerAdd] = nonce[5];
        headerAdd++;
        record->epoch = 4 + headerAdd;
    } else {
        record->epoch = nonce[5];
    }
    uint32_t leading_zero = 6;
    while (leading_zero < 11 && nonce[leading_zero] == 0) leading_zero++;
    record->snr = 12 - leading_zero;
    memcpy(record->payload + headerAdd, nonce + leading_zero, record->snr);
    headerAdd += record->snr;
    record->length = rec_length_implicit;
    record->u2 = 6;

    memcpy(record->payload + headerAdd, data, len);

    if (key_block) {
        uint8_t key[16];
        nvm_getVar(key, key_block + KEY_BLOCK_SERVER_KEY, 16);
        nvm_getVar(nonce, key_block + KEY_BLOCK_SERVER_IV, 4);
        #if DEBUG
            uint32_t i;
            PRINTF("Bei Paketversand berechnete Nonce:");
            for (i = 0; i < 12; i++) PRINTF(" %02X", nonce[i]);
            PRINTF("\n");
        #endif
        aes_crypt(record->payload + headerAdd, len, key, nonce, 0);
        headerAdd += MAC_LEN;
    }

    uip_udp_packet_send(conn, packet, sizeof(DTLSRecord_t) + headerAdd + len);
}

/* Private Funktionen ------------------------------------------------------ */
