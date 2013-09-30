#include "er-dtls-13.h"

#include <string.h>

#include "er-coap-13.h"
#include "er-dtls-13-data.h"
#include "er-dtls-13-alert.h"

#include "aes.h"

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

__attribute__((always_inline)) static int checkCoapURI(const uint8_t *packet, size_t len);

/* Öffentliche Funktionen -------------------------------------------------- */

void dtls_parse_message(DTLSRecord_t *record, uint8_t len, CoapData_t *coapdata) {
    uip_ipaddr_t *addr = &UIP_IP_BUF->srcipaddr;

    len -= sizeof(DTLSRecord_t);
    uint8_t type = record->type;
    uint8_t *payload = record->payload;
    uint8_t nonce[12] = {0, 0, 0, 0, 0, record->epoch, 0, 0, 0, 0, 0, 0};

    returnType = record->type;

    if (record->type == type_8_bit) {
        type = payload[0] - 20;
        len -= 1;
        payload += 1;
    }
    if (record->version == version_16_bit) {
        if (payload[0] == 3 && payload[1] == 3) {
            record->version = dtls_1_2;
        }
        len -= 2;
        payload += 2;
    }
    if (record->version != dtls_1_2) {
        PRINTF("Ungültige Protokollversion erhalten\n");
        sendAlert(addr, UIP_UDP_BUF->srcport, fatal, protocol_version);
        return;
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

    uint32_t key_block = getKeyBlock(addr, EPOCH, 1);

    // Durch getKeyBlock wurde eventuell die Epoche weitergeschaltet
    // Deswegen wird erst jetzt die Sequenznummer geprüft
    if (checkReadNum(addr, nonce + 6)) {
        PRINTF("Ungültige Sequenznummer erhalten\n");
        sendAlert(addr, UIP_UDP_BUF->srcport, fatal, decode_error);
        return;
    }

    // Bei Bedarf entschlüsseln
    if (EPOCH > 0) {
        if (key_block) {
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
            if (memcmp(oldMAC, payload + len, MAC_LEN)) {
                PRINTF("DTLS-MAC-Fehler. Paket ungültig\n");
                sendAlert(addr, UIP_UDP_BUF->srcport, fatal, bad_record_mac);
                return;
            }
        } else {
            sendAlert(addr, UIP_UDP_BUF->srcport, fatal, decode_error);
            return;
        }
    } else {
        uint16_t known_epoch = 0;
        getSessionData((uint8_t *) &known_epoch, addr, session_epoch);
        if (known_epoch > 0) {
            PRINTF("Angriff auf Session oder Client hat Daten verloren\n");
            // Leider nicht zu unterscheiden. Bei Datenverlust ist Reset notwendig.
            return;
        }

        if (type == application_data) {
            PRINTF("Anwendungsdaten werden in Epoche 0 nicht akzeptiert\n");
            sendAlert(addr, UIP_UDP_BUF->srcport, fatal, unexpected_message);
            return;
        }
    }

    if (type == handshake) {
        if (checkCoapURI(payload, len)) {
            PRINTF("Im Handshake ist nur die Ressource /dtls erlaubt\n");
            sendAlert(addr, UIP_UDP_BUF->srcport, fatal, illegal_parameter);
            return;
        }
    }

    if (type == alert) {
        PRINTF("Alert erhalten.\n");
        deleteSession(addr);
        return;
    }

    coapdata->valid = 1;
    coapdata->data = payload;
    coapdata->data_len = len;
}

void dtls_send_message(struct uip_udp_conn *conn, const void *data, uint8_t len) {

    uint8_t nonce[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

    getSessionData(nonce + 4, &conn->ripaddr, session_epoch);

    uint32_t key_block;
    key_block = getKeyBlock(&conn->ripaddr, EPOCH, 0);

    getSessionData(nonce + 6, &conn->ripaddr, session_num_write);

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

__attribute__((always_inline)) static int checkCoapURI(const uint8_t *packet, size_t len) {
    // coap_parse_message verändert payload und liefert komplette uri
    // payload zunächst kopieren und dann in coap_parse_message verwenden
    // ist ineffizienter (auch weil die URI noch zerlegt werden muss)

    if (packet[1] == 0) {
        // Empty ist ok. Wird für die Block 2 Empfangsbestätigung benutzt.
        PRINTF("dtls-uri-check: empty\n");
        return 0;
    }

    int url_len = 0;

    packet += (4 + (packet[0] & 0x0F));         // 4 Byte Header und Tokenlength. packet zeigt nun auf Options
    int option = 0;
    while (1) {
        option += ((packet[0] & 0xF0) >> 4);    // Da 11 gesucht ist es nicht notwendig Extendet-Delta zu berücksichten
        if (option > 11) {                      // Da Payload-Marker an dieser Stelle 15 wäre, erledigt sich Ende-Check von selbst
            packet = 0;
            break;
        }
        url_len = packet[0] & 0x0F;
        packet++;

        if (url_len == 13) {
            url_len = packet[0];
            packet++;
        }
        if (url_len == 14) {
            url_len = ((packet[0] << 8) + packet[1]);
            packet+=2;
        }

        if (option == 11) break;
        packet += url_len;
    }

    if (packet) {
        PRINTF("dtls-uri-check: %.*s\n", url_len, packet);
        if (url_len != 4 || strncmp("dtls", packet, 4)) {
            return -1;
        }
    }

    return 0;
}
