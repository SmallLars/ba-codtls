#include "dtls_handshake.h"

#include <string.h>
#include <time.h>

#include "dtls_ecc.h"
#include "dtls_random.h"
#include "dtls_content.h"
#include "dtls_clientHello.h"
#include "dtls_serverHello.h"
#include "dtls_keyExchange.h"
#include "dtls_data.h"
#include "dtls_prf.h"
#include "dtls_aes.h"
#include "../coap_client.h"

#define DEBUG 1
#define DEBUG_ECC 0
#define DEBUG_PRF 1

#if DEBUG || DEBUG_ECC || DEBUG_PRF
    #include <stdio.h>
#endif

#if DEBUG
    #define PRINTF(...) printf(__VA_ARGS__)
#else
    #define PRINTF(...)
#endif

uint32_t base_x[8] = {0xd898c296, 0xf4a13945, 0x2deb33a0, 0x77037d81, 0x63a440f2, 0xf8bce6e5, 0xe12c4247, 0x6b17d1f2};
uint32_t base_y[8] = {0x37bf51f5, 0xcbb64068, 0x6b315ece, 0x2bce3357, 0x7c0f9e16, 0x8ee7eb4a, 0xfe1a7f9b, 0x4fe342e2};

uint8_t handshake_messages[4096];
uint16_t handshake_messages_len;

extern uint8_t isHandshakeMessage;

void dtls_handshake(uint8_t ip[16]) {
    handshake_messages_len = 0;

    isHandshakeMessage = 1;

    uint32_t i;
    uint8_t len;
    uint8_t message[128];

    time_t my_time = time(NULL);
    uint8_t random[28];
    random_x(random, 28);
    char buffer[256];

    len = makeClientHello(message, my_time, random, NULL, 0, NULL, 0);
    memset(buffer, 0, 256);
    coap_setPayload(message, len);
    coap_setBlock1(0, 1, 1);
    coap_request(ip, COAP_REQUEST_POST, "dtls", buffer);
    coap_setPayload(message, len);
    coap_setBlock1(1, 0, 1);
    coap_request(ip, COAP_REQUEST_POST, "dtls", buffer);
    if (getContentType(buffer) != hello_verify_request) {
        return;
    }
    HelloVerifyRequest_t *verify = (HelloVerifyRequest_t *) (getContentData(buffer));
    PRINTF("Step 1 done: Cookie erhalten: ");
    for (i = 0; i < verify->cookie_len; i++) printf("%02X", verify->cookie[i]);
    PRINTF("\n");

// --------------------------------------------------------------------------------------------

    len = makeClientHello(message, my_time, random, NULL, 0, verify->cookie, verify->cookie_len);

    memcpy(handshake_messages + handshake_messages_len, message, len);
    handshake_messages_len += len;

    memset(buffer, 0, 256);
    coap_setPayload(message, len);
    coap_setBlock1(0, 1, 1);
    coap_request(ip, COAP_REQUEST_POST, "dtls", buffer);
    coap_setPayload(message, len);
    coap_setBlock1(1, 1, 1);
    coap_request(ip, COAP_REQUEST_POST, "dtls", buffer);
    coap_setPayload(message, len);
    coap_setBlock1(2, 0, 1);
    coap_request(ip, COAP_REQUEST_POST, "dtls", buffer);
    if (getContentType(buffer) != server_hello) {
        PRINTF("Erwartetes ServerHello nicht erhalten. Abbruch.\n");
        return;
    }

    char *pointer = buffer;
    for (i = 0; i < 3; i++) {
        size_t len = getContentLen(pointer);
        memcpy(handshake_messages + handshake_messages_len, pointer, len);
        handshake_messages_len += len;
        pointer += len;
    }

    ServerHello_t *serverHello = (ServerHello_t *) (getContentData(buffer));
    PRINTF("Step 2 done: Session-Id: %.*s\n", serverHello->session_id.len, serverHello->session_id.session_id);

    createSession(ip, serverHello->session_id.session_id);

// --------------------------------------------------------------------------------------------

    uint32_t result_x[8];
    uint32_t result_y[8];
    uint32_t private_key[8];
    do {
        random_x((uint8_t *) private_key, 32);
    } while (!ecc_is_valid_key(private_key));
    #if DEBUG_ECC
        printf("Private Key : ");
        for (i = 0; i < 8; i++) printf("%08X", htonl(private_key[i]));
        printf("\n");
    #endif

// --------------------------------------------------------------------------------------------

    KeyExchange_t *ske = (KeyExchange_t *) getContentData(getContent(buffer, 256, server_key_exchange));

    PRINTF("PSK-Hint erhalten: ");
    for (i = 0; i < ntohs(ske->pskHint_len); i++) PRINTF("%02X", ske->pskHint[i]);
    PRINTF("\n");

    #if DEBUG_ECC
        printf("_S_PUB_KEY-X: ");
        for (i = 0; i < 8; i++) printf("%08X", htonl(ske->public_key.x[i]));
        printf("\n_S_PUB_KEY-Y: ");
        for (i = 0; i < 8; i++) printf("%08X", htonl(ske->public_key.y[i]));
        printf("\n");
    #endif

    ecc_ec_mult(ske->public_key.x, ske->public_key.y, private_key, result_x, result_y);
    #if DEBUG_ECC
        printf("SECRET_KEY-X: ");
        for (i = 0; i < 8; i++) printf("%08X", htonl(result_x[i]));
        printf("\nSECRET_KEY-Y: ");
        for (i = 0; i < 8; i++) printf("%08X", htonl(result_y[i]));
        printf("\n");
    #endif

// --------------------------------------------------------------------------------------------

    ServerHello_t *sh = (ServerHello_t *) getContentData(getContent(buffer, 256, server_hello));

    uint8_t prf_buffer[160];
    prf_buffer[0] = 0;
    prf_buffer[1] = 16;
    getPSK(prf_buffer + 2, NULL);
    prf_buffer[18] = 0;
    prf_buffer[19] = 64;
    memcpy(prf_buffer + 20, result_x, 32);
    memcpy(prf_buffer + 52, result_y, 32);
    memcpy(prf_buffer + 84, "master secret", 13);
    memcpy(prf_buffer + 97, random, 28);                    // Client-Random
    memcpy(prf_buffer + 125, sh->random.random_bytes, 28);  // Server-Random
    #if DEBUG_PRF
        printf("Seed für Master-Secret:\n    ");
        for (i = 0; i < 33; i++) printf("%02X", prf_buffer[i]);
        printf("\n    ");
        for (i = 33; i < 65; i++) printf("%02X", prf_buffer[i]);
        printf("\n    ");
        for (i = 65; i < 97; i++) printf("%02X", prf_buffer[i]);
        printf("\n    ");
        for (i = 97; i < 125; i++) printf("%02X", prf_buffer[i]);
        printf("\n    ");
        for (i = 125; i < 153; i++) printf("%02X", prf_buffer[i]);
        printf("\n");
    #endif

    uint8_t master_secret[48];
    prf(master_secret, 48, prf_buffer, 153);
    #if DEBUG_PRF
        printf("Master-Secret:\n    ");
        for (i = 0; i < 24; i++) printf("%02X", master_secret[i]);
        printf("\n    ");
        for (i = 24; i < 48; i++) printf("%02X", master_secret[i]);
        printf("\n");
    #endif

    memcpy(prf_buffer + 40, master_secret, 48);
    memcpy(prf_buffer + 88, "key expansion", 13);
    memcpy(prf_buffer + 101, sh->random.random_bytes, 28);
    memcpy(prf_buffer + 129, random, 28);
    prf(prf_buffer, 40, prf_buffer + 40, 117);
    #if DEBUG_PRF
        printf("Key-Block:\n    ");
        for (i = 0; i < 20; i++) printf("%02X", prf_buffer[i]);
        printf("\n    ");
        for (i = 20; i < 40; i++) printf("%02X", prf_buffer[i]);
        printf("\n");
    #endif

    insertKeyBlock(ip, (KeyBlock_t *) prf_buffer);

// --------------------------------------------------------------------------------------------

    KeyExchange_t cke;
    cke.pskHint_len = ske->pskHint_len;
    memcpy(cke.pskHint, ske->pskHint, ntohs(ske->pskHint_len));
    cke.curve_params.curve_type = named_curve;
    cke.curve_params.namedcurve = secp256r1;
    cke.public_key.len = 65;
    cke.public_key.type = uncompressed;
    #if DEBUG_ECC
        printf("BASE_POINT-X: ");
        for (i = 0; i < 8; i++) printf("%08X", htonl(base_x[i]));
        printf("\nBASE_POINT-Y: ");
        for (i = 0; i < 8; i++) printf("%08X", htonl(base_y[i]));
        printf("\n");
    #endif
        ecc_ec_mult(base_x, base_y, private_key, cke.public_key.x, cke.public_key.y);
    #if DEBUG_ECC
        printf("_C_PUB_KEY-X: ");
        for (i = 0; i < 8; i++) printf("%08X", htonl(cke.public_key.x[i]));
        printf("\n_C_PUB_KEY-Y: ");
        for (i = 0; i < 8; i++) printf("%08X", htonl(cke.public_key.y[i]));
        printf("\n");
    #endif

    char uri[14];
    memcpy(uri, "dtls/", 5);
    memcpy(uri + 5, serverHello->session_id.session_id, serverHello->session_id.len);
    uri[13] = '\0';
    memset(buffer, 0, 256);
    uint8_t paylen = 0;
    paylen += makeContent(message, client_key_exchange, &cke, sizeof(KeyExchange_t));

    memcpy(handshake_messages + handshake_messages_len, message, paylen);
    handshake_messages_len += paylen;

    // Change Cipher Spec
    uint8_t changeCipherSpec = 1;
    paylen += makeContent(message + paylen, change_cipher_spec, &changeCipherSpec, 1);

    // Finished Nachrichten berechnen
    uint8_t finished_source[79];
    uint8_t client_finished[20];
    uint8_t server_finished[20];

    memset(finished_source + 63, 0, 16);
    aes_cmac(finished_source + 63, handshake_messages, handshake_messages_len, 1);
    memcpy(finished_source, master_secret, 48);

    memcpy(finished_source + 48, "client finished", 15);
    prf(client_finished, 12, finished_source, 79);
    #if DEBUG_PRF
        printf("Client Finished: ");
        for (i = 0; i < 12; i++) printf("%02X", client_finished[i]);
        printf("\n");
    #endif

    memcpy(finished_source + 48, "server finished", 15);
    prf(server_finished, 12, finished_source, 79);
    #if DEBUG_PRF
        printf("Server Finished: ");
        for (i = 0; i < 12; i++) printf("%02X", server_finished[i]);
        printf("\n");
    #endif

    // Senden
    coap_setPayload(message, paylen);
    coap_setBlock1(0, 1, 1);
    coap_request(ip, COAP_REQUEST_POST, uri, buffer);
    coap_setPayload(message, paylen);
    coap_setBlock1(1, 1, 1);
    coap_request(ip, COAP_REQUEST_POST, uri, buffer);
    coap_setPayload(message, paylen);
    coap_setBlock1(2, 0, 1);
    coap_request(ip, COAP_REQUEST_POST, uri, buffer);
    if (getContentType(buffer) != change_cipher_spec) {
        PRINTF("Erwartetes ChangeCipherSpec nicht erhalten. Abbruch.\n");
        return;
    }

    PRINTF("Step 3 done.\n");
    increaseEpoch(ip);

    isHandshakeMessage = 0;
}
