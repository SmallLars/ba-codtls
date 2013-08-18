#include "dtls_handshake.h"

#include "dtls_ecc.h"
#include "dtls_random.h"
#include "dtls_content.h"
#include "dtls_clientHello.h"
#include "dtls_serverHello.h"
#include "dtls_keyExchange.h"

//#include <stdlib.h>
#include <stdio.h>
#include <string.h>
//#include <netinet/in.h>
#include <time.h>

#include "dtls_random.h"
#include "coap_client.h"

#define KEY (uint8_t *) "ABCDEFGHIJKLMNOP"

uint32_t base_x[8] = {0xd898c296, 0xf4a13945, 0x2deb33a0, 0x77037d81, 0x63a440f2, 0xf8bce6e5, 0xe12c4247, 0x6b17d1f2};
uint32_t base_y[8] = {0x37bf51f5, 0xcbb64068, 0x6b315ece, 0x2bce3357, 0x7c0f9e16, 0x8ee7eb4a, 0xfe1a7f9b, 0x4fe342e2};

void dtls_handshake(struct in6_addr *ip) {
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
    printf("Step 1 done: Cookie erhalten: ");
    for (i = 0; i < verify->cookie_len; i++) printf("%02X", verify->cookie[i]);
    printf("\n");

// --------------------------------------------------------------------------------------------

    len = makeClientHello(message, my_time, random, NULL, 0, verify->cookie, verify->cookie_len);
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
        printf("Erwartetes ServerHello nicht erhalten. Abbruch.\n");
        return;
    }    
    ServerHello_t *serverHello = (ServerHello_t *) (getContentData(buffer));
    printf("Step 2 done: Session-Id: %.*s\n", serverHello->session_id.len, serverHello->session_id.session_id);

// --------------------------------------------------------------------------------------------

    uint32_t result_x[8];
    uint32_t result_y[8];
    uint32_t private_key[8];
    memset(private_key, 1, 32);
    /*
    do {
        random_x((uint8_t *) private_key, 32);
    } while (!ecc_is_valid_key(private_key));
    */
    printf("Private Key : ");
    for (i = 0; i < 8; i++) printf("%08X", htonl(private_key[i]));
    printf("\n");

// --------------------------------------------------------------------------------------------

    KeyExchange_t *ske = (KeyExchange_t *) getContentData(getContent(buffer, 256, server_key_exchange));

    printf("PSK-Hint erhalten: ");
    for (i = 0; i < ntohs(ske->pskHint_len); i++) printf("%02X", ske->pskHint[i]);
    printf("\n");

    printf("_S_PUB_KEY-X: ");
    for (i = 0; i < 8; i++) printf("%08X", htonl(ske->public_key.x[i]));
    printf("\n_S_PUB_KEY-Y: ");
    for (i = 0; i < 8; i++) printf("%08X", htonl(ske->public_key.y[i]));
    printf("\n");

    ecc_ec_mult(ske->public_key.x, ske->public_key.y, private_key, result_x, result_y);
    printf("SECRET_KEY-X: ");
    for (i = 0; i < 8; i++) printf("%08X", htonl(result_x[i]));
    printf("\nSECRET_KEY-Y: ");
    for (i = 0; i < 8; i++) printf("%08X", htonl(result_y[i]));
    printf("\n");

// --------------------------------------------------------------------------------------------

    KeyExchange_t cke;
    cke.pskHint_len = ske->pskHint_len;
    memcpy(cke.pskHint, ske->pskHint, ntohs(ske->pskHint_len));
    cke.curve_params.curve_type = named_curve;
    cke.curve_params.namedcurve = secp256r1;
    cke.public_key.len = 65;
    cke.public_key.type = uncompressed;
    printf("BASE_POINT-X: ");
    for (i = 0; i < 8; i++) printf("%08X", htonl(base_x[i]));
    printf("\nBASE_POINT-Y: ");
    for (i = 0; i < 8; i++) printf("%08X", htonl(base_y[i]));
    printf("\n");
    ecc_ec_mult(base_x, base_y, private_key, cke.public_key.x, cke.public_key.y);
    printf("_C_PUB_KEY-X: ");
    for (i = 0; i < 8; i++) printf("%08X", htonl(cke.public_key.x[i]));
    printf("\n_C_PUB_KEY-Y: ");
    for (i = 0; i < 8; i++) printf("%08X", htonl(cke.public_key.y[i]));
    printf("\n");

    char uri[16];
    memcpy(uri, "dtls?s=", 7);
    memcpy(uri + 7, serverHello->session_id.session_id, serverHello->session_id.len);
    uri[15] = '\0';
    memset(buffer, 0, 256);
    uint8_t paylen = 0;
    paylen += makeContent(message, client_key_exchange, &cke, sizeof(KeyExchange_t));
    uint8_t changeCipherSpec = 1;
    paylen += makeContent(message + paylen, change_cipher_spec, &changeCipherSpec, 1);
    coap_setPayload(message, paylen);
    coap_setBlock1(0, 1, 1);
    coap_request(ip, COAP_REQUEST_POST, uri, buffer);
    coap_setPayload(message, paylen);
    coap_setBlock1(1, 1, 1);
    coap_request(ip, COAP_REQUEST_POST, uri, buffer);
    coap_setPayload(message, paylen);
    coap_setBlock1(2, 0, 1);
    coap_request(ip, COAP_REQUEST_POST, uri, buffer);
    printf("Step 3 done.\n");
}
