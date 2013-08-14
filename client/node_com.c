#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <poll.h>
#include <arpa/inet.h>

#include "node_com.h"
#include "ip_tools.h"
#include "libcoap-4.0.1/coap_client.h"
#include "libcoap-4.0.1/coap_dtls_handshake.h"

/* Private Funktionsprototypen --------------------------------------------- */


/* Private Variablen ------------------------------------------------------- */


/* Öffentliche Funktionen -------------------------------------------------- */

void node_getName(struct in6_addr *ip, char *target) {
    coap_request(ip, COAP_REQUEST_GET, "d?i=name", target);
}

void node_getModel(struct in6_addr *ip, char *target) {
    coap_request(ip, COAP_REQUEST_GET, "d?i=model", target);
}

void node_getUUID(struct in6_addr *ip, char *target) {
    coap_request(ip, COAP_REQUEST_GET, "d?i=uuid", target);
}

void node_getTime(struct in6_addr *ip, char *target) {
    coap_request(ip, COAP_REQUEST_GET, "d?i=time", target);
    uint32_t *time = (uint32_t *) target;
    *time = ntohl(*time);
}

void node_eccTest(struct in6_addr *ip, char *target) {
    coap_request(ip, COAP_REQUEST_GET, "d?i=ecc", target);
}

void node_handshake(struct in6_addr *ip) {
    dtls_handshake(ip);
}

/* Private Funktionen ------------------------------------------------------ */
