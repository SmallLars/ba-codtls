#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <poll.h>

#include "node_com.h"
#include "ip_tools.h"
#include "libcoap-4.0.1/coap_client.h"
#include "libcoap-4.0.1/coap_dtls.h"

/* Private Funktionsprototypen --------------------------------------------- */


/* Private Variablen ------------------------------------------------------- */


/* Öffentliche Funktionen -------------------------------------------------- */

void node_getName(struct in6_addr *ip, char *target) {
  coap_request(ip, COAP_REQUEST_GET, "d/name", target);
}

void node_getModel(struct in6_addr *ip, char *target) {
  coap_request(ip, COAP_REQUEST_GET, "d/model", target);
}

void node_getUUID(struct in6_addr *ip, char *target) {
  coap_request(ip, COAP_REQUEST_GET, "d/uuid", target);
}

void node_handshake(struct in6_addr *ip) {
  dtls_handshake(ip);
}

/* Private Funktionen ------------------------------------------------------ */
