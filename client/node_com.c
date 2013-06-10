#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <poll.h>

#include "node_com.h"
#include "ip_tools.h"
#include "coap_client.h"

/* Private Funktionsprototypen --------------------------------------------- */


/* Private Variablen ------------------------------------------------------- */


/* Öffentliche Funktionen -------------------------------------------------- */

void node_getName(struct in6_addr *ip, char *target) {
  coap_request(ip, COAP_REQUEST_GET, "d/name", target);
}

/* Private Funktionen ------------------------------------------------------ */
