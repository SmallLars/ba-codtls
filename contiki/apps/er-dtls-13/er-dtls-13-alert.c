#include "er-dtls-13-alert.h"

#include "er-coap-13.h"
#include "er-dtls-13.h"
#include "er-dtls-13-resource.h"

/*---------------------------------------------------------------------------*/

#define DEBUG 0

#if DEBUG
    #include <stdio.h>
    #define PRINTF(...) printf(__VA_ARGS__)
#else
    #define PRINTF(...)
#endif

typedef struct {
    AlertLevel level;
    AlertDescription description;
} __attribute__ ((packed)) DTLSAlert_t;

extern RecordType returnType;

/* Private Funktionsprototypen --------------------------------------------- */

/* Öffentliche Funktionen -------------------------------------------------- */

void sendAlert(uip_ipaddr_t *addr, uint16_t port, AlertLevel level, AlertDescription description) {
    struct uip_udp_conn udp_conn;
    uip_ipaddr_copy(&(udp_conn.ripaddr), addr);
    udp_conn.rport = port;
    udp_conn.lport = UIP_HTONS(COAP_SERVER_PORT);
    udp_conn.ttl = UIP_TTL;

    DTLSAlert_t a;
    a.level = level;
    a.description = description;

    returnType = alert;
    dtls_send_message(&udp_conn, &a, sizeof(DTLSAlert_t));
}

void generateAlert(void* response, uint8_t *buffer, AlertDescription description) {
    coap_set_status_code(response, BAD_REQUEST_4_00);

    DTLSContent_t *c = (DTLSContent_t *) buffer;
    c->type = c_alert;
    c->len = con_length_8_bit;
    c->payload[0] = 2;

    DTLSAlert_t *a = (DTLSAlert_t *) (buffer + 2);
    a->level = fatal;
    a->description = description;

    coap_set_payload(response, buffer, 4);
}

/* Private Funktionen ------------------------------------------------------ */

