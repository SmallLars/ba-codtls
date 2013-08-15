#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <poll.h>
#include <arpa/inet.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

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

void node_firmware(struct in6_addr *ip, char *file) {
    struct stat status;
    if (stat(file, &status)) {
        printf("Datei nicht gefunden!\n");
        return;
    }

    int fd = open(file, O_RDONLY);
    if (fd == -1) {
        printf("Konnte Datei nicht öffnen!\n");
        return;
    }

    uint32_t size = status.st_size;

    int r;
    uint8_t buf[66];
    memcpy(buf + 2, "OKOK", 4);
    memcpy(buf + 6, &size, 4);
    r = 8 + read(fd, buf + 10, 56);

    size = (size + 8) / 64;
    printf("Block    0/%u gesendet!", size);
    fflush(stdout);
    uint16_t i;
    for (i = 0; r > 0; i++) {
        memcpy(buf, &i, 2);
        coap_setPayload(buf, 2 + r);
        coap_request(ip, COAP_REQUEST_POST, "f", NULL);
        printf("\rBlock %4u/%u gesendet!", i, size);
        fflush(stdout);
        r = read(fd, buf + 2, 64);
    }
    printf("\n");

    close(fd);

    buf[0] = 0xFF;
    buf[1] = 0xFF;
    coap_setPayload(buf, 2);
    coap_setNoneConfirmable();
    coap_request(ip, COAP_REQUEST_POST, "f", NULL);
}

void node_handshake(struct in6_addr *ip) {
    dtls_handshake(ip);
}

/* Private Funktionen ------------------------------------------------------ */
