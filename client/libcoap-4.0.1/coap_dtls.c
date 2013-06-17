#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>

#include "coap_dtls.h"

#include "ccm.h"

ssize_t dtls_sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen) {
    uint8_t *key = (uint8_t *) "ABCDEFGHIJKLMNOP";

    DTLSCipher_t *c = (DTLSCipher_t *) malloc(sizeof(DTLSCipher_t) + len + 8); // 8 = Länge des MAC
    c->type = application_data;
    c->version.major = 3;
    c->version.minor = 3;
    c->length = len + 16;
    memcpy(c->ccm_fragment.nonce_explicit, "ABCDEFGH", 8);
    encrypt(&(c->ccm_fragment), key, buf, len);

    ssize_t send = sendto(sockfd, c, sizeof(DTLSCipher_t) + len + 8, flags, dest_addr, addrlen) - (sizeof(DTLSCipher_t) + 8);

    free(c);

    return send;
}

/*
ssize_t dtls_recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen) {
    size_t size = recvfrom(sockfd, buf, len, flags, src_addr, addrlen);

    struct sockaddr_in6 *addr = (struct sockaddr_in6 *) src_addr;
    struct in6_addr *ip = &(addr->sin6_addr);
    unsigned char *key = processorGetKey(ip);

    char str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, ip, str, INET6_ADDRSTRLEN);
    if (key == NULL || AES_DISABLED) {
        logWrite(L_DEBUG, "aes-udp - AES_recvfrom", "AES_recvfrom OFFEN benutzt. -> %s", str);
        free(key);
        return size;
    }

    logWrite(L_DEBUG, "aes-udp - AES_recvfrom", "AES_recvfrom SICHER benutzt. -> %s", str);
    aes_decrypt(buf, size, key);
    free(key);
    return size - aes_headerlen();
}*/
