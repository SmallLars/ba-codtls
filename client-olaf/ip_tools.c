#include <stdio.h>
#include <string.h>

#include "ip_tools.h"

void print_ip(const struct in6_addr *addr) {
    uint16_t a;
    unsigned int i;
    int f;
    for(i = 0, f = 0; i < sizeof(struct in6_addr); i += 2) {
        a = (addr->s6_addr[i] << 8) + addr->s6_addr[i + 1];
        if(a == 0 && f >= 0) {
            if(f++ == 0) {
                printf("::");
            }
        } else {
            if(f > 0) {
                f = -1;
            } else if(i > 0) {
                printf(":");
            }
            printf("%x", a);
        }
    }
}

int ipcmp(const struct in6_addr *addr1, const struct in6_addr *addr2) {
    return memcmp(addr1, addr2, sizeof(struct in6_addr));
}
