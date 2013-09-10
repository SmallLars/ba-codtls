#include <stdio.h>
#include <string.h>

#include "ip_tools.h"

void print_ip(const uint8_t ip[16]) {
    uint16_t a;
    unsigned int i;
    int f;
    for(i = 0, f = 0; i < 16; i += 2) {
        a = (ip[i] << 8) + ip[i + 1];
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

int ipcmp(const uint8_t ip1[16], const uint8_t ip2[16]) {
    return memcmp(ip1, ip2, 16);
}
