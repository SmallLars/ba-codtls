#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "ip_list.h"
#include "ip_tools.h"
#include "border_com.h"
#include "node_com.h"

struct ip_list *liste = NULL;
unsigned char aes_key[16];

int main(int argc, char *argv[]) {
    char cbuffer[32];

    border_getNodes(&liste);
    border_printNodes(liste);

    char run = 1;
    while (run) {
        if (fgets(cbuffer,32,stdin) == NULL) continue;
        int length = strlen(cbuffer) - 1;
        char unknown = 1;
        switch (length) {
            case 2:
                if (!memcmp("ls", cbuffer, 2)) {
                    border_getNodes(&liste);
                    border_printNodes(liste);
                    unknown = 0;
                }
                break;
            case 4:
                if (!memcmp("exit", cbuffer, 4)) {
                    run = 0;
                    unknown = 0;
                }
                break;
            case 6:
                if (!memcmp("name", cbuffer, 4)) {
                    struct in6_addr *ip = get_ip(liste, atoi(cbuffer + 5));
                    char nodeName[512];
                    node_getName(ip, nodeName);
                    printf("%s\n", nodeName);
                    unknown = 0;
                }
                break;
        }
        if (unknown) printf("Unbekannter Befehl. Möglichkeiten: ls, name <nr>, exit\n");
    }    

    clear_ip(&liste);
    return 0;
}
