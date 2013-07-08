#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <uuid/uuid.h>

#include "ip_list.h"
#include "ip_tools.h"
#include "border_com.h"
#include "node_com.h"

struct ip_list *liste = NULL;
unsigned char aes_key[16];

int main(int argc, char *argv[]) {
    char buffer[512];
    char cbuffer[32];

    if (argc == 2) {
      add_ip(&liste, argv[1], NULL);
    } else {
      border_getNodes(&liste);
    }
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
                    memset(buffer, 0, 512);
                    node_getName(ip, buffer);
                    printf("Name: %s\n", buffer);
                    unknown = 0;
                }
                if (!memcmp("uuid", cbuffer, 4)) {
                    struct in6_addr *ip = get_ip(liste, atoi(cbuffer + 5));
                    memset(buffer, 0, 512);
                    node_getUUID(ip, buffer);
                    char uuid[37];
                    uuid_unparse(buffer, uuid);
                    printf("UUID: %s\n", uuid);
                    unknown = 0;
                }
                break;
            case 7:
                if (!memcmp("model", cbuffer, 5)) {
                    struct in6_addr *ip = get_ip(liste, atoi(cbuffer + 6));
                    memset(buffer, 0, 512);
                    node_getModel(ip, buffer);
                    printf("Model: %s\n", buffer);
                    unknown = 0;
                }
                break;
            case 11:
                if (!memcmp("handshake", cbuffer, 9)) {
                    struct in6_addr *ip = get_ip(liste, atoi(cbuffer + 10));
                    node_handshake(ip);
                    unknown = 0;
                }
                break;
        }
        if (unknown) printf("Unbekannter Befehl. Möglichkeiten: ls, name <nr>, exit\n");
    }    

    clear_ip(&liste);
    return 0;
}
