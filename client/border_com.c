#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>

#include "border_com.h"
#include "ip_tools.h"

#define BUFF_SIZE 4096

/* Private Funktionsprototypen --------------------------------------------- */
int border_getAnswer(int sockfd, char *buffer);
void border_parseAnswer(char *buffer, struct ip_list **list);

/* Öffentliche Funktionen -------------------------------------------------- */
void border_getNodes(struct ip_list **list) {
    int sockfd;

    struct in6_addr border_ip;
    inet_pton(AF_INET6, "aaaa::60b1:60b1:60b1:0022", &border_ip);

    struct sockaddr_in6 border_addr;
    memset(&border_addr, 0, sizeof(border_addr));
    border_addr.sin6_family = AF_INET6;
    border_addr.sin6_port = htons(80);
    bcopy((char *) &border_ip, (char *) &border_addr.sin6_addr.s6_addr, sizeof(struct in6_addr));

    char buffer[BUFF_SIZE];

    if ((sockfd = socket(AF_INET6, SOCK_STREAM, 0)) < 0) {
        perror("Fehler beim Öffnen des Sockets!");
        exit(EXIT_FAILURE);
    }

    if (connect(sockfd,(struct sockaddr *) &border_addr, sizeof(border_addr)) < 0) {
        perror("Socket Verbindungsfehler!");
        exit(EXIT_FAILURE);
    }

    if (write(sockfd, (char *) "GET / HTTP/1.0\r\n", 16) < 1) {
        perror("Anforderung der Daten fehlgeschlagen!");
        exit(EXIT_FAILURE);
    }

    border_getAnswer(sockfd, buffer);
    border_parseAnswer(buffer, list);

    close(sockfd);
}

void border_printNodes(struct ip_list *list) {
    printf("Im Netz verfügbare Knoten:\n");
    int i;
    for (i = 0; i < size_ip(list); i++) {
        printf("%d: ", i);
        print_ip(get_ip(list, i));
        uint8_t *tmp = get_via(list, i);
        if (tmp != NULL) {
            printf(" via ");
            print_ip(tmp);
        }
        printf("\n");
    }
}

/* Private Funktionen ------------------------------------------------------ */
int border_getAnswer(int sockfd, char *buffer) {
    int n = 0;
    int t = 0;
    bzero(buffer, BUFF_SIZE);
    while ((t = read(sockfd,buffer+n, 127)) > 0) {
        n += t;
    }
    if (n < 0) {
        perror("ERROR reading from socket!");
        return 0;
    }
    return 1;
}

void border_parseAnswer(char *buffer, struct ip_list **list) {
    clear_ip(list);
    char *pos;

    pos = strstr(buffer, "<pre>") + 5;
    while (*pos != '<') {
        char *ende = strstr(pos, "\n");

        uint8_t ip[40];
        memset(ip, 0, 40);
        memcpy(ip, pos, ende - pos);
        memset(ip, 'a', 4);
        add_ip(list, ip, NULL);
        pos = ende + 1;
    }

    pos = strstr(pos, "<pre>") + 5;
    while (*pos != '<') {
        char *ende;

        ende = strstr(pos, "/");
        uint8_t ip[40];
        memset(ip, 0, 40);
        memcpy(ip, pos, ende - pos);

        pos = strstr(pos, "via") + 4;
        ende = strstr(pos, ")");
        uint8_t via[40];
        memset(via, 0, 40);
        memcpy(via, pos, ende - pos);
        memset(via, 'a', 4);

        add_ip(list, ip, via);
        pos = strstr(pos, "\n") + 1;
    }
}
