#include "ip_list.h"
#include "ip_tools.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

int size_ip(struct ip_list *list) {
    if (list != NULL) return size_ip(list->next) + 1;
    return 0;
}

void add_ip(struct ip_list **list, uint8_t ip[], uint8_t *via) {
    if (ip == NULL) {
        fprintf(stderr, "Fehler: ip_list: add_ip: NULL kann nicht zur Liste hinzugefügt werden.");
        return;
    }

    // Leere Liste mit ersten Element versehen
    if (*list == NULL) {
        *list = (struct ip_list *) malloc(sizeof(struct ip_list));
        inet_pton(AF_INET6, (const char *) ip, &((*list)->ip));
        if (via == NULL) {
            (*list)->via = NULL;
        } else {
            (*list)->via = (uint8_t *) malloc(16);
            inet_pton(AF_INET6, (const char *) via, (*list)->via);
        }
        (*list)->next = NULL;
        return;
    }

    // Element an Liste anhängen, falls nicht schon vorhanden

    // Neues Element erzeugen und IP konvertieren
    // Wird wieder gelöscht, falls IP schon vorhanden
    struct ip_list *new = (struct ip_list *) malloc(sizeof(struct ip_list));
    inet_pton(AF_INET6, (const char *) ip, &(new->ip));
    if (via == NULL) {
        new->via = NULL;
    } else {
        new->via = (uint8_t *) malloc(16);
        inet_pton(AF_INET6, (const char *) via, new->via);
    }
    new->next = NULL;

    struct ip_list *current = *list;
    while (1) {
        if (!ipcmp(new->ip, current->ip)) {
            free(new->via);
            free(new);
            if (via != NULL) {
                if (current->via == NULL) {
                    current->via = (uint8_t *) malloc(16);
                }
                inet_pton(AF_INET6, (const char *) via, current->via);
            }
            return;
        }
        if (current->next == NULL) break;
        current = current->next;
    }

    current->next = new;
}

uint8_t *get_ip(struct ip_list *list, int i) {
    if (i == 0)
        return list->ip;

    if (list->next != NULL)
        return get_ip(list->next, i-1);

    fprintf(stderr, "Fehler: ip_list: get_ip: Listenende erreicht. Ungültiger Listenindex.");
    return NULL;
}

uint8_t *get_via(struct ip_list *list, int i) {
    if (i == 0)
        return list->via;

    if (list->next != NULL)
        return get_via(list->next, i-1);

    fprintf(stderr, "Fehler: ip_list: get_via: Listenende erreicht. Ungültiger Listenindex.");
    return NULL;
}

void clear_ip(struct ip_list **list) {
    if (*list == NULL) return;
    clear_ip(&((*list)->next));
    free((*list)->via);
    free(*list);
    *list = NULL;
}
