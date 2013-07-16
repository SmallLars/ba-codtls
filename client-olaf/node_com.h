/* __NODE_COM_H__ */
#ifndef __NODE_COM_H__
#define __NODE_COM_H__

#include <netinet/in.h>

void node_getName(struct in6_addr *ip, char *target);

void node_getModel(struct in6_addr *ip, char *target);

void node_getUUID(struct in6_addr *ip, char *target);

#endif /* __NODE_COM_H__ */