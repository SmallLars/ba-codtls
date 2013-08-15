/* __NODE_COM_H__ */
#ifndef __NODE_COM_H__
#define __NODE_COM_H__

#include <netinet/in.h>

void node_getName(struct in6_addr *ip, char *target);

void node_getModel(struct in6_addr *ip, char *target);

void node_getUUID(struct in6_addr *ip, char *target);

void node_getTime(struct in6_addr *ip, char *target);

void node_eccTest(struct in6_addr *ip, char *target);

void node_firmware(struct in6_addr *ip, char *file);

void node_handshake(struct in6_addr *ip);

#endif /* __NODE_COM_H__ */
