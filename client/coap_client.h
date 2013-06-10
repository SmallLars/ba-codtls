/* __COAP_CLIENT_H__ */
#ifndef __COAP_CLIENT_H__
#define __COAP_CLIENT_H__

#include <netinet/in.h>

#include "libcoap-4.0.1/coap.h"

typedef unsigned char method_t;

void coap_request(struct in6_addr *ip, method_t my_method, char *my_res, char *target);

#endif /* __COAP_CLIENT_H__ */
