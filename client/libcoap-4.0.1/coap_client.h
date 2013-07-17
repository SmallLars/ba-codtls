/* __COAP_CLIENT_H__ */
#ifndef __COAP_CLIENT_H__
#define __COAP_CLIENT_H__

#include <stddef.h>
#include <stdint.h>
#include <netinet/in.h>

#include "coap.h"

typedef unsigned char method_t;

void coap_request(struct in6_addr *ip, method_t my_method, char *my_res, char *target);

void coap_setPayload(uint8_t *data, size_t len);

void coap_setNoneConfirmable();

#endif /* __COAP_CLIENT_H__ */
