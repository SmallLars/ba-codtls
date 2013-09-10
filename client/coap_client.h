/* __COAP_CLIENT_H__ */
#ifndef __COAP_CLIENT_H__
#define __COAP_CLIENT_H__

#include <stddef.h>
#include <stdint.h>
#include <netinet/in.h>

#include "libcoap-4.0.1/coap.h"

typedef unsigned char method_t;

void coap_request(uint8_t *ip, method_t my_method, char *my_res, char *target);

void coap_setPayload(uint8_t *data, size_t len);

void coap_setBlock1(uint8_t num, uint8_t m, uint8_t szx);

void coap_setNoneConfirmable();

void coap_setWait(uint32_t secs);

#endif /* __COAP_CLIENT_H__ */
