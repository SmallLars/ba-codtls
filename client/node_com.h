/* __NODE_COM_H__ */
#ifndef __NODE_COM_H__
#define __NODE_COM_H__

#include <stdint.h>

void node_getCore(uint8_t *ip, char *target);

void node_getName(uint8_t *ip, char *target);

void node_getModel(uint8_t *ip, char *target);

void node_getUUID(uint8_t *ip, char *target);

void node_getTime(uint8_t *ip, char *target);

void node_getPSK(uint8_t *ip, char *target);

void node_setTime(uint8_t *ip, char *target);

void node_firmware(uint8_t *ip, char *file);

void node_handshake(uint8_t *ip);

#endif /* __NODE_COM_H__ */
