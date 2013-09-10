/* __IP_TOOLS_H__ */
#ifndef __IP_TOOLS_H__
#define __IP_TOOLS_H__

#include <stdint.h>

void print_ip(const uint8_t addr[16]);

int ipcmp(const uint8_t addr1[16], const uint8_t addr2[16]);

#endif /* __IP_TOOLS_H__ */
