/* __IP_TOOLS_H__ */
#ifndef __IP_TOOLS_H__
#define __IP_TOOLS_H__

#include <netinet/in.h>

void print_ip(const struct in6_addr *addr);

int ipcmp(const struct in6_addr *addr1, const struct in6_addr *addr2);

#endif /* __IP_TOOLS_H__ */
