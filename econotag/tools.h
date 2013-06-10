/* __TOOLS_H__ */
#ifndef __TOOLS_H__
#define __TOOLS_H__

#include <stdlib.h>

#if DEBUG
  #include <stdio.h>
  #define PRINTF(...) printf(__VA_ARGS__)
#else
  #define PRINTF(...)
#endif

#define max(x,y) ((x)>(y)?(x):(y))

#define min(x,y) ((x)<(y)?(x):(y))

void set_response(void *response, unsigned int code, unsigned int content_type, const void *payload, size_t length);
//#define set_response(w, x, y, z) set_response((w), (x), (y), (z), strlen(z)) TODO ueberladen geht nicht!

#endif /* __TOOLS_H__ */
