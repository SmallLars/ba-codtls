#include "tools.h"
#include "persist.h"

#include <erbium.h>
#include <er-coap-13.h>
#include <string.h>

/*************************************************************************/
/*  HANDSHAKE                                                            */
/*************************************************************************/
void handshake_handler(void* request, void* response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset) {
  uint8_t *text = "lala";
  set_response(response, CONTENT_2_05, APPLICATION_OCTET_STREAM, text, 4);
}
