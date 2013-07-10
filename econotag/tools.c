#include "tools.h"

#include <erbium.h>
#include "mc1322x.h"

#include "persist.h"

// Funktion um moeglichst effizient eine Antwort zu generieren
void set_response(void *response, unsigned int code, unsigned int content_type, const void *payload, size_t length) {
    REST.set_response_status(response, code);
    REST.set_header_content_type(response, content_type);
    REST.set_header_etag(response, (uint8_t *) &length, 1);
    REST.set_response_payload(response, payload, length);
}

uint32_t getTime() {
  uint32_t time;
  nvm_getVar((void *) &time, RES_FLASHTIME, LEN_FLASHTIME);
  return time + (*MACA_CLK / 250000);
}
