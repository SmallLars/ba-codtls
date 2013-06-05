#include "tools.h"

#include <erbium.h>

// Funktion um moeglichst effizient eine Antwort zu generieren
void set_response(void *response, unsigned int code, unsigned int content_type, const void *payload, size_t length) {
    REST.set_response_status(response, code);
    REST.set_header_content_type(response, content_type);
    REST.set_header_etag(response, (uint8_t *) &length, 1);
    REST.set_response_payload(response, payload, length);
}
