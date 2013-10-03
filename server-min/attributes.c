#include <string.h>

#include <erbium.h>
#include <er-coap-13.h>

void device_handler(void* request, void* response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset) {
    memcpy(buffer, "Hallo Welt!", 11);
    buffer[REST_MAX_CHUNK_SIZE - 1] = 0;
    REST.set_response_status(response, CONTENT_2_05);
    REST.set_header_content_type(response, TEXT_PLAIN);
    REST.set_response_payload(response, buffer, 11);
}
