#include <stdlib.h>
#include <string.h>
#include <er-coap-12.h>
#include <adc.h>
#include <gpio.h>
#include <gpio-util.h>
#include "contiki.h"
#include "contiki-net.h"
#include "erbium.h"
#include "dev/leds.h"
#include "dev/button-sensor.h"
#include <stddef.h>
#include <mc1322x.h>
#include <board.h>
#include <stddef.h>
#include <stdint.h>
#include "persist.h"
#include "pwm.h"

#define PRINTF(...) //printf(__VA_ARGS__);
#ifndef max
#define max(x,y) ((x)>(y)?(x):(y))
#endif

#ifndef min
#define min(x,y) ((x)<(y)?(x):(y))
#endif

// TODO: find include file
#define CONTENT_2_05  69
#define INTERNAL_SERVER_ERROR_5_00  160

// Funktion um moeglichst effizient eine Antwort zu generieren
void set_response(void *response, unsigned int code, unsigned int content_type, const void *payload, size_t length) {
    REST.set_response_status(response, code);
    REST.set_header_content_type(response, content_type);
    REST.set_header_etag(response, (uint8_t *) &length, 1);
    REST.set_response_payload(response, payload, length);
}
//#define set_response(w, x, y, z) set_response((w), (x), (y), (z), strlen(z)) TODO ueberladen geht nicht!

/*************************************************************************/
/*  DEVICE NAME                                                          */
/*************************************************************************/
RESOURCE(device_name, METHOD_GET, "d/name","rt=\"gobi.dev.n\";if=\"core.rp\"");
void
device_name_handler(void* request, void* response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset)
{
  const char *device_name = "Name: Server";

  int length = 0;

  buffer[REST_MAX_CHUNK_SIZE-1] = 0;
  memcpy(buffer,device_name,length = min(strlen(device_name), REST_MAX_CHUNK_SIZE-1));

  REST.set_header_content_type(response, REST.type.TEXT_PLAIN); /* text/plain is the default, hence this option could be omitted. */
  REST.set_header_etag(response, (uint8_t *) &length, 1);
  REST.set_response_payload(response, buffer, length);
}

/*************************************************************************/
/*  DEVICE MODEL                                                         */
/*************************************************************************/
RESOURCE(device_model, METHOD_GET, "d/model","rt=\"gobi.dev.mdl\";if=\"core.rp\"");
void
device_model_handler(void* request, void* response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset)
{
  const char *device_model = "Model: Server";
  int length = 0;
  buffer[REST_MAX_CHUNK_SIZE-1] = 0;
  memcpy(buffer,device_model,length = min(strlen(device_model), REST_MAX_CHUNK_SIZE-1));

  REST.set_header_content_type(response, REST.type.TEXT_PLAIN); /* text/plain is the default, hence this option could be omitted. */
  REST.set_header_etag(response, (uint8_t *) &length, 1);
  REST.set_response_payload(response, buffer, length);
}

/*************************************************************************/
/*  DEVICE IDENTIFIER                                                    */
/*************************************************************************/
RESOURCE(device_identifier, METHOD_GET, "d/identifier","rt=\"gobi.dev.id\";if=\"core.rp\"");
void
device_identifier_handler(void* request, void* response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset)
{
  unsigned char device_identifier[LEN_UUID];
  nvm_getVar(device_identifier, RES_UUID, LEN_UUID);

  int length = 0;
  buffer[REST_MAX_CHUNK_SIZE-1] = 0;
  memcpy(buffer,device_identifier,length = min(LEN_UUID, REST_MAX_CHUNK_SIZE-1));

  REST.set_header_content_type(response, REST.type.TEXT_PLAIN); /* text/plain is the default, hence this option could be omitted. */
  REST.set_header_etag(response, (uint8_t *) &length, 1);
  REST.set_response_payload(response, buffer, length);
}

/*************************************************************************/
/*  HANDSHAKE                                                            */
/*************************************************************************/
RESOURCE(handshake, METHOD_GET | METHOD_PUT, "b/handshake","rt=\"binary\";if=\"core.rp\"");
void
handshake_handler(void* request, void* response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset)
{
  uint8_t *text = "lala";
  set_response(response, CONTENT_2_05, APPLICATION_OCTET_STREAM, text, 4);
}

// Start Process
PROCESS(server_firmware, "Server Firmware");
AUTOSTART_PROCESSES(&server_firmware);

PROCESS_THREAD(server_firmware, ev, data)
{
  PROCESS_BEGIN();

  PRINTF("Firmware gestartet.\n");

  rest_init_engine();

  rest_activate_resource(&resource_device_name);
  rest_activate_resource(&resource_device_model);
  rest_activate_resource(&resource_device_identifier);

  rest_activate_resource(&resource_handshake);

	while(1) {
		PROCESS_WAIT_EVENT();

		if (ev == sensors_event && data == &button_sensor) {
      PRINTF("Button.\n");
		}

	}

  PROCESS_END();
}
