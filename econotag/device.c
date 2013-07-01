/*
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
#include <stddef.h>
#include <mc1322x.h>
#include <board.h>
#include <stddef.h>
#include <stdint.h>
*/
#include "tools.h"
#include "persist.h"
#include "attributes.h"

#include <dev/button-sensor.h>

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
  rest_activate_resource(&resource_device_uuid);

	while(1) {
		PROCESS_WAIT_EVENT();

		if (ev == sensors_event && data == &button_sensor) {
      PRINTF("Button.\n");
		}

	}

  PROCESS_END();
}
