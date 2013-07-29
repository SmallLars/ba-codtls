#include "attributes.h"
#include "button-sensor.h"

#include <string.h>

#define DEBUG 0

#if DEBUG
    #include <stdio.h>
    #define PRINTF(...) printf(__VA_ARGS__)
#else
    #define PRINTF(...)
#endif

// Start Process
PROCESS(server_firmware, "Server Firmware");
AUTOSTART_PROCESSES(&server_firmware);

PROCESS_THREAD(server_firmware, ev, data) {
    PROCESS_BEGIN();

    PRINTF("Firmware gestartet.\n");

    rest_init_engine();

    rest_activate_resource(&resource_device);

	while(1) {
		PROCESS_WAIT_EVENT();

		if (ev == sensors_event && data == &button_sensor) {
            PRINTF("Button.\n");
		}
	}

    PROCESS_END();
}
