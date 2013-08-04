#include "attributes.h"
#include "button-sensor.h"

#include "mc1322x.h"
#include "flash-store.h"
#include "ecc_add.h"
#include "ecc_sub.h"

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

            uint32_t result_x[8];
            uint32_t result_y[8];
            uint32_t base_x[8];
            uint32_t base_y[8];
            nvm_getVar((void *) base_x, RES_ECC_BASE_X, LEN_ECC_BASE_X);
            nvm_getVar((void *) base_y, RES_ECC_BASE_Y, LEN_ECC_BASE_Y);

            uint32_t private_key[8];
            do {
                uint32_t i;
                for (i = 0; i < 32; i++)
                    ((uint8_t *) private_key)[i] = (*MACA_RANDOM) & 0x000000FF;
            } while (!ecc_is_valid_key(private_key));

            uint32_t time = *MACA_CLK;
            printf("ECC - START\n");
            ecc_ec_mult(base_x, base_y, private_key, result_x, result_y);
            printf("ECC - ENDE - %u\n", (*MACA_CLK - time) / 250);

/*
    uint32_t a[8] = {2, 3, 4, 5, 6, 7, 8, 9};
    uint32_t b[8] = {1, 3, 5, 2, 1, 1, 1, 10};
    uint32_t c[8] = {5, 5, 5, 5, 5, 5, 5, 5};
    uint8_t carry = ecc_sub(a, b, c, 8);
    int i;
    for (i = 0; i < 8; i++) printf("%u - %u = %u\n", a[i], b[i], c[i]);
    printf("Carry: %u\n", carry);
*/

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
