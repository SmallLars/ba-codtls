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

uint8_t ecc_add_n(const uint32_t *x, const uint32_t *y, uint32_t *result, uint8_t length) {
    uint32_t index;
    uint32_t total;
    uint32_t toAdd;

    asm volatile(
            "mov  %[t], #0 \n\t"
            "mov  %[i], #0 \n\t"
        ".loop: \n\t"
            "ldrh %[s], [%[x],%[i]] \n\t"
            "add  %[t], %[t], %[s] \n\t"
            "ldrh %[s], [%[y],%[i]] \n\t"
            "add  %[t], %[t], %[s] \n\t"
            "strh %[t], [%[r],%[i]] \n\t"
            "asr  %[t], #16 \n\t"
            "add  %[i], %[i], #2 \n\t"
            "cmp  %[i], %[l] \n\t"
            "bne .loop \n\t"
    : /* out */
        [i] "+r" (index),
        [t] "+r" (total),
        [s] "+r" (toAdd)
    : /* in */
        [x] "r" (x),
        [y] "r" (y),
        [r] "r" (result),
        [l] "r" (length)
    : /* clobber list */
        "memory"
    );

    return total;
}

// Start Process
PROCESS(server_firmware, "Server Firmware");
AUTOSTART_PROCESSES(&server_firmware);

PROCESS_THREAD(server_firmware, ev, data) {
    PROCESS_BEGIN();

    PRINTF("Firmware gestartet.\n");

/*
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
*/
    uint32_t a[8] = {0xFFFFFFFF, 0, 0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFFFF, 0, 0xFFFFFFFF, 0xFFFFFFFF};
    uint32_t b[8] = {1, 1, 1, 1, 1, 1, 1, 4};
    uint32_t c[8] = {0, 0, 0, 0, 0, 0, 0, 0};
    uint8_t carry = ecc_add_n(a, b, c, 32);
    int i;
    for (i = 0; i < 8; i++) printf("%u + %u = %u\n", a[i], b[i], c[i]);
    printf("Carry: %u\n", carry);

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
