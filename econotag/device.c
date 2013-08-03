#include "attributes.h"
#include "button-sensor.h"

#include "mc1322x.h"
#include "flash-store.h"

#include <string.h>

#define DEBUG 0

#if DEBUG
    #include <stdio.h>
    #define PRINTF(...) printf(__VA_ARGS__)
#else
    #define PRINTF(...)
#endif

uint8_t ecc_add_n(const uint32_t *x, const uint32_t *y, uint32_t *result, uint8_t length) {
    uint32_t total;
    uint32_t toAdd;

    asm volatile(
            "cmp %[l], # \n\t"
            "beq .add2 \n\t"
            "bhi .add4or8 \n\t"
        ".add1: \n\t"
            "ldr %[t], [%[x],#0] \n\t"
            "ldr %[s], [%[y],#0] \n\t"
            "add %[t], %[t], %[s] \n\t"
            "str %[t], [%[r],#0] \n\t"
            "b .foot \n\t"
        ".add2: \n\t"
            "ldr %[t], [%[x],#0] \n\t"
            "ldr %[s], [%[y],#0] \n\t"
            "add %[t], %[t], %[s] \n\t"
            "str %[t], [%[r],#0] \n\t"
            "ldr %[t], [%[x],#4] \n\t"
            "ldr %[s], [%[y],#4] \n\t"
            "adc %[t], %[t], %[s] \n\t"
            "str %[t], [%[r],#4] \n\t"
            "b .foot \n\t"
        ".add4or8: \n\t"
            "cmp %[l], #8 \n\t"
            "beq .add8 \n\t"
        ".add4: \n\t"
            "ldr %[t], [%[x],#0] \n\t"
            "ldr %[s], [%[y],#0] \n\t"
            "add %[t], %[t], %[s] \n\t"
            "str %[t], [%[r],#0] \n\t"
            "ldr %[t], [%[x],#4] \n\t"
            "ldr %[s], [%[y],#4] \n\t"
            "adc %[t], %[t], %[s] \n\t"
            "str %[t], [%[r],#4] \n\t"
            "ldr %[t], [%[x],#8] \n\t"
            "ldr %[s], [%[y],#8] \n\t"
            "adc %[t], %[t], %[s] \n\t"
            "str %[t], [%[r],#8] \n\t"
            "ldr %[t], [%[x],#12] \n\t"
            "ldr %[s], [%[y],#12] \n\t"
            "adc %[t], %[t], %[s] \n\t"
            "str %[t], [%[r],#12] \n\t"
            "b .foot \n\t"
        ".add8: \n\t"
            "ldr %[t], [%[x],#0] \n\t"
            "ldr %[s], [%[y],#0] \n\t"
            "add %[t], %[t], %[s] \n\t"
            "str %[t], [%[r],#0] \n\t"
            "ldr %[t], [%[x],#4] \n\t"
            "ldr %[s], [%[y],#4] \n\t"
            "adc %[t], %[t], %[s] \n\t"
            "str %[t], [%[r],#4] \n\t"
            "ldr %[t], [%[x],#8] \n\t"
            "ldr %[s], [%[y],#8] \n\t"
            "adc %[t], %[t], %[s] \n\t"
            "str %[t], [%[r],#8] \n\t"
            "ldr %[t], [%[x],#12] \n\t"
            "ldr %[s], [%[y],#12] \n\t"
            "adc %[t], %[t], %[s] \n\t"
            "str %[t], [%[r],#12] \n\t"
            "ldr %[t], [%[x],#16] \n\t"
            "ldr %[s], [%[y],#16] \n\t"
            "adc %[t], %[t], %[s] \n\t"
            "str %[t], [%[r],#16] \n\t"
            "ldr %[t], [%[x],#20] \n\t"
            "ldr %[s], [%[y],#20] \n\t"
            "adc %[t], %[t], %[s] \n\t"
            "str %[t], [%[r],#20] \n\t"
            "ldr %[t], [%[x],#24] \n\t"
            "ldr %[s], [%[y],#24] \n\t"
            "adc %[t], %[t], %[s] \n\t"
            "str %[t], [%[r],#24] \n\t"
            "ldr %[t], [%[x],#28] \n\t"
            "ldr %[s], [%[y],#28] \n\t"
            "adc %[t], %[t], %[s] \n\t"
            "str %[t], [%[r],#28] \n\t"
        ".foot: \n\t"
            "bcc .nocarry \n\t"
            "mov %[t], #1 \n\t"
            "b .end \n\t"
        ".nocarry: \n\t"
            "mov %[t], #0 \n\t"
        ".end: \n\t"
    : /* out */
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
    uint32_t c[8] = {5, 5, 5, 5, 5, 5, 5, 5};
    uint8_t carry = ecc_add_n(a, b, c, 8);
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
