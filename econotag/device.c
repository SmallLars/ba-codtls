#include "attributes.h"
#include "button-sensor.h"
#include "leds.h"

#define DEBUG 1

#if DEBUG
    #include <stdio.h>
    #define PRINTF(...) printf(__VA_ARGS__)
    extern uint32_t _start, _edata;
    extern uint32_t __stack_start__;
    extern uint32_t __irq_stack_top__, IRQ_STACK_SIZE;
    extern uint32_t __fiq_stack_top__, FIQ_STACK_SIZE;
    extern uint32_t __svc_stack_top__, SVC_STACK_SIZE;
    extern uint32_t __abt_stack_top__, ABT_STACK_SIZE;
    extern uint32_t __und_stack_top__, UND_STACK_SIZE;
    extern uint32_t __sys_stack_top__, SYS_STACK_SIZE;
    extern uint32_t __bss_start__, __bss_end__;
    extern uint32_t __heap_start__, __heap_end__, HEAP_SIZE;
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
    rest_activate_resource(&resource_firmware);

	while(1) {
		PROCESS_WAIT_EVENT();

		if (ev == sensors_event && data == &button_sensor) {
            leds_on(LEDS_GREEN);
            nvm_init();
            leds_off(LEDS_GREEN);

            #if DEBUG
                PRINTF("\n");
                PRINTF("Speicheraufteilung (Konfiguration in contiki/cpu/mc1322x/mc1322x.lds)\n");
                PRINTF("---------------------------------------------------------------------\n");
                PRINTF("\n");
                PRINTF("Beschreibung | Start      | Ende       | Größe\n");
                PRINTF("----------------------------------------------\n");
                PRINTF("Programm     | 0x%08x | 0x%08x | %5u\n", &_start, &_edata, (uint32_t) &_edata - (uint32_t) &_start);
                PRINTF("Irq Stack    | 0x%08x | 0x%08x | %5u\n", &__stack_start__, &__irq_stack_top__, &IRQ_STACK_SIZE);
                PRINTF("Fiq Stack    | 0x%08x | 0x%08x | %5u\n", &__irq_stack_top__, &__fiq_stack_top__, &FIQ_STACK_SIZE);
                PRINTF("Svc Stack    | 0x%08x | 0x%08x | %5u\n", &__fiq_stack_top__, &__svc_stack_top__, &SVC_STACK_SIZE);
                PRINTF("Abt Stack    | 0x%08x | 0x%08x | %5u\n", &__svc_stack_top__, &__abt_stack_top__, &ABT_STACK_SIZE);
                PRINTF("Und Stack    | 0x%08x | 0x%08x | %5u\n", &__abt_stack_top__, &__und_stack_top__, &UND_STACK_SIZE);
                PRINTF("Sys Stack    | 0x%08x | 0x%08x | %5u\n", &__und_stack_top__, &__sys_stack_top__, &SYS_STACK_SIZE);
                PRINTF("Datensegment | 0x%08x | 0x%08x | %5u\n", &__bss_start__, &__bss_end__, (uint32_t) &__bss_end__ - (uint32_t) &__bss_start__);
                PRINTF("Heap         | 0x%08x | 0x%08x | %5u\n", &__heap_start__, &__heap_end__, &HEAP_SIZE);
                PRINTF("Frei         | 0x%08x | 0x%08x | %5u\n", &__heap_end__, 0x418000, 0x418000 - (uint32_t) &__heap_end__);
                PRINTF("----------------------------------------------\n");
                PRINTF("Frei += 1132 bei der Deaktivierung dieser Auskunft\n");

                PRINTF("\n");

                // Folgende Ausgaben möglich durch Speicherinitialisierung in
                // contiki/platform/redbee-econotag/contiki-mc1322x-main.c
                // durch hinzufügen der Flags STACKMONITOR und HEAPMONITOR
                uint32_t p;
                p = (uint32_t) &__und_stack_top__;
                do {
                    if (*(uint32_t *)p != 0x42424242) {
                        PRINTF("Nie benutzer Stack > %d Byte\n", p - (uint32_t) &__und_stack_top__);
                        break;
                    }
                    p += 16;
                } while (p < (uint32_t) &__sys_stack_top__ - 100);
                p = (uint32_t) &__heap_end__ - 4;
                do {
                    if (*(uint32_t *)p != 0x42424242) {
                        break;
                    }
                    p -= 4;
                } while (p >= (uint32_t) &__heap_start__);
                PRINTF("Nie benutzer Heap >= %d Byte\n", (uint32_t) &__heap_end__ - p - 4);

                PRINTF("\n");
            #endif
		}
	}

    PROCESS_END();
}
