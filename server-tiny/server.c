//#include "attributes.h"
#include "button-sensor.h"
#include "leds.h"

#include "./contiki/apps/tinydtls/config.h"
#include "./contiki/apps/tinydtls/dtls.h"

#define UIP_IP_BUF ((struct uip_ip_hdr *)&uip_buf[UIP_LLH_LEN])
#define UIP_UDP_BUF ((struct uip_udp_hdr *)&uip_buf[UIP_LLIPH_LEN])

int send_to_peer(struct dtls_context_t *, session_t *, uint8 *, size_t);

static struct uip_udp_conn *server_conn;
static dtls_context_t *dtls_context;
static dtls_handler_t cb = {
    .write = send_to_peer,
    .read = NULL,
    .event = NULL
};

#define MYDEBUG 1

#if MYDEBUG
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

    dtls_init();

    server_conn = udp_new(NULL, 0, NULL);
    udp_bind(server_conn, UIP_HTONS(5684));

    dtls_context = dtls_new_context(server_conn);
    if (!dtls_context) {
        PROCESS_EXIT();
    }

    dtls_set_handler(dtls_context, &cb);

//    rest_init_engine();

//    rest_activate_resource(&resource_device);
	while(1) {
		PROCESS_WAIT_EVENT();

		if (ev == sensors_event && data == &button_sensor) {
            #if MYDEBUG
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
        if (ev == tcpip_event && uip_newdata()) {
            session_t session;
            uip_ipaddr_copy(&session.addr, &UIP_IP_BUF->srcipaddr);
            session.port = UIP_UDP_BUF->srcport;
            session.size = sizeof(session.addr) + sizeof(session.port);
            dtls_handle_message(dtls_context, &session, uip_appdata, uip_datalen());
        }
	}

    PROCESS_END();
}

int send_to_peer(struct dtls_context_t *ctx, session_t *session, uint8 *data, size_t len) {
    struct uip_udp_conn *conn = (struct uip_udp_conn *)dtls_get_app_data(ctx);
    uip_ipaddr_copy(&conn->ripaddr, &session->addr);
    conn->rport = session->port;
    uip_udp_packet_send(conn, data, len);
    memset(&conn->ripaddr, 0, sizeof(server_conn->ripaddr));
    memset(&conn->rport, 0, sizeof(conn->rport));
    return len;
}
