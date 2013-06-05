CONTIKI_PROJECT = device

CONTIKI = ../contiki
TARGET = redbee-econotag
all: $(CONTIKI_PROJECT)

WITH_UIP6=1
UIP_CONF_IPV6=1
WITH_COAP=12

CFLAGS += -DWITH_COAP=12
CFLAGS += -DREST=coap_rest_implementation
CFLAGS += -DUIP_CONF_TCP=0
CFLAGS += -I../../contiki/apps/er-coap-12

LDFLAGS += "-Wl,-gc-sections"

# zusätzliche Bibliotheken aus $(CONTIKI)/apps
APPS += er-coap-12
APPS += erbium

# der eigentliche Code (nicht benoetigt, wenn nur eine Datei...)
PROJECT_SOURCEFILES = tools.c persist.c attributes.c handshake.c

clear:
	sudo ../libmc1322x/tools/ftditools/bbmc -l redbee-econotag erase

upload:
	../blaster/blaster 19 < device_redbee-econotag.bin > device_e_redbee-econotag.bin 2> device_e_redbee-econotag.txt
	../libmc1322x/tools/mc1322x-load.pl -f ../libmc1322x/tests/flasher_redbee-econotag.bin -s device_e_redbee-econotag.bin -t /dev/ttyUSB1

include $(CONTIKI)/Makefile.include
