CONTIKI_PROJECT = device

CONTIKI = ../contiki
TARGET = redbee-econotag
all: $(CONTIKI_PROJECT)

WITH_UIP6=1
UIP_CONF_IPV6=1
WITH_COAP=13

CFLAGS += -DWITH_COAP=13
CFLAGS += -DREST=coap_rest_implementation
CFLAGS += -DUIP_CONF_TCP=0
CFLAGS += -DDEBUG_PRINT=1
CFLAGS += -I../../contiki/apps/er-coap-13

LDFLAGS += "-Wl,-gc-sections"

# zusätzliche Bibliotheken aus $(CONTIKI)/apps
APPS += er-coap-13
APPS += erbium

# der eigentliche Code (nicht benoetigt, wenn nur eine Datei...)
PROJECT_SOURCEFILES = tools.c persist.c attributes.c

clear:
	sudo ../libmc1322x/tools/ftditools/bbmc -l redbee-econotag erase

upload:
	../blaster/blaster 19 < $(CONTIKI_PROJECT)_redbee-econotag.bin > \
	$(CONTIKI_PROJECT)_e_redbee-econotag.bin 2> \
	$(CONTIKI_PROJECT)_e_redbee-econotag.txt \
	
	../libmc1322x/tools/mc1322x-load \
	-f ../libmc1322x/tests/flasher_redbee-econotag.bin \
	-s $(CONTIKI_PROJECT)_e_redbee-econotag.bin \
	-c 'sudo ../libmc1322x/tools/ftditools/bbmc -l redbee-econotag -i 0 reset' \
	-t /dev/ttyUSB1 -e -v \
	
	sudo ../libmc1322x/tools/ftditools/bbmc -l redbee-econotag -i 0 reset

listen:
	while true; do cat /dev/ttyUSB1; done

include $(CONTIKI)/Makefile.include
