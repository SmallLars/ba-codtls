CONTIKI_PROJECT = server

CONTIKI = ../contiki
TARGET = redbee-econotag
all: $(CONTIKI_PROJECT) copy

WITH_UIP6=1
UIP_CONF_IPV6=1
WITH_DTLS=1
WITH_COAP=13

CFLAGS += -DWITH_DTLS=1
CFLAGS += -DWITH_COAP=13
CFLAGS += -DREST=coap_rest_implementation
CFLAGS += -DUIP_CONF_TCP=0
#??? CFLAGS += -DDEBUG_PRINT=1
CFLAGS += -I../../contiki/apps/er-coap-13
# CFLAGS += -Wcast-align -Wall -Wstrict-prototypes -Wextra
# http://www.gnu.org/software/gsl/manual/html_node/GCC-warning-options-for-numerical-programs.html

LDFLAGS += "-Wl,-gc-sections"

# zusätzliche Bibliotheken aus $(CONTIKI)/apps
APPS += er-dtls-13
APPS += er-coap-13
APPS += erbium
APPS += flash-store
APPS += ecc
APPS += time

# der eigentliche Code (nicht benoetigt, wenn nur eine Datei...)
PROJECT_SOURCEFILES = attributes.c flasher.c

copy:
	 cp $(CONTIKI_PROJECT)_redbee-econotag.bin ../client/$(CONTIKI_PROJECT)_redbee-econotag.bin

clear:
	-rm $(CONTIKI_PROJECT)_e_redbee-econotag.bin
	-rm $(CONTIKI_PROJECT)_e_redbee-econotag.txt
	-rm qr-code.pbm
	sudo ../libmc1322x/tools/ftditools/bbmc -l redbee-econotag -i 0 erase

upload:
	../blaster/blaster 19 -t < $(CONTIKI_PROJECT)_redbee-econotag.bin > \
	$(CONTIKI_PROJECT)_e_redbee-econotag.bin 2> \
	$(CONTIKI_PROJECT)_e_redbee-econotag.txt \
	
	../libmc1322x/tools/mc1322x-load \
	-f ../libmc1322x/tests/flasher_redbee-econotag.bin \
	-s $(CONTIKI_PROJECT)_e_redbee-econotag.bin \
	-c 'sudo ../libmc1322x/tools/ftditools/bbmc -l redbee-econotag -i 0 reset' \
	-t /dev/ttyUSB1 -e \
	
	sudo ../libmc1322x/tools/ftditools/bbmc -l redbee-econotag -i 0 reset

listen:
	while true; do cat /dev/ttyUSB1; done

eccasm:
	arm-none-eabi-gcc -Werror -mcpu=arm7tdmi-s -mthumb-interwork \
	-march=armv4t -mtune=arm7tdmi-s -Os -fno-strict-aliasing \
	-fno-common -ffixed-r8 -msoft-float -fno-builtin-printf \
	-fno-builtin-sprintf -ffunction-sections -fdata-sections \
	-MMD -mthumb -mcallee-super-interworking ../contiki/apps/ecc/ecc.c -S

include $(CONTIKI)/Makefile.include
