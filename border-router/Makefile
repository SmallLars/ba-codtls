CONTIKI_PROJECT=border-router

CONTIKI=../contiki
TARGET = redbee-econotag
all: $(CONTIKI_PROJECT) 

WITH_UIP6=1
UIP_CONF_IPV6=1
CFLAGS+= -DUIP_CONF_IPV6_RPL

#linker optimizations
SMALL=1

CFLAGS += -DPROJECT_CONF_H=\"project-conf.h\"
PROJECT_SOURCEFILES += slip-bridge.c

#Simple built-in webserver is the default.
#Override with make WITH_WEBSERVER=0 for no webserver.
#WITH_WEBSERVER=webserver-name will use /apps/webserver-name if it can be
#found in the /apps, /platform/$(TARGET)/apps/, or current directory (in that order).
# WITH_WEBSERVER=webserver for /apps/webserver
# WITH_WEBSERVER=raven-webserver for /platform/avr-raven/apps/raven-webserver/
#make clean before changing webservers!

#Note /apps/webserver contains a 2500 byte style sheet which is a severe test
#of the slip connection. Large MSS together with low baud rates without flow
#control will overrun the transmit buffer when the style sheet is requested.

WITH_WEBSERVER=1
ifeq ($(WITH_WEBSERVER),1)
CFLAGS += -DWEBSERVER=1
PROJECT_SOURCEFILES += httpd-simple.c
else ifneq ($(WITH_WEBSERVER), 0)
APPS += $(WITH_WEBSERVER)
CFLAGS += -DWEBSERVER=2
endif

ifeq ($(PREFIX),)
 PREFIX = aaaa::1/64
endif

clear:
	sudo ../libmc1322x/tools/ftditools/bbmc -l redbee-econotag erase

upload:
	../blaster/blaster 22 < $(CONTIKI_PROJECT)_redbee-econotag.bin > \
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

border:
	sudo ../contiki/tools/tunslip6 -s /dev/ttyUSB1 aaaa::1/64

include $(CONTIKI)/Makefile.include

$(CONTIKI)/tools/tunslip6:	$(CONTIKI)/tools/tunslip6.c
	(cd $(CONTIKI)/tools && $(MAKE) tunslip6)

connect-router:	$(CONTIKI)/tools/tunslip6
	sudo $(CONTIKI)/tools/tunslip6 $(PREFIX)

connect-router-cooja:	$(CONTIKI)/tools/tunslip6
	sudo $(CONTIKI)/tools/tunslip6 -a 127.0.0.1 $(PREFIX)
