CONTIKI_PROJECT = ../libmc1322x/tests/rftest-rx

all: upload

clear:
	sudo ../libmc1322x/tools/ftditools/bbmc -l redbee-econotag erase

upload:
	../libmc1322x/tools/mc1322x-load \
	-f ../libmc1322x/tests/flasher_redbee-econotag.bin \
	-s rftest-rx_redbee-econotag.bin 0x1e000,0xB160B162,0x2800B160 \
	-c 'sudo ../libmc1322x/tools/ftditools/bbmc -l redbee-econotag -i 0 reset' \
	-t /dev/ttyUSB1 -e \
	
	sudo ../libmc1322x/tools/ftditools/bbmc -l redbee-econotag -i 0 reset

listen:
	../libmc1322x/tools/rftestrx2pcap.py /dev/ttyUSB3 26 | wireshark -k -i -

listen2:
	../libmc1322x/tools/rftestrx2pcap.py /dev/ttyUSB3 26 > cap.pcap
