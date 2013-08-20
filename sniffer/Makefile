CONTIKI_PROJECT = ../libmc1322x/tests/rftest-rx

all: upload

clear:
	-rm rftest-rx_e_redbee-econotag.bin
	-rm rftest-rx_e_redbee-econotag.txt
	-rm qr-code.pbm
	sudo ../libmc1322x/tools/ftditools/bbmc -l redbee-econotag erase

upload:
	../blaster/blaster 28 < $(CONTIKI_PROJECT)_redbee-econotag.bin > \
	rftest-rx_e_redbee-econotag.bin 2> \
	rftest-rx_e_redbee-econotag.txt \
	
	../libmc1322x/tools/mc1322x-load \
	-f ../libmc1322x/tests/flasher_redbee-econotag.bin \
	-s rftest-rx_e_redbee-econotag.bin \
	-c 'sudo ../libmc1322x/tools/ftditools/bbmc -l redbee-econotag -i 0 reset' \
	-t /dev/ttyUSB1 -e -v \
	
	sudo ../libmc1322x/tools/ftditools/bbmc -l redbee-econotag -i 0 reset

listen:
	../libmc1322x/tools/rftestrx2pcap.py /dev/ttyUSB3 26 | wireshark -k -i -

listen2:
	../libmc1322x/tools/rftestrx2pcap.py /dev/ttyUSB3 26 > cap.pcap
