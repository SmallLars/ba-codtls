CC = gcc

CFLAGS = -Wall -pthread -O2 -g
LDFLAGS = -lssl -lcrypto -luuid
DEFINES =

HEADERS = ip_tools.h ip_list.h border_com.h node_com.h coap_client.h libcoap-4.0.1/coap_client.h dtls/dtls.h

all: client

%.o: %.c $(HEADERS)
	$(CC) -c $(CFLAGS) -o $@ $< ${DEFINES}

libcoap-4.0.1/Makefile:
	cd libcoap-4.0.1 && ./configure

libcoap-4.0.1/libcoap.a: libcoap-4.0.1/Makefile
	make -C libcoap-4.0.1

dtls/dtls.a:
	make -C dtls

client: client.o ip_tools.o ip_list.o border_com.o node_com.o coap_client.o libcoap-4.0.1/libcoap.a dtls/dtls.a
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	-rm *.o client
	-make -C libcoap-4.0.1 clean
	-make -C dtls clean

.PHONY: all clean
