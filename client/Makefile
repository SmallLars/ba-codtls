#
# MAKEFILE for client
#

# Value of RAND_GEN determines the strength of the random number generator
# 0 - /dev/zero (do not use for everything else than testing)
# 1 - /dev/urandom (default)
# 2 - /dev/random (very secure but blocks if not enough entropy)
RAND_GEN=1

CC = gcc

CFLAGS=-Wall -pthread -O2 -g
LDFLAGS= -lssl -lcrypto -luuid
DEFINES= -DRND_DEV=${RAND_GEN}

FLAGS=${CFLAGS} ${LDFLAGS} ${DEFINES}

all: client

HEADERS = ip_tools.h ip_list.h border_com.h node_com.h

%.o: %.c $(HEADERS)
	$(CC) -c $(CFLAGS) -o $@ $< ${DEFINES}

libcoap-4.0.1/libcoap.a:
	make -C libcoap-4.0.1

client: client.o ip_tools.o ip_list.o border_com.o node_com.o coap_client.o libcoap-4.0.1/libcoap.a
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) ${DEFINES}

clean:
	rm *.o client
	make -C libcoap-4.0.1 clean

.PHONY: all clean
