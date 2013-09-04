CC = gcc

CFLAGS= -Wall -pthread -O2 -g

HEADERS = dtls.h dtls_aes.h dtls_clientHello.h dtls_content.h dtls_data.h \
	dtls_ecc.h dtls_handshake.h dtls_keyExchange.h dtls_prf.h dtls_random.h \
	dtls_serverHello.h

all: dtls.a

%.o: %.c $(HEADERS)
	$(CC) -c $(CFLAGS) -o $@ $< ${DEFINES}

dtls.a: dtls.o dtls_aes.o dtls_clientHello.o dtls_content.o dtls_data.o \
	dtls_ecc.o dtls_handshake.o dtls_prf.o dtls_random.o
	ar cru $@ $^ 
	ranlib $@

clean:
	-rm *.o dtls.a

.PHONY: all clean
