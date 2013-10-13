/* __DTLS_CLIENTHELLO_H__ */
#ifndef __DTLS_CLIENTHELLO_H__
#define __DTLS_CLIENTHELLO_H__

#include <stddef.h>
#include <stdint.h>
#include <time.h>

typedef struct {
    uint8_t major;
    uint8_t minor;
} __attribute__ ((packed)) ProtocolVersion;

typedef struct {
    uint32_t gmt_unix_time;
    uint8_t random_bytes[28];
} __attribute__ ((packed)) Random;

typedef struct {
    ProtocolVersion client_version;
    Random random;
    uint8_t data[0];
} __attribute__ ((packed)) ClientHello_t;

typedef struct {
    ProtocolVersion server_version;
    uint8_t cookie_len;
    uint8_t cookie[0];
} __attribute__ ((packed)) HelloVerifyRequest_t;

/**
  * \brief  Erzeugung einer ClientHello-Nachricht
  *
  *         Erzeugt eine ClientHello-Nachricht mit den übergebenen Parametern
  *         an Position target. Cookie kann dabei NULL sein.
  *
  * \param  target     Position an der die ClientHello-Nachricht abgelegt wird
  * \param  time       Unix-Timestamp, der in die ClientHello-Nachricht eingefügt wird
  * \param  random     Zeige auf einen 28 Byte langen Random-Wert, der in die ClientHello-Nachricht eingefügt wird
  * \param  cookie     Falls vorhanden, Zeiger auf einen Cookie, der in die ClientHello-Nachricht eingefügt wird
  * \param  cookie_len Länge des Cookies der in die ClientHello-Nachricht eingefügt wird
  *
  * \return Länge der erzeugten ClientHello-Nachricht
  */
size_t makeClientHello(uint8_t *target, time_t time, uint8_t *random, uint8_t *cookie, uint8_t cookie_len);

#endif /* __DTLS_CLIENTHELLO_H__ */
