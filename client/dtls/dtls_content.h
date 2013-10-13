/* __DTLS_CONTENT_H__ */
#ifndef __DTLS_CONTENT_H__
#define __DTLS_CONTENT_H__

#include <stddef.h>
#include <netinet/in.h>

typedef enum {
    hello_request = 0,
    client_hello = 1,
    server_hello = 2,
    hello_verify_request = 3, 
    certificate = 11,
    server_key_exchange = 12,
    certificate_request = 13,
    server_hello_done = 14,
    certificate_verify = 15,
    client_key_exchange = 16,
    finished = 20,
    change_cipher_spec = 32,
    alert = 33,
    // max = 63
} __attribute__ ((packed)) ContentType;

/**
  * \brief    Suche nach einem ContentType
  *
  *           Sucht an Position data nach dem übergebenen ContentType.
  *           Jedoch geht die Suche maximal bis zur übergebenen Länge.
  *
  * \param    data  Position ab der gesucht wird
  * \param    len   maximale Länge des Bereichs der durchsucht wird
  * \param    type  ContentType nach dem gesucht wird
  *
  * \return   Zeiger auf den gesuchten Content, falls gefunden. Sonst NULL
  */
void *getContent(void *data, size_t len, ContentType type);

/**
  * \brief    Ermittlung des ContentType
  *
  *           Ermittelt den ContentType des Contents an Position data.
  *
  * \param    data  Position ab der der Content hinterlegt ist
  *
  * \return   Ermittelter ContentType
  */
ContentType getContentType(void *data);

/**
  * \brief    Ermittlung der Länge des gesamten Contents
  *
  *           Ermittelt die Länge des gesamten Contents inklusive Header.
  *
  * \param    data  Position an der der Content hinterlegt ist
  *
  * \return   Ermittelte Länge des gesamten Contents
  */
size_t getContentLen(void *data);

/**
  * \brief    Ermittlung der Länge der Content-Daten
  *
  *           Ermittelt die Länge der im Content enthaltenen Daten.
  *
  * \param    data  Position an der der Content hinterlegt ist
  *
  * \return   Ermittelte Länge der Content-Daten
  */
size_t getContentDataLen(void *data);

/**
  * \brief    Suche nach den Content-Daten
  *
  *           Ermittelt Postion der im Content enthaltenen Daten.
  *
  * \param    data  Position an der der Content hinterlegt ist
  *
  * \return   Zeiger auf die im Content enthaltenen Daten
  */
void *getContentData(void *data);

/**
  * \brief    Erstellung eines Contents
  *
  *           Erstellt an Position dst Content vom übergebenen Typ
  *           und hinterlegt die übergebenen Daten darin.
  *
  * \param    dst   Position an der der Content hinterlegt wird
  * \param    type  Typ des Contents der erzeugt wird
  * \param    data  Daten die im Content hinterlegt werden
  * \param    len   Länge der Daten die im Content hinterlegt werden
  *
  * \return   Gesamtgröße des erstellten Contents
  */
size_t makeContent(void *dst, ContentType type, void *data, size_t len);

#endif /* __DTLS_CONTENT_H__ */
