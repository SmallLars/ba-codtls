/* __COAP_CLIENT_H__ */
#ifndef __COAP_CLIENT_H__
#define __COAP_CLIENT_H__

#include <stddef.h>
#include <stdint.h>
#include <netinet/in.h>

#include "libcoap-4.0.1/coap.h"

typedef unsigned char method_t;

/**
  * \brief    Durchführen einer CoAP-Anfrage
  *
  *           Führt eine CoAP-Anfrage durch in blockiert, bis die Antwort
  *           eingetroffen ist; maximal jedoch 90 Sekunden.
  *
  * \param    ip        Zeiger auf die IP des CoAP-Servers
  * \param    my_method COAP_REQUEST_GET | COAP_REQUEST_POST
  * \param    my_res    URI der anzufragenden Ressource, wie bspw. ".well-known/core"
  * \param    target    Zeiger auf den Speicher in dem die Antwort abgelegt werden soll
  *
  * \return   Die Art der Antwort. 2 = Success, 4 = Client Error, 5 = Server Error
  */
int coap_request(uint8_t *ip, method_t my_method, char *my_res, char *target);

/**
  * \brief    Einfügen von Payload in eine CoAP-Anfrage
  *
  *           Setzt das Payload für eine nachfolgende CoAP-Anfrage
  *
  * \param    data   Zeiger auf die anzuhängenden Daten
  * \param    len    Länge der anzuhängenden Daten
  */
void coap_setPayload(uint8_t *data, size_t len);

/**
  * \brief    Setzen der Block-1-Option
  *
  *           Setzt die Block-1-Option für eine nachfolgende CoAP-Anfrage.
  *           Dadurch wird nur der entsprechende Block des Payloads angehängt.
  *
  * \param    num   Index des Blocks der übertragen werden soll
  * \param    m     Gibt an, ob weitere Blöcke folgen
  * \param    szx   2^(4 + szx) = Größe des Blocks der übertragen werden soll
  */
void coap_setBlock1(uint8_t num, uint8_t m, uint8_t szx);

/**
  * \brief    Änderung der Bestätigung
  *
  *           Bei Aufruf ist eine Beantwortung der nachfolgenden CoAP-Anfrage
  *           nicht notwendig. Bei Ausbleiben einer Antwort wird die Anfrage
  *           nicht wiederholt. Trotzdem wird 90 Sekunden auf eine Antwort gewartet.
  */
void coap_setNoneConfirmable();

/**
  * \brief    Änderung der Wartezeit
  *
  *           Ändert die standard Wartezeit von 90 Sekunden für die nachfolgenden CoAP-Anfrage.
  *
  * \param    secs   Anzahl der Sekunden, die auf eine Antwort gewartet wird
  */
void coap_setWait(uint32_t secs);

#endif /* __COAP_CLIENT_H__ */
