/* __ER_COAP_13_DTLS_PSK_H__ */
#ifndef __ER_COAP_13_DTLS_PSK_H__
#define __ER_COAP_13_DTLS_PSK_H__

#include <stdint.h>

/**
  * \brief  Ermittlung und Ausgabe des derzeit gültigen Pre-shared Key
  *
  *         Hinterlegt den derzeit gültigen 16 Byte langen Pre-shared Key
  *         in dst.
  *
  * \param  dst Zeiger auf den Speicher an dem der 16 Byte lange
  *             Pre-shared Key hinterlegt werden soll
  */
void getPSK(uint8_t *dst);

/**
  * \brief  Generierung eines neuen Pre-shared Key
  *
  *         Ersetzt den alten Pre-shared Key durch einen neuen zufällig
  *         generierten Pre-shared Key.
  */
void newPSK();

#endif /* __ER_COAP_13_DTLS_PSK_H__ */
