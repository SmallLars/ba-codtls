/* __DTLS_HANDSHAKE_H__ */
#ifndef __DTLS_HANDSHAKE_H__
#define __DTLS_HANDSHAKE_H__

#include <netinet/in.h>

/**
  * \brief  DTLS-Handshake
  *
  *         Führt einen DTLS-Handshake durch.
  *
  * \param  ip  Zeiger auf die IP-Adresse des Servers, mit dem der Handshake durchgeführt werden soll
  */
void dtls_handshake(uint8_t ip[16]);

#endif /* __DTLS_HANDSHAKE_H__ */
