/* __COAP_DTLS_PRF_H__ */
#ifndef __COAP_DTLS_PRF_H__
#define __COAP_DTLS_PRF_H__

#include <stdint.h>

/**
  * \brief  Pseudorandom-Funktion basierend auf CBC-MAC
  *
  *         Erzeugt len Zufallsbyte an Position dst. Zur Berechnung
  *         werden seed_len Bytes an Position seed herangezogen.
  *         Anstatt HMAC wird hier der CBC-MAC mit dem derzeit gültigen
  *         Pre-shared Key verwendet.
  *
  *         PRF(secret, label, seed) = P_hash(secret + label + seed)
  *
  *         P_hash(seed) = CBC-MAC(A(1) + seed) +
  *                        CBC-MAC(A(2) + seed) +
  *                        CBC-MAC(A(3) + seed) + ...
  *         A(0) = seed
  *         A(i) = CBC-MAC(A(i-1))
  *
  * \param  dst         Zeiger auf die Position an dem die Zufallswerte
  *                     hinterlegt werden sollen
  * \param  len         Länge in Byte der gewünschten Zufallsdaten
  * \param  seed        Bytefolge die zur Berechnung der Zufallsdaten
                        herangezogen wird
  * \param  seed_len    Länge der Bytefolge
  */
void prf(uint8_t *dst, uint8_t len, uint8_t *seed, uint16_t seed_len);

#endif /* __COAP_DTLS_PRF_H__ */


