/* __DTLS_PRF_H__ */
#ifndef __DTLS_PRF_H__
#define __DTLS_PRF_H__

#include <stdint.h>

/**
  * \brief  Pseudorandom-Funktion basierend auf CMAC
  *
  *         Erzeugt len Zufallsbyte an Position dst. Zur Berechnung
  *         werden seed_len Bytes an Position seed herangezogen.
  *         Anstatt HMAC wird hier der CMAC verwendet.
  *
  *         PRF(secret, label, seed) = P_hash(secret + label + seed)
  *
  *         P_hash(seed) = CMAC(A(1) + seed) +
  *                        CMAC(A(2) + seed) +
  *                        CMAC(A(3) + seed) + ...
  *         A(0) = seed
  *         A(i) = CMAC(A(i-1))
  *
  *         CMAC(data) = AES-CMAC(psk, data)
  *
  * \param  dst         Zeiger auf die Position an dem die Zufallswerte
  *                     hinterlegt werden sollen
  * \param  len         Länge in Byte der gewünschten Zufallsdaten
  * \param  psk         Für AES-CMAC genutzter Schlüssel
  * \param  seed        Bytefolge die zur Berechnung der Zufallsdaten
                        herangezogen wird
  * \param  seed_len    Länge der Bytefolge
  */
void prf(uint8_t *dst, uint8_t len, uint8_t psk[16], uint8_t *seed, uint16_t seed_len);

#endif /* __DTLS_PRF_H__ */


