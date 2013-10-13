/* __ER_DTLS_13_PRF_H__ */
#ifndef __ER_DTLS_13_PRF_H__
#define __ER_DTLS_13_PRF_H__

#include <stdint.h>

/**
  * \brief  Pseudorandom-Funktion basierend auf CMAC
  *
  *         Erzeugt len Zufallsbyte an Position dst. Zur Berechnung
  *         werden seed_len Bytes an Position seed herangezogen.
  *         Anstatt HMAC wird hier der CMAC mit dem derzeit gültigen
  *         Pre-shared Key verwendet.
  *
  *         PRF(label, seed) = P_hash(label + seed)
  *
  *         P_hash(seed) = CMAC(psk, A(1) + seed) +
  *                        CMAC(psk, A(2) + seed) +
  *                        CMAC(psk, A(3) + seed) + ...
  *         A(0) = seed
  *         A(i) = CMAC(psk, A(i-1))
  *
  * \param  dst         Zeiger auf die Position an dem die Zufallswerte
  *                     hinterlegt werden sollen
  * \param  len         Länge in Byte der gewünschten Zufallsdaten
  * \param  seed        Bytefolge die zur Berechnung der Zufallsdaten
                        herangezogen wird
  * \param  seed_len    Länge der Bytefolge
  */
void prf(uint8_t *dst, uint8_t len, uint8_t *seed, uint16_t seed_len);

#endif /* __ER_DTLS_13_PRF_H__ */


