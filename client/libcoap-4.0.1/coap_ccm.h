/* __COAP_CCM_H__ */
#ifndef __COAP_CCM_H__
#define __COAP_CCM_H__

#include <stdlib.h>
#include <stdint.h>

#define MAC_LEN 8                 // Länge des Authentication Fields    Element von {4, 6, 8, 10, 12, 14, 16}
#define LEN_LEN 7                 // Länge des Längenfeldes             Element von {2, 3, 4, 5, 6, 7, 8}
#define NONCE_LEN (15-LEN_LEN)    // Es Ergibt sich die Länge der Nonce

/**
  * \brief  Verschlüsselung
  *
  *         Verschlüsselt die in data hinterlegten Daten mit key und nonce.
  *         Die Daten werden verschlüsselt und ein 8 Byte langer MAC wird
  *         angehangen. Genug Speicher muss reserviert sein.
  *
  * \param  data        Zeiger auf die Struktur mit Nonce und Klartextdaten
  * \param  data_len    Länge der Klartextdaten
  * \param  key         Schlüssel mit dem die Daten verschlüsselt und der MAC erzeugt wird
  * \param  nonce       Nonce die zur Verschlüsselung der Daten herangezogen wird
  */
void encrypt(uint8_t data[], size_t data_len, uint8_t key[16], uint8_t nonce[NONCE_LEN]);

/**
  * \brief    Entschlüsselung
  *
  *           Entschlüsselt die in datahinterlegten Daten mit key und nonce.
  *           Die Daten werden entschlüsselt und ein 8 Byte langer MAC wird
  *           angehangen, wobei der der alte MAC überschrieben wird.
  *
  * \param  data        Zeiger auf die Struktur mit Nonce und Klartextdaten
  * \param  data_len    Länge der Klartextdaten
  * \param  key         Schlüssel mit dem die Daten entschlüsselt und der MAC erzeugt wird
  * \param  nonce       Nonce die zur Entschlüsselung der Daten herangezogen wird
  */
void decrypt(uint8_t data[], size_t data_len, uint8_t key[16], uint8_t nonce[NONCE_LEN]);

#endif /* __COAP_CCM__ */
