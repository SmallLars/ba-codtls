/* __COAP_CCM_H__ */
#ifndef __COAP_CCM_H__
#define __COAP_CCM_H__

#include <stdlib.h>
#include <stdint.h>

#define MAC_LEN 8                 // Länge des Authentication Fields    Element von {4, 6, 8, 10, 12, 14, 16}
#define LEN_LEN 7                 // Länge des Längenfeldes             Element von {2, 3, 4, 5, 6, 7, 8}
#define NONCE_LEN (15-LEN_LEN)    // Es Ergibt sich die Länge der Nonce

typedef struct {
  uint8_t nonce_explicit[8];
  uint8_t ccm_ciphered[];
} __attribute__ ((packed)) CCMData_t;

/**
  * \brief    MAC Position
  *
  *           Liefert den Zeiger auf den in der Struktur hinterlegten MAC.
  *
  * \param    c   Zeiger auf die Struktur mit Nonce und Daten
  * \param    len Länge der CCMData Struktur
  *
  * \return   
  */
uint8_t *getMAC(CCMData_t *c, size_t len);

/**
  * \brief    Verschlüsselung
  *
  *           Verschlüsselt die in c hinterlegten Daten. Eine Nonce
  *           muss in c schon hinterlegt sein. Die Daten werden verschlüsselt
  *           und ein 8 Byte langer MAC wird angehangen. Genug Speicher muss
  *           reserviert sein.
  *
  * \param    c   Zeiger auf die Struktur mit Nonce und Klartextdaten
  * \param    key Schlüssel mit dem die Daten verschlüsselt und der MAC erzeugt wird
  * \param    len Länge der CCMData Struktur
  */
void encrypt(CCMData_t *c, uint8_t *key, size_t len);

/**
  * \brief    Entschlüsselung
  *
  *           Entschlüsselt die in c hinterlegten Daten. Eine Nonce
  *           muss in c schon hinterlegt sein. Die Daten werden entschlüsselt
  *           und ein 8 Byte langer MAC wird angehangen, wobei der der alte
  *           MAC überschrieben wird.
  *
  * \param    c   Zeiger auf die Struktur mit Nonce und Geheimtext
  * \param    key Schlüssel mit dem die Daten entschlüsselt und der MAC erzeugt wird
  * \param    len Länge der CCMData Struktur
  */
void decrypt(CCMData_t *c, uint8_t *key, size_t len);

#endif /* __COAP_CCM__ */
