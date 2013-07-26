/* __ER_COAP_13_DTLS_CCM_H__ */
#ifndef __ER_COAP_13_DTLS_CCM_H__
#define __ER_COAP_13_DTLS_CCM_H__

#include <stddef.h>
#include <stdint.h>

#define MAC_LEN 8                 // Länge des Authentication Fields    Element von {4, 6, 8, 10, 12, 14, 16}
#define LEN_LEN 7                 // Länge des Längenfeldes             Element von {2, 3, 4, 5, 6, 7, 8}
#define NONCE_LEN (15-LEN_LEN)    // Es Ergibt sich die Länge der Nonce

typedef struct {
  uint8_t nonce_explicit[NONCE_LEN];
  uint8_t ccm_ciphered[0];
} __attribute__ ((packed)) CCMData_t;

/**
  * \brief    AES-Initialisierung
  *
  *           Muss beim Start des Econotags einmalig aufgerufen
  *           werden um das AES-Modul zu initialisieren.
  *
  * \return   0 falls die Ausführung erfolgreich war
  *           -1 falls ein FEhler aufgetreten ist
  */
uint32_t aes_init();

/**
  * \brief    Ent- und Verschlüsselung
  *
  *           Ent- oder Verschlüsselt den unter data hinterlegten Text.
  *           Unter data muss genug Speicher reserviert sein, damit das
  *           Authentication Field an den Text gehangen werden kann.
  *           Die Nonce muss in data hinterlegt sein und len muss die
  *           Länge des Textes ohne Authentication Field enthalten.
  *
  * \param    key        Zeiger auf den 16 Byte langen Schlüssel
  * \param    data       Zeiger auf die CCM-Daten in denen die Nonce und
  *                      Klar- oder Geheimtext hinterlegt sein muss.
  * \param    len        Länge der übergebenen CCMData_t Struktur
  * \param    nonce_only Falls 1, wird nur die Mac berechnet und an den
  *                      Klar- oder Geheimtext gehangen.
  */
void crypt(uint8_t *key, CCMData_t *data, size_t len, uint8_t nonce_only);

/**
  * \brief    MAC-Position
  *
  *           Liefert den Zeiger auf die Position an der der MAC hinterlegt ist.
  *
  * \param    data       Zeiger auf die CCM-Daten
  * \param    len        Länge der übergebenen CCMData_t Struktur
  *
  * \return   Zeiger auf die Position an der der MAC hinterlegt ist
  */
uint8_t *getMAC(CCMData_t *data, size_t len);

void CBC_MAC(uint8_t *mac, size_t mac_len, uint8_t *key, uint8_t *data, size_t data_len);

#endif /* __ER_COAP_13_DTLS_CCM_H__ */
