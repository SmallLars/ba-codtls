/* __DTLS_CCM_H__ */
#ifndef __DTLS_CCM_H__
#define __DTLS_CCM_H__

#include <stdlib.h>
#include <stdint.h>

#define MAC_LEN 8                 // Länge des Authentication Fields    Element von {4, 6, 8, 10, 12, 14, 16}
#define LEN_LEN 3                 // Länge des Längenfeldes             Element von {2, 3, 4, 5, 6, 7, 8}
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
void aes_encrypt(uint8_t data[], size_t data_len, uint8_t key[16], uint8_t nonce[NONCE_LEN]);

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
void aes_decrypt(uint8_t data[], size_t data_len, uint8_t key[16], uint8_t nonce[NONCE_LEN]);

/**
  * \brief  CBC-MAC-Berechnung
  *
  *         Berechnet die CBC-MAC der Daten an Position data. Für die
  *         Berechnung werden data_len Bytes einbezogen. Die CBC-MAC
  *         wird in 16 Byte Blöcken berechnet. Der letzte Block wird bei
  *         Bedarf mit 0en aufgefüllt. Das 16 Byte lange Ergebnis wird
  *         an der Position mac hinterlegt. Zu beginn muss der Speicher an
  *         Position mac genullt sein, falls ein neuer MAC berechnet werden
  *         soll. Ansonsten werden die Daten an Position MAC als Initialisierungs-
  *         vektor genutzt, so dass eine MAC-Berechnung jederzeit fortgesetzt
  *         werden kann. Als Schlüssel wird der derzeit gültige Pre-shared Key benutzt.
  *
  * \param  mac         Position an der der IV liegt bzw. die MAC abgelegt wird (16 Byte)
  * \param  data        Position der Daten für die ein MAC berechnet werden soll
  * \param  data_len    Länge der Daten für die ein MAC berechnet werden soll
  */
void aes_cmac(uint8_t mac[16], uint8_t data[], size_t data_len, uint8_t finish);

#endif /* __DTLS_CCM__ */
