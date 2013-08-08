/* __ER_COAP_13_DTLS_CCM_H__ */
#ifndef __ER_COAP_13_DTLS_CCM_H__
#define __ER_COAP_13_DTLS_CCM_H__

#include <stddef.h>
#include <stdint.h>

#define MAC_LEN 8                 // Länge des Authentication Fields    Element von {4, 6, 8, 10, 12, 14, 16}
#define LEN_LEN 7                 // Länge des Längenfeldes             Element von {2, 3, 4, 5, 6, 7, 8}
#define NONCE_LEN (15-LEN_LEN)    // Es Ergibt sich die Länge der Nonce

/**
  * \brief  AES-Initialisierung
  *
  *         Muss beim Start des Econotags einmalig aufgerufen
  *         werden um das AES-Modul zu initialisieren.
  *
  * \return 0 falls die Ausführung erfolgreich war
  *         -1 falls ein Fehler aufgetreten ist
  */
uint32_t aes_init();

/**
  * \brief  Ent- und Verschlüsselung
  *
  *         Ent- oder Verschlüsselt des unter data hinterlegten Textes der
  *         Länge data_len. Das Authentication Field wird an Position mac
  *         hinterlegt. Die Nonce muss an Position nonce hinterlegt sein und
  *         der Key an Position key. Bei mac_only == 1 wird ausschließlich
  *         Authentication Field berechnet und an Position mac hinterlegt.
  *
  * \param  mac         Zeiger auf die Position an der der MAC hinterlegt wird
  * \param  data        Zeiger auf die Daten in denen der Klar- oder
  *                     Geheimtext hinterlegt sein muss
  * \param  data_len    Länge der übergebenen Daten
  * \param  key         Zeiger auf den 16 Byte langen Schlüssel
  * \param  nonce       Zeiger auf die Nonce die zur Ent- oder
  *                     Verschlüsselung verwendet wird
  * \param  mac_only    Falls 1, wird nur die Mac berechnet und an
  *                     Position mac hinterlegt ohne die Daten zu verändern
  */
void crypt(uint8_t mac[MAC_LEN], uint8_t data[], size_t data_len, uint8_t key[16], uint8_t nonce[NONCE_LEN], uint8_t mac_only);

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
  *         werden kann.
  *
  * \param  mac         Position an der der IV liegt bzw. die MAC abgelegt wird (16 Byte)
  * \param  data        Position der Daten für die ein MAC berechnet werden soll
  * \param  data_len    Länge der Daten für die ein MAC berechnet werden soll
  * \param  key         Schlüssel der für die CBC-MAC-Berechnung genutzt wird (16 Byte)
  */
void CBC_MAC_16(uint8_t mac[16], uint8_t data[], size_t data_len, uint8_t key[16]);

#endif /* __ER_COAP_13_DTLS_CCM_H__ */
