/* __AES_H__ */
#ifndef __AES_H__
#define __AES_H__

#include <stddef.h>
#include <stdint.h>

#define MAC_LEN 8                 // Länge des Authentication Fields    Element von {4, 6, 8, 10, 12, 14, 16}
#define LEN_LEN 3                 // Länge des Längenfeldes             Element von {2, 3, 4, 5, 6, 7, 8}
#define NONCE_LEN (15-LEN_LEN)    // Es ergibt sich die Länge der Nonce

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
  *         Ent- oder Verschlüsselt den unter data hinterlegten Text der
  *         Länge data_len. Das Authentication Field wird an Position data + data_len
  *         hinterlegt. Die Nonce muss an Position nonce hinterlegt sein und
  *         der Key an Position key. Bei mac_only == 1 wird ausschließlich das
  *         Authentication Field berechnet und an Position data + data_len hinterlegt.
  *
  * \param  data        Zeiger auf die Position der Daten an der
  *                     der Klar- oder Geheimtext hinterlegt sein muss
  * \param  data_len    Länge der Klar- oder Geheimtext-Daten
  * \param  key         Zeiger auf den 16 Byte langen Schlüssel
  * \param  nonce       Zeiger auf die Nonce, die zur Ent- oder
  *                     Verschlüsselung verwendet wird
  * \param  mac_only    Falls 1, wird nur die Mac berechnet und an Position
  *                     data + data_len hinterlegt ohne die Daten zu verändern
  */
void aes_crypt(uint8_t data[], size_t data_len, uint8_t key[16], uint8_t nonce[NONCE_LEN], uint8_t mac_only);

/**
  * \brief  CMAC-Berechnung
  *
  *         Berechnet den CMAC der Daten an Position data. Für die
  *         Berechnung werden data_len Bytes einbezogen. Der CMAC
  *         wird in 16 Byte Blöcken berechnet. Der letzte Block wird entsprechend
  *         CMAC-Vorgabe behandelt, falls finish 1 ist. Das 16 Byte lange
  *         Ergebnis wird an der Position mac hinterlegt. Zu beginn muss der Speicher
  *         an Position mac genullt sein, falls ein neuer MAC berechnet werden
  *         soll. Ansonsten werden die Daten an Position MAC als Initialisierungs-
  *         vektor genutzt, so dass eine MAC-Berechnung jederzeit fortgesetzt
  *         werden kann. Als Schlüssel wird der derzeit gültige Pre-shared Key benutzt.
  *
  * \param  mac         Position an der der IV liegt bzw. die MAC abgelegt wird (16 Byte)
  * \param  data        Position der Daten für die ein MAC berechnet werden soll
  * \param  data_len    Länge der Daten für die ein MAC berechnet werden soll
  * \param  key         Zeiger auf den 16 Byte langen Schlüssel
  * \param  finish      Falls 1, wird der letzte Block entsprechend CMAC-Vorgabe behandelt
  */
void aes_cmac(uint8_t mac[16], uint8_t data[], size_t data_len, uint8_t key[16], uint8_t finish);

#endif /* __AES_H__ */
