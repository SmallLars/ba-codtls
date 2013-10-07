/* __ER_DTLS_13_DATA_H__ */
#ifndef __ER_DTLS_13_DATA_H__
#define __ER_DTLS_13_DATA_H__

#include <stddef.h>
#include <stdint.h>

#include "flash-store.h"
#include "contiki-net.h"

typedef struct { // 16 + 8 + 2 + 2 + 32 = 60
    uip_ipaddr_t addr;
    uint8_t session[8];
    uint16_t epoch;
    uint16_t valid;    // Platz ist frei oder wird benutzt
    uint32_t private_key[8];
}  __attribute__ ((packed)) Session_t;
// valid ist 16 Bit groß und steht nicht vorne, um eine
// Ausrichtung der Werte an 32-bit-Blöcken sicherzustellen

typedef union {
    uint8_t key_block[40];
    struct {
//      uint8_t client_MAC[0];
//      uint8_t server_MAC[0];
        uint8_t client_key[16];
        uint8_t server_key[16];
        uint8_t client_IV[4];
        uint8_t server_IV[4];
    } write;
}  __attribute__ ((packed)) KeyBlock_t;

#define KEY_BLOCK_CLIENT_KEY  0
#define KEY_BLOCK_SERVER_KEY 16
#define KEY_BLOCK_CLIENT_IV  32
#define KEY_BLOCK_SERVER_IV  36

typedef enum {
    session_id = 0,
    session_epoch = 1,
    session_key = 2,
    session_num_write = 3
} SessionDataType;

// ----------------------------------------------------------------------------

/**
  * \brief    Erzeugt eine Session
  *
  *           Falls für die übergebene IP-Adresse schon eine Session existiert,
  *           wird lediglich ein neues Geheimnis für einen weiteren Handshake
  *           berechnet und gespeichert. Ansonsten wird, falls Speicher zur
  *           Verfügung ist, eine neue Session erzeugt.
  *
  * \param    buf   Mindestens 23 Worte langer Buffer.
                    Die Ausrichtung an Wortgrenzen ist zwingend erforderlich!
  * \param    addr  IP-Adresse für die die Session erzeugt werden soll.
  *
  * \return   0 bei Erfolg. -1 falls keine Session erzeugt werden konnte
  */
int createSession(uint32_t *buf, uip_ipaddr_t *addr);

/**
  * \brief    Abruf von einzelnen Sessionparametern
  *
  *           Ermöglicht den Abruf der Session-ID, der Epoche und des Geheimnisses
  *           für den Handshake. Wird die aktuelle Sequenznummer für einen Paketversand
  *           abgerufen, erhöht sich diese automatisch um eins. Die Sequenznummer wird
  *           in Network-Byte-Order in dst abgelegt.
  *
  * \param    dst   Zeiger auf die Stelle, an der die angeforderten Daten abgelegt werden sollen
  * \param    addr  IP-Adresse für die die Session-Daten abgerufen werden sollen
  * \param    type  Art der angeforderten Session-Daten
  *
  * \return   -1 falls keine Session bezüglich der übergeben IP-Adresse gefunden wurde.
  *           Ansonsten länge in Byte der in dst abgelegten Daten.
  */
int getSessionData(uint8_t *dst, uip_ipaddr_t *addr, SessionDataType type);

/**
  * \brief    Überprüfung der erhaltenen Sequenznummer
  *
  *           Überprüft die erhaltene Sequenznummer auf Gültigtkeit. Gültig ist diese
  *           falls sie innerhalb von -10 und +100 bezüglich der erwarteten Sequenznummer liegt.
  *           Erwartet ist immer die zuletzt geprüfte Sequenznummer + 1
  *
  * \param    addr      IP-Adresse für die die Sequenznummer überprüft werden soll
  * \param    seq_num   Zu überprüfende Sequenznummer in Network-Byte-Order
  *
  * \return   0 falls die Sequentznummer gültig ist. Ansonsten -1
  */
int checkReadNum(uip_ipaddr_t *addr, uint8_t seq_num[6]);

/**
  * \brief    Löscht eine Session
  *
  *           Löscht die Session, die für die IP-Adresse addr hinterlegt ist.
  *
  * \param    addr  IP-Adresse für die die Session gelöscht werden soll
  *
  * \return   0 bei Erfolg. -1 falls keine Session zur IP gefunden wurde
  */
int deleteSession(uip_ipaddr_t *addr);

// ----------------------------------------------------------------------------

/**
  * \brief    Einfügen eines Schlüsselblocks
  *
  *           Fügt einen Schlüsselblock in die, zur IP-Adresse passende,
  *           Session ein. Dabei wird dieser nur zusätzlich, zum derzeit
  *           gültigen, abgelegt und nicht aktiviert.
  *
  * \param    addr      IP-Adresse für die der Schlüsselblock gespeichert werden soll
  * \param    key_block Zeiger auf die Position mit dem Schlüsselblock
  *
  * \return   0 bei Erfolg. -1 falls keine Session zur IP gefunden wurde
  */
int insertKeyBlock(uip_ipaddr_t *addr, KeyBlock_t *key_block);

/**
  * \brief    Abruf eines Schlüsselblocks
  *
  *           Ruft den für die IP-Adresse gültigen Schlüsselblock zur übergebenen
  *           Epoche ab, falls die Epoche mit der hinterlegten übereinstimmt.
  *           Ist die übergebene Epoche um eins größer, wird der zusätzlich hinterlegte
  *           Schlüsselblock abgerufen. Ist dabei update auf 1, wird die Epoche der
  *           Session um 1 erhöht, der alte Schlüsselblock vernichtet, und die
  *           Sequenznummern zurückgesetzt.
  *
  * \param    addr      IP-Adresse für die der Schlüsselblock abgerufen werden soll
  * \param    epoch     Epoche für die der Schlüsselblock abgerufen werden soll
  * \param    update    Falls 1, wird die Epoche bei einer Anfrage aktualisiert
  *
  * \return   0 falls keine Session zur IP gefunden wurde. Ansonsten Zeiger
  *           auf die Position im Flash-Speicher, an der der Schlüsselblock liegt.
  */
fpoint_t getKeyBlock(uip_ipaddr_t *addr, uint16_t epoch, int update);

#endif /* __ER_DTLS_13_DATA_H__ */
