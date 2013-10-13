/* __DTLS_DATA_H__ */
#ifndef __DTLS_DATA_H__
#define __DTLS_DATA_H__

#include <stdint.h>

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
} __attribute__ ((packed)) KeyBlock_t;

#define KEY_BLOCK_CLIENT_KEY  0
#define KEY_BLOCK_SERVER_KEY 16
#define KEY_BLOCK_CLIENT_IV  32
#define KEY_BLOCK_SERVER_IV  36

typedef struct { // 16 + 8 + 2 + 32 = 58
    uint8_t ip[16];
    uint8_t id[8];
    uint16_t epoch;
    uint16_t valid;
    uint32_t seq_num_w;
    KeyBlock_t key_block;
    KeyBlock_t key_block_new;
} __attribute__ ((packed)) Session_t;

/*---------------------------------------------------------------------------*/

/**
  * \brief    Abruf eines PSK
  *
  *           Sucht nach dem PSK des Gerät mit dem übergebenen UUID.
  *           Bisher gibt diese Funktion immer einen Standard-PSK zurück.
  *           Eine Datenbank, in der PSKs abgelegt werden können soll
  *           später zur Suche herangezogen werden.
  *
  * \param    dst      Position an der der PSK geschrieben werden soll
  * \param    uuid     UUID des Endgeräts, fürs das der PSK gesucht wird
  *
  * \return   0 falls ein PSK gefunden wurde. Sonst -1
  */
int getPSK(uint8_t dst[16], uint8_t uuid[16]);

/*---------------------------------------------------------------------------*/

/**
  * \brief    Erstellung einer Session
  *
  *           Erstellt eine Session für die spezifizierte IP mit der
  *           übergebenen Session-ID.
  *
  * \param    ip    Zeiger auf die IP-Adresse des Servers
  * \param    id    Zeiger auf die vom Server erhaltene Session-ID
  */
void createSession(uint8_t ip[16], uint8_t id[8]);

/**
  * \brief    Abruf der Epoche
  *
  *           Ruft die Epoche zur übergebenen IP-Adresse ab.
  *
  * \param    ip    Zeiger auf die IP-Adresse des Servers, für den die Epoche abgefragt wird
  *
  * \return   Die Epoche zur übergebenen IP-Adresse. Ist keine Session
  *           zur IP-Adresse hinterlegt, ist der Rückgabewert 0
  */
uint16_t getEpoch(uint8_t ip[16]);

/**
  * \brief    Abruf der Sequenznummer
  *
  *           Ruft die Sequenznummer zur übergebenen IP-Adresse ab.
  *
  * \param    ip    Zeiger auf die IP-Adresse des Servers, für den die Sequenznummer abgefragt wird
  *
  * \return   Die Sequenznummer zur übergebenen IP-Adresse. Ist keine Session
  *           zur IP-Adresse hinterlegt, ist der Rückgabewert 0
  */
uint32_t getSeqNum(uint8_t ip[16]);

/*---------------------------------------------------------------------------*/

/**
  * \brief    Einfügen eines Keyblocks
  *
  *           Fügt der zur übergebenen IP-Adresse passenden Session einen Keyblock hinzu.
  *
  * \param    ip        Zeiger auf die IP-Adresse des Servers, zu dem der Keyblock gehört
  * \param    key_block Zeiger auf den Keyblock, der eingefügt werden soll
  *
  * \return   0 falls erfolgreich. -1 falls keine Session zur übergebenen IP-Adresse gefunden wurde
  */
int insertKeyBlock(uint8_t ip[16], KeyBlock_t *key_block);

/**
  * \brief    Abrufen eines Keyblocks
  *
  *           Ruft den Keyblock zur übergebenen IP-Adresse passenden Session ab,
  *           falls für die übergebene Epoche ein Keyblock hinterlegt ist.
  *
  * \param    ip    Zeiger auf die IP-Adresse des Servers, zu dem der Keyblock abgerufen werden soll
  * \param    epoch Epoche für die der Keyblock abgerufen werden soll
  *
  * \return   Falls erfolgreich Zeiger auf den Keyblock. Sonst NULL
  */
uint8_t *getKeyBlock(uint8_t ip[16], uint16_t epoch);

/**
  * \brief    Erhöhung der Epoche
  *
  *           Erhöht die Epoche der zur übergebenen IP-Adresse passenden
  *           Session um 1. Dabei wird der ale Keyblock vernichtet.
  *
  * \param    ip    Zeiger auf die IP-Adresse des betroffenen Servers
  */
void increaseEpoch(uint8_t ip[16]);

#endif /* __DTLS_DATA_H__ */


