#ifndef FLASH_STORE_H_
#define FLASH_STORE_H_

#include <nvm.h>

// Blöcke
// 0x18000 - 0x18FFF Random Zugriff Block 1.1
// 0x19000 - 0x19FFF Random Zugriff Block 1.2
// 0x1A000 - 0x1AFFF Random Zugriff Block 2.1
// 0x1B000 - 0x1BFFF Random Zugriff Block 2.2
// 0x1C000 - 0x1CFFF Stack ohne Pop-Funktion
// 0x1D000 - 0x1DFFF Fehlermeldungen
// 0x1E000 - 0x1EFFF MAC, UUID, PSK, ECC-Base-Point, Name, Model, Flashzeitpunkt
// 0x1F000 - 0x1FFFF Systemreserviert

#define RES_STACK        0x1C000
#define LEN_STACK        0x1000

//Read Only Fehlermeldungen
#define RES_B_ERR_05     0x1D000
#define LEN_B_ERR_05     73
#define RES_B_ERR_04     0x1D080
#define LEN_B_ERR_04     51
#define RES_B_ERR_03     0x1D100
#define LEN_B_ERR_03     52
#define RES_B_ERR_02     0x1D180
#define LEN_B_ERR_02     31
#define RES_B_ERR_01     0x1D200
#define LEN_B_ERR_01     61

//Read Only Vars
#define RES_MAC          0x1E000
#define LEN_MAC          0x08
#define RES_UUID         0x1E008
#define LEN_UUID         0x10
#define RES_PSK          0x1E018
#define LEN_PSK          0x10
#define RES_ANSCHARS     0x1E028
#define LEN_ANSCHARS     0x40
#define RES_ECC_BASE_X   0x1E068
#define LEN_ECC_BASE_X   0x20
#define RES_ECC_BASE_Y   0x1E088
#define LEN_ECC_BASE_Y   0x20
#define RES_ECC_ORDER    0x1E0A8
#define LEN_ECC_ORDER    0x20
#define RES_NAME         0x1E0C8
#define LEN_NAME         0x0F
#define RES_MODEL        0x1E0E8
#define LEN_MODEL        0x0E
#define RES_FLASHTIME    0x1E108
#define LEN_FLASHTIME    0x04

//Random Access Vars - Byte 0 bis 8192
#define RES_BLK_1_ACTIVE       0
#define RES_BLK_2_ACTIVE    4096
#define LEN_BLK_X_ACTIVE       1

//------------------------------------

#define RES_PSK_ISNEW          1
#define LEN_PSK_ISNEW          1

#define RES_NEWPSK             2
#define LEN_NEWPSK            16

#define SESSION_LIST_LEN      10
#define RES_SESSION_LIST      18
#define LEN_SESSION_LIST     600

#define LEN_BLOCK_1          618

//------------------------------------

#define RES_KEY_BLOCK_LIST  (4096 + 1)
#define LEN_KEY_BLOCK_LIST   800

#define LEN_BLOCK_2          801

typedef uint32_t fpoint_t;   // Adresse im Flash-Speicher

/**
  * \brief    Zurücksetzen der Blöcke für den Random-Zugriff
  *
  *           Löscht die 4 Blöck für den Random-Zugriff im Flashspeicher
  *           und setzt die für das System notwendigen Bytes erneut.
  */
void nvm_init();

/**
  * \brief    Lesen von Daten aus dem Flashspeicher
  *
  *           Liest numBytes aus dem Flashspeicher und hinterlegt diese in dest.
  *           Nur gültig für die Adressbereiche 0x0 - 0x1FFF und 0x18000 - 0x1FFFF.
  *           0x0 - 0x1FFF wird dabei entsprechend auf eine Position im anderen
  *           Adressbereich umgerechnet.
  *
  * \param    dest       Zeiger auf die Position an der die Daten hinterlegt werden sollen
  * \param    address    Zeiger auf die zu lesenden Daten
  * \param    numBytes   Anzahl der Bytes die gelesen werden sollen
  *
  * \return   0 bei erfolgreichem Lesevorgang. Ansonsten größer 0
  */
nvmErr_t nvm_getVar(void *dest, fpoint_t address, uint16_t numBytes);

/**
  * \brief    Schreiben von Daten in den Flashspeicher
  *
  *           Schreibt numBytes aus src in den Flashspeicher.
  *           Nur gültig für die Adressbereiche 0x0 - 0x1FFF.
  *
  * \param    src        Zeiger auf die Position der zu schreibenden Daten
  * \param    address    Zeiger auf die Position an die geschrieben werden soll
  * \param    numBytes   Anzahl der Bytes die geschrieben werden sollen
  *
  * \return   0 bei erfolgreichem Schreibvorgang. Ansonsten größer 0
  */
nvmErr_t nvm_setVar(void *src, fpoint_t address, uint16_t numBytes);

/**
  * \brief    Vergleich von Daten mit Daten aus dem Flashspeicher
  *
  *           Vergleicht numBytes aus src mit Daten aus dem Flashspeicher.
  *           Nur gültig für die Adressbereiche 0x0 - 0x1FFF und 0x18000 - 0x1FFFF.
  *           0x0 - 0x1FFF wird dabei entsprechend auf eine Position im anderen
  *           Adressbereich umgerechnet.
  *
  * \param    src        Zeiger auf die Daten, die mit den im Flash hinterlegten Daten verglichen werden sollen
  * \param    address    Zeiger auf die zu vergleichenden Daten
  * \param    numBytes   Anzahl der Bytes die verglichen werden sollen
  *
  * \return   0 bei Gleichheit der Daten. Ansonsten größer 0
  */
nvmErr_t nvm_cmp(void *src, fpoint_t address, uint16_t numBytes);

/*
typedef enum {
   gNvmErrNoError_c = 0,
   gNvmErrInvalidInterface_c,
   gNvmErrInvalidNvmType_c,
   gNvmErrInvalidPointer_c,
   gNvmErrWriteProtect_c,
   gNvmErrVerifyError_c,
   gNvmErrAddressSpaceOverflow_c,
   gNvmErrBlankCheckError_c,
   gNvmErrRestrictedArea_c,
   gNvmErrMaxError_c
} nvmErr_t;
*/

/**
  * \brief    Stack initialisieren
  *
  *           Löscht den Block im Flashspeicher und setzt den Stackpointer zurück.
  *           Ist vor einer Nutzung erforderlich.
  */
void stack_init();

/**
  * \brief    Einfügen von Daten auf den Stack
  *
  *           Packt numBytes aus src auf den Stack.
  *
  * \param    src        Zeiger auf die Daten, die auf den Stack gepackt werden sollen
  * \param    numBytes   Anzahl der Bytes die auf den Stack gepackt werden sollen
  */
void stack_push(uint8_t *src, uint16_t numBytes);

/**
  * \brief    Stackgröße
  *
  *           Gibt die Menge der im Stack hinterlegten Daten zurück.
  *
  * \return   Die Menge der im Stack hinterlegten Daten
  */
uint16_t stack_size();

/**
  * \brief    Lesen von Daten aus dem Stack
  *
  *           Liest numBytes aus dem Stack an Position offset und hinterlegt diese in dest.
  *
  * \param    dest       Zeiger auf die Position an der die Daten hinterlegt werden sollen
  * \param    offset     Position im Stack, von der die Daten gelesen werden sollen
  * \param    numBytes   Anzahl der Bytes die gelesen werden sollen
  *
  * \return   0 bei erfolgreichem Lesevorgang. Ansonsten größer 0
  */
#define stack_read(dest, offset, numBytes) nvm_getVar(dest, RES_STACK + (offset), numBytes)

#endif /* FLASH_STORE_H_ */
