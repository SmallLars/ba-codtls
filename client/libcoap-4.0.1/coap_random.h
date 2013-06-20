/* __AES_RANDOM_H__ */
#ifndef __AES_RANDOM_H__
#define __AES_RANDOM_H__

#include <stddef.h>
#include <stdint.h>

/**
  * \brief    Zufallsfunktion
  *
  *           Füllt die angegebene Stelle im Speicher mit Zufallszahlen.
  *           Diese werden so weit möglich aus /dev/random entnommen.
  *           Sind dort keine Zahlen hinterlegt wird Byteweise auf
  *           /dev/urandom ausgewichen.
  *
  * \param    c   Zeiger auf den Speicherbereich der gefüllt werden soll
  * \param    len Anzahl der Bytes die in den Speicher geschrieben werden sollen
  */
void random_x(uint8_t *c, size_t len);

#endif /* __AES_RANDOM_H__ */
