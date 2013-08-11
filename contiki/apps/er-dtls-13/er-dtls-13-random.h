/* __ER_DTLS_13_RANDOM_H__ */
#ifndef __ER_DTLS_13_RANDOM_H__
#define __ER_DTLS_13_RANDOM_H__

#include <stddef.h>
#include <stdint.h>

/**
  * \brief    Erzeugung von Zufallswerten
  *
  *           Erzeugt len Zufallsbyte an der Stelle des übergebenen Zeigers.
  *
  * \param    c   Zeiger auf die mit Zufallszahlen zu füllenden Bytes
  * \param    len Anzahl der Bytes die mit Zufallszahlen gefüllt werden sollen
  */
void random_x(uint8_t *c, size_t len);

/**
  * \brief    Erzeugung einer 32 Bit Zufallszahl
  *
  *           Erzeugt eine 32 Bit Zufallszahl und gibt diese zurück.
  *
  * \return   Die zufällig erzeugte Zahl.
  */
uint32_t random_32(void);

/**
  * \brief    Erzeugung einer 16 Bit Zufallszahl
  *
  *           Erzeugt eine 16 Bit Zufallszahl und gibt diese zurück.
  *
  * \return   Die zufällig erzeugte Zahl.
  */
uint16_t random_16(void);

/**
  * \brief    Erzeugung einer 8 Bit Zufallszahl
  *
  *           Erzeugt eine 8 Bit Zufallszahl und gibt diese zurück.
  *
  * \return   Die zufällig erzeugte Zahl.
  */
uint8_t random_8(void);

#endif /* __ER_DTLS_13_RANDOM_H__ */
