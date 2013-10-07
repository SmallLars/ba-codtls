#ifndef TIME_H_
#define TIME_H_

#include <stdint.h>

/**
  * \brief    Liefert die aktuelle Systemzeit
  *
  *           Gibt die aktuelle Systemzeit zurück, die anhand eines
  *           im Flash-Speicher hinterlegten Basiswertes berechnet wird.
  *           Der Basiswert enthält den Herstellungszeitpunkt.
  *
  * \return   Die aktuelle Systemzeit
  */
uint32_t getTime();

/**
  * \brief    Einstellen der Systemzeit
  *
  *           Setzt die Systemzeit auf die neue Zeit. Dafür wird
  *           ein Korrekturwert ermittelt, der zukünftig auf den
  *           Herstellungszeitpunkt addiert wird.
  *
  * \param    time  Die neue Systemzeit
  */
void setTime(uint32_t time);

#endif /* TIME_H_ */
