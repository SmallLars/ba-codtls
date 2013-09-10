/* __IP_LISTE_H__ */
#ifndef __IP_LISTE_H__
#define __IP_LISTE_H__

struct ip_list {
    unsigned char ip[16];
    unsigned char *via;
    struct ip_list *next;
};

/**
  * \brief    Listenlänge
  *
  *           Gibt die Länge der übergebenen Liste zurück.
  *
  * \param    list   Zeiger auf die Liste, für die die Länge ermittelt werden soll
  * \return   Die Länge der übergebenen Liste
  */
int size_ip(struct ip_list *list);

/**
  * \brief    Element einfügen
  *
  *           Hängt ein neues Element mit der geparsten IP an das Ende der Liste.
  *           Sollte die IP schon vorhanden sein, wird kein neues Element angehängt.
  *
  * \param    list   Zeiger auf die Liste, die um ein Element verlängert werden soll
  * \param    ip     Gültige IPv6-Adresse in menschenlesbarer Form (bspw. aaaa::60B1:60B1:60B1:0001)
  * \param    via    Gültige IPv6-Adresse in menschenlesbarer Form (bspw. aaaa::60B1:60B1:60B1:0001)
  */
void add_ip(struct ip_list **list, char *ip, char *via);

/**
  * \brief    Listenelement auslesen
  *
  *           Gibt die IP zurück, die an der gewünschten Stelle in der Liste hinterlegt ist.
  *
  * \param    list   Zeiger auf die Liste, aus der ein Element gelesen werden soll
  * \param    i      Index des gewünschten Elements in der Liste
  * \return   Zeiger auf die IP am gewünschten Index
  */
unsigned char *get_ip(struct ip_list *list, int i);

/**
  * \brief    Listenelement auslesen
  *
  *           Gibt die IP zurück, die an der gewünschten Stelle in der Liste hinterlegt ist.
  *
  * \param    list   Zeiger auf die Liste, aus der ein Element gelesen werden soll
  * \param    i      Index des gewünschten Elements in der Liste
  * \return   Zeiger auf die IP am gewünschten Index
  */
unsigned char *get_via(struct ip_list *list, int i);

/**
  * \brief    Liste leeren
  *
  *           Löscht alle Elemente aus der Liste und gibt den Speicher weider frei.
  *
  * \param    list   Zeiger auf die Liste, die geleert werden soll
  */
void clear_ip(struct ip_list **list);

#endif /* __IP_LISTE_H__ */
