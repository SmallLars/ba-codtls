/* __ER_DTLS_13_ALERT_H__ */
#ifndef __ER_DTLS_13_ALERT_H__
#define __ER_DTLS_13_ALERT_H__

#include <stdint.h>

#include "contiki-net.h"

/* Alert Layer Datenstrukturen -------------------------------------------- */

typedef enum {
    warning = 1,
    fatal =   2
} AlertLevel;

typedef enum {
    close_notify                  =   0,
    unexpected_message            =  10,
    bad_record_mac                =  20,
    decryption_failed_RESERVED    =  21,
    record_overflow               =  22,
    decompression_failure         =  30,
    handshake_failure             =  40,
    no_certificate_RESERVED       =  41,
    bad_certificate               =  42,
    unsupported_certificate       =  43,
    certificate_revoked           =  44,
    certificate_expired           =  45,
    certificate_unknown           =  46,
    illegal_parameter             =  47,
    unknown_ca                    =  48,
    access_denied                 =  49,
    decode_error                  =  50,
    decrypt_error                 =  51,
    export_restriction_RESERVED   =  60,
    protocol_version              =  70,
    insufficient_security         =  71,
    internal_error                =  80,
    user_canceled                 =  90,
    no_renegotiation              = 100,
    unsupported_extension         = 110
} AlertDescription;

/* ------------------------------------------------------------------------- */

/**
  * \brief  Titel
  *
  *         Beschreibung
  *
  * \param  addr        1
  * \param  port        2
  * \param  level       3
  * \param  description 4
  */
void sendAlert(uip_ipaddr_t *addr, uint16_t port, AlertLevel level, AlertDescription description);

/**
  * \brief  Titel
  *
  *         Beschreibung
  *
  * \param  addr        1
  * \param  port        2
  * \param  level       3
  * \param  description 4
  */
void generateAlert(void* response, uint8_t *buffer, AlertDescription description);

#endif /* __ER_DTLS_13_ALERT_H__ */


