/* __ER_COAP_13_DTLS_RANDOM_H__ */
#ifndef __ER_COAP_13_DTLS_RANDOM_H__
#define __ER_COAP_13_DTLS_RANDOM_H__

#include <stddef.h>
#include <stdint.h>

uint32_t random_32( void );

uint16_t random_16( void );

uint8_t random_8( void );

void doRand( uint8_t *c, size_t len );

#endif /* __ER_COAP_13_DTLS_RANDOM_H__ */
