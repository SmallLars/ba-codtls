/* __CCM_H__ */
#ifndef __CCM_H__
#define __CCM_H__

#include <stdlib.h>
#include <stdint.h>

#include "coap_dtls.h"

void encrypt(CCMData_t *c, uint8_t *key, uint8_t *buf, size_t len);

#endif /* __CCM__ */
