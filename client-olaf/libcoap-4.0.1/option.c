/*
 * option.c -- helpers for handling options in CoAP PDUs
 *
 * Copyright (C) 2010-2013 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use. 
 */


#include "config.h"

#if defined(HAVE_ASSERT_H) && !defined(assert)
# include <assert.h>
#endif

#include <stdio.h>
#include <string.h>

#include "option.h"
#include "debug.h"

coap_opt_t *
options_start(coap_pdu_t *pdu) {

  if (pdu && pdu->hdr && 
      (pdu->hdr->token + pdu->hdr->token_length 
       < (unsigned char *)pdu->hdr + pdu->length)) {

    coap_opt_t *opt = pdu->hdr->token + pdu->hdr->token_length;
    return (*opt == COAP_PAYLOAD_START) ? NULL : opt;
  
  } else 
    return NULL;
}

size_t
coap_opt_parse(const coap_opt_t *opt, size_t length, coap_option_t *result) {

  const coap_opt_t *opt_start = opt; /* store where parsing starts  */

  assert(opt); assert(result);

#define ADVANCE_OPT(o,e,step) if ((e) < step) {			\
    debug("cannot advance opt past end\n");			\
    return 0;							\
  } else {							\
    (e) -= step;						\
    (o) = ((unsigned char *)(o)) + step;			\
  }

  if (length < 1)
    return 0;

  result->delta = (*opt & 0xf0) >> 4;
  result->length = *opt & 0x0f;

  switch(result->delta) {
  case 15:
    if (*opt != COAP_PAYLOAD_START)
      debug("ignored reserved option delta 15\n");
    return 0;
  case 14:
    /* Handle two-byte value: First, the MSB + 269 is stored as delta value.
     * After that, the option pointer is advanced to the LSB which is handled
     * just like case delta == 13. */
    ADVANCE_OPT(opt,length,1);
    result->delta = ((*opt & 0xff) << 8) + 269;
    if (result->delta < 269) {
      debug("delta too large\n");
      return 0;
    }
    /* fall through */
  case 13:
    ADVANCE_OPT(opt,length,1);
    result->delta += *opt & 0xff;
    break;
    
  default:
    ;
  }

  switch(result->length) {
  case 15:
    debug("found reserved option length 15\n");
    return 0;
  case 14:
    /* Handle two-byte value: First, the MSB + 269 is stored as delta value.
     * After that, the option pointer is advanced to the LSB which is handled
     * just like case delta == 13. */
    ADVANCE_OPT(opt,length,1);
    result->length = ((*opt & 0xff) << 8) + 269;
    /* fall through */
  case 13:
    ADVANCE_OPT(opt,length,1);
    result->length += *opt & 0xff;
    break;
    
  default:
    ;
  }

  ADVANCE_OPT(opt,length,1);
  /* opt now points to value, if present */

  result->value = (unsigned char *)opt;
  if (length < result->length) {
    debug("invalid option length\n");
    return 0;
  }

#undef ADVANCE_OPT

  return (opt + result->length) - opt_start;
}

coap_opt_iterator_t *
coap_option_iterator_init(coap_pdu_t *pdu, coap_opt_iterator_t *oi,
			  const coap_opt_filter_t filter) {
  assert(pdu); 
  assert(pdu->hdr);
  assert(oi);
  
  memset(oi, 0, sizeof(coap_opt_iterator_t));

  oi->next_option = (unsigned char *)pdu->hdr + sizeof(coap_hdr_t)
    + pdu->hdr->token_length;
  if ((unsigned char *)pdu->hdr + pdu->length <= oi->next_option) {
    oi->bad = 1;
    return NULL;
  }

  assert((sizeof(coap_hdr_t) + pdu->hdr->token_length) <= pdu->length);

  oi->length = pdu->length - (sizeof(coap_hdr_t) + pdu->hdr->token_length);

  if (filter) {
    memcpy(oi->filter, filter, sizeof(coap_opt_filter_t));
    oi->filtered = 1;
  }
  return oi;
}

inline int
opt_finished(coap_opt_iterator_t *oi) {
  assert(oi);

  if (oi->bad || oi->length == 0 || 
      !oi->next_option || *oi->next_option == COAP_PAYLOAD_START) {
    oi->bad = 1;
  }

  return oi->bad;
}

coap_opt_t *
coap_option_next(coap_opt_iterator_t *oi) {
  coap_option_t option;
  coap_opt_t *current_opt = NULL;
  size_t optsize;
  int b;		   /* to store result of coap_option_getb() */

  assert(oi);

  if (opt_finished(oi))
    return NULL;

  while (1) {
    /* oi->option always points to the next option to deliver; as
     * opt_finished() filters out any bad conditions, we can assume that
     * oi->option is valid. */
    current_opt = oi->next_option;
    
    /* Advance internal pointer to next option, skipping any option that
     * is not included in oi->filter. */
    optsize = coap_opt_parse(oi->next_option, oi->length, &option);
    if (optsize) {
      assert(optsize <= oi->length);
      
      oi->next_option += optsize;
      oi->length -= optsize;
      
      oi->type += option.delta;
    } else {			/* current option is malformed */
      oi->bad = 1;
      return NULL;
    }

    /* Exit the while loop when:
     *   - no filtering is done at all
     *   - the filter matches for the current option
     *   - the filter is too small for the current option number 
     */
    if (!oi->filtered ||
	(b = coap_option_getb(oi->filter, oi->type)) > 0)
      break;
    else if (b < 0) {		/* filter too small, cannot proceed */
      oi->bad = 1;
      return NULL;
    }
  }

  return current_opt;
}

coap_opt_t *
coap_check_option(coap_pdu_t *pdu, unsigned char type, 
		  coap_opt_iterator_t *oi) {
  coap_opt_filter_t f;
  
  coap_option_filter_clear(f);
  coap_option_setb(f, type);

  coap_option_iterator_init(pdu, oi, f);

  return coap_option_next(oi);
}

unsigned short
coap_opt_delta(const coap_opt_t *opt) {
  unsigned short n;

  n = (*opt++ & 0xf0) >> 4;

  switch (n) {
  case 15: /* error */
    warn("coap_opt_delta: illegal option delta\n");

    /* This case usually should not happen, hence we do not have a
     * proper way to indicate an error. */
    return 0;
  case 14: 
    /* Handle two-byte value: First, the MSB + 269 is stored as delta value.
     * After that, the option pointer is advanced to the LSB which is handled
     * just like case delta == 13. */
    n = ((*opt++ & 0xff) << 8) + 269;
    /* fall through */
  case 13:
    n += *opt & 0xff;
    break;
  default: /* n already contains the actual delta value */
    ;
  }

  return n;
}

unsigned short
coap_opt_length(const coap_opt_t *opt) {
  unsigned short length;

  length = *opt & 0x0f;
  switch (*opt & 0xf0) {
  case 0xf0:
    debug("illegal option delta\n");
    return 0;
  case 0xe0:
    ++opt;
    /* fall through to skip another byte */
  case 0xd0:
    ++opt;
    /* fall through to skip another byte */
  default:
    ++opt;
  }

  switch (length) {
  case 0x0f:
    debug("illegal option length\n");
    return 0;
  case 0x0e:
    length = (*opt++ << 8) + 269;
    /* fall through */
  case 0x0d:
    length += *opt++;
    break;
  default:
    ;
  }
  return length;
}

unsigned char *
coap_opt_value(coap_opt_t *opt) {
  size_t ofs = 1;

  switch (*opt & 0xf0) {
  case 0xf0:
    debug("illegal option delta\n");
    return 0;
  case 0xe0:
    ++ofs;
    /* fall through */
  case 0xd0:
    ++ofs;
    break;
  default:
    ;
  }

  switch (*opt & 0x0f) {
  case 0x0f:
    debug("illegal option length\n");
    return 0;
  case 0x0e:
    ++ofs;
    /* fall through */
  case 0x0d:
    ++ofs;
    break;
  default:
    ;
  }

  return (unsigned char *)opt + ofs;
}

size_t
coap_opt_size(const coap_opt_t *opt) {
  coap_option_t option;

  /* we must assume that opt is encoded correctly */
  return coap_opt_parse(opt, (size_t)-1, &option);
}

size_t
coap_opt_setheader(coap_opt_t *opt, size_t maxlen, 
		   unsigned short delta, size_t length) {
  size_t skip = 0;

  assert(opt);

  if (maxlen == 0)		/* need at least one byte */
    return 0;

  if (delta < 13) {
    opt[0] = delta << 4;
  } else if (delta < 270) {
    if (maxlen < 2) {
      debug("insufficient space to encode option delta %d", delta);
      return 0;
    }

    opt[0] = 0xd0;
    opt[++skip] = delta - 13;
  } else {
    if (maxlen < 3) {
      debug("insufficient space to encode option delta %d", delta);
      return 0;
    }

    opt[0] = 0xe0;
    opt[++skip] = ((delta - 269) >> 8) & 0xff;
    opt[++skip] = (delta - 269) & 0xff;    
  }
    
  if (length < 13) {
    opt[0] |= length & 0x0f;
  } else if (length < 270) {
    if (maxlen < skip + 1) {
      debug("insufficient space to encode option length %d", length);
      return 0;
    }
    
    opt[0] |= 0x0d;
    opt[++skip] = length - 13;
  } else {
    if (maxlen < skip + 2) {
      debug("insufficient space to encode option delta %d", delta);
      return 0;
    }

    opt[0] |= 0x0e;
    opt[++skip] = ((length - 269) >> 8) & 0xff;
    opt[++skip] = (length - 269) & 0xff;    
  }

  return skip + 1;
}

size_t
coap_opt_encode(coap_opt_t *opt, size_t maxlen, unsigned short delta,
		const unsigned char *val, size_t length) {
  size_t l = 1;

  l = coap_opt_setheader(opt, maxlen, delta, length);
  assert(l <= maxlen);
  
  if (!l) {
    debug("coap_opt_encode: cannot set option header\n");
    return 0;
  }
  
  maxlen -= l;
  opt += l;

  if (maxlen < length) {
    debug("coap_opt_encode: option too large for buffer\n");
    return 0;
  }

  if (val)			/* better be safe here */
    memcpy(opt, val, length);

  return l + length;
}

