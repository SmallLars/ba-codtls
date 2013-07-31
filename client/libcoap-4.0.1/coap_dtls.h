/* __COAP_DTLS_H__ */
#ifndef __COAP_DTLS_H__
#define __COAP_DTLS_H__

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
//#include <netinet/in.h>

/* Record Layer Datenstrukturen -------------------------------------------- */

typedef enum {
  type_8_bit = 0,
  alert = 1,
  dtls_data = 2,
  application_data = 3
} RecordType;

typedef enum {
  dtls_1_0 = 0,
  version_16_bit = 1,
  dtls_1_2 = 2,
  version_future_use = 3
} Version;

typedef enum {
  epoch_0 = 0,
  epoch_1 = 1,
  epoch_2 = 2,
  epoch_3 = 3,
  epoch_4 = 4,
  epoch_8_bit = 5,
  epoch_16_bit = 6,
  epoch_implicit = 7 // same as previous record in the datagram
} Epoch;

typedef enum {
  snr_0 = 0,
  snr_8_bit = 1,
  snr_16_bit = 2,
  snr_24_bit = 3,
  snr_32_bit = 4,
  snr_40_bit = 5,
  snr_48_bit = 6,
  snr_implicit = 7 // number of previous record in the datagram + 1
} SequenceNumber;

typedef enum {
  rec_length_0 = 0,
  rec_length_8_bit = 1,
  rec_length_16_bit = 2,
  rec_length_implicit = 3 // datagram size - sizeof(DTLSRecord_t)
} RecordLength;

typedef struct {
  uint8_t :1;
  RecordType type:2;
  Version version:2;
  Epoch epoch:3;
  uint8_t :3;
  SequenceNumber snr:3;
  RecordLength length:2;
  uint8_t payload[0];
} __attribute__ ((packed)) DTLSRecord_t;

/* ------------------------------------------------------------------------- */

ssize_t dtls_sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen);

ssize_t dtls_recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen);

#endif /* __COAP_DTLS_H__ */
