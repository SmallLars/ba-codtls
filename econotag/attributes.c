#include "tools.h"
#include "persist.h"

#include <erbium.h>
#include <er-coap-13.h>
#include <er-coap-13-separate.h>
#include <er-coap-13-transactions.h>
#include <string.h>

#include "mc1322x.h"

/*************************************************************************/
/*  DEVICE NAME                                                          */
/*************************************************************************/
static uint8_t separate_active = 0;

void ecc_wait_14() {
  uint32_t result_x[8];
  uint32_t result_y[8];
  uint32_t base_x[8];
  uint32_t base_y[8];
  nvm_getVar((void *) base_x, RES_ECC_BASE_X, LEN_ECC_BASE_X);
  nvm_getVar((void *) base_y, RES_ECC_BASE_Y, LEN_ECC_BASE_Y);

  uint32_t private_key[8];
  do {
    random_x((uint8_t *) private_key, 32);
  } while (!ecc_is_valid_key(private_key));

  uint32_t time = *MACA_CLK;
  printf("ECC - START\n");
  ecc_ec_mult(base_x, base_y, private_key, result_x, result_y);
  printf("ECC - ENDE - %u\n", (*MACA_CLK - time) / 25000);
}

void device_name_handler(void* request, void* response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset) {
/*
  nvm_getVar(buffer, RES_NAME, LEN_NAME);
  buffer[REST_MAX_CHUNK_SIZE - 1] = 0;
  set_response(response, CONTENT_2_05, TEXT_PLAIN, buffer, min(LEN_NAME, REST_MAX_CHUNK_SIZE - 1));
*/
/*
  int i;
  for (i = 0; i < preferred_size; i+=2) sprintf(buffer + i, "%02X", *offset);
  REST.set_response_payload(response, buffer, preferred_size);
  *offset += preferred_size;
  if (*offset > 250) *offset = -1;
*/
  if (separate_active) {
      coap_separate_reject();
  } else {
    if (*offset == 0) {
      coap_separate_t request_metadata[1];

      separate_active = 1;
      coap_separate_accept(request, request_metadata); // ACK + Anfrageinformationen zwischenspeichern

      ecc_wait_14(); // Testzeug das dauert

      // Erstes Paket senden - START
      coap_transaction_t *transaction = NULL;
      if ( (transaction = coap_new_transaction(request_metadata->mid, &request_metadata->addr, request_metadata->port)) ) {
        coap_packet_t response[1];

        // Anfrageinformationen wiederherstellen
        coap_separate_resume(response, request_metadata, REST.status.OK);

        // Payload generieren
        memset(buffer, 0x30, preferred_size);
        coap_set_payload(response, buffer, preferred_size);

        // Das es sich hier um den ersten von mehreren Blöcken handelt wird die Blockoption gesetzt.
        coap_set_header_block2(response, 0, 1, preferred_size); // Block 0, Es folgen weitere, Blockgröße 64 = preferred_size

        // TODO Warning: No check for serialization error.
        transaction->packet_len = coap_serialize_message(response, transaction->packet);
        coap_send_transaction(transaction);
      }
      // Erstes Paket senden - ENDE

      separate_active = 0;
    } else {
      int i;
      for (i = 0; i < preferred_size; i+=2) sprintf(buffer + i, "%02X", *offset);
      REST.set_response_payload(response, buffer, preferred_size);
      *offset += preferred_size;
      if (*offset > 250) *offset = -1;
    }
  }
}

/*************************************************************************/
/*  DEVICE MODEL                                                         */
/*************************************************************************/
void device_model_handler(void* request, void* response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset) {
  nvm_getVar(buffer, RES_MODEL, LEN_MODEL);
  buffer[REST_MAX_CHUNK_SIZE - 1] = 0;
  set_response(response, CONTENT_2_05, TEXT_PLAIN, buffer, min(LEN_MODEL, REST_MAX_CHUNK_SIZE - 1));
}

/*************************************************************************/
/*  DEVICE IDENTIFIER                                                    */
/*************************************************************************/
void device_uuid_handler(void* request, void* response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset) {
  nvm_getVar(buffer, RES_UUID, LEN_UUID);
  buffer[REST_MAX_CHUNK_SIZE - 1] = 0;
  set_response(response, CONTENT_2_05, APPLICATION_OCTET_STREAM, buffer, min(LEN_UUID, REST_MAX_CHUNK_SIZE - 1));
}

/*************************************************************************/
/*  DEVICE TIME                                                          */
/*************************************************************************/
void device_time_handler(void* request, void* response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset) {
  uint32_t time = uip_htonl(getTime());
  memcpy(buffer, &time, 4);
  set_response(response, CONTENT_2_05, APPLICATION_OCTET_STREAM, buffer, 4);
}
