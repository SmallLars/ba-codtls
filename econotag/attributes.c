#include "tools.h"
#include "persist.h"

#include <erbium.h>
#include <er-coap-13.h>
#include <er-coap-13-separate.h>
#include <er-coap-13-transactions.h>
#include <string.h>

#include "mc1322x.h"

void device_name_finalize_handler();

/*************************************************************************/
/*  DEVICE NAME                                                          */
/*************************************************************************/

/* A structure to store the required information */
typedef struct application_separate_store {
  coap_separate_t request_metadata;  // Provided by Erbium to store generic request information such as remote address and token
  char buffer[16];                   // Add fields for addition information to be stored for finalizing
} application_separate_store_t;

static uint8_t separate_active = 0;
static application_separate_store_t separate_store[1];

void device_name_handler(void* request, void* response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset) {
  if (separate_active) {
    coap_separate_reject();
  } else {
    separate_active = 1;
    coap_separate_accept(request, &separate_store->request_metadata);
    snprintf(separate_store->buffer, sizeof(separate_store->buffer), "StoredInfo");

// Testzeug das dauer - BEGIN
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

    printf("ECC - START\n");
    ecc_ec_mult(base_x, base_y, private_key, result_x, result_y);
    printf("ECC - ENDE\n");
// Testzeug das dauer - ENDE

    device_name_finalize_handler();
  }
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
}

void device_name_finalize_handler() {
  if (separate_active) {
    coap_transaction_t *transaction = NULL;
    if ( (transaction = coap_new_transaction(separate_store->request_metadata.mid, &separate_store->request_metadata.addr, separate_store->request_metadata.port)) ) {
      coap_packet_t response[1]; /* This way the packet can be treated as pointer as usual. */

      /* Restore the request information for the response. */
      coap_separate_resume(response, &separate_store->request_metadata, REST.status.OK);

      coap_set_payload(response, separate_store->buffer, strlen(separate_store->buffer));

      /*
       * Be aware to respect the Block2 option, which is also stored in the coap_separate_t.
       * As it is a critical option, this example resource pretends to handle it for compliance.
       */
      coap_set_header_block2(response, separate_store->request_metadata.block2_num, 0, separate_store->request_metadata.block2_size);

      /* Warning: No check for serialization error. */
      transaction->packet_len = coap_serialize_message(response, transaction->packet);
      coap_send_transaction(transaction);
      /* The engine will clear the transaction (right after send for NON, after acked for CON). */

      separate_active = 0;
    } else {
      /*
       * Set timer for retry, send error message, ...
       * The example simply waits for another button press.
       */
    }
  } /* if (separate_active) */
}

/*
int device_name_pre_handler(struct resource_s *resource, void* request, void* response) {
   printf("PRE\n");
}

void device_name_post_handler(struct resource_s *resource, void* request, void* response) {
   printf("POST\n");
}
*/



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
