#include <string.h>

#include <erbium.h>
#include <er-coap-13.h>
#include <er-coap-13-transactions.h>

#include "mc1322x.h"

#define BLOCKSIZE 46

#define DEBUG 0

#if DEBUG
    #include <stdio.h>
    #define PRINTF(...) printf(__VA_ARGS__)
#else
    #define PRINTF(...)
#endif

#if DEBUG
void printflash() {
    uint8_t i;
    uint8_t buffer[16];

    printf("Flash:\n    ");
    nvm_read(gNvmInternalInterface_c, gNvmType_SST_c, buffer, 0, 16);
    for (i = 0; i < 16; i++) printf(" %02X", buffer[i]);
    printf("\n    ");
    nvm_read(gNvmInternalInterface_c, gNvmType_SST_c, buffer, BLOCKSIZE - 8, 16);
    for (i = 0; i < 16; i++) printf(" %02X", buffer[i]);
    printf("\n    ");
    nvm_read(gNvmInternalInterface_c, gNvmType_SST_c, buffer, (2 * BLOCKSIZE) - 8, 16);
    for (i = 0; i < 16; i++) printf(" %02X", buffer[i]);
    printf("\n");
}
#endif

uint16_t f_block;

void flasher_handler(void* request, void* response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset) {
    const uint8_t *payload = 0;
    size_t pay_len = REST.get_request_payload(request, &payload);
    if (pay_len && payload) {
        uint16_t block;
        memcpy(&block, payload, 2);
        if (block == 0xFFFF) {
            PRINTF("\n");
            #if DEBUG
                printflash();
            #endif
            // nvm_init(); Bei Bedarf auch RW-Flash löschen. Wird momentan eh bei Systemstart erledigt.
            soft_reset();
        } else {
            if (block == 0) {
                f_block = 0;
                #if DEBUG
                    printflash();
                    PRINTF("Erase: %u\n", nvm_erase(gNvmInternalInterface_c, gNvmType_SST_c, 0x00FFFFFF));
                    printflash();
                #else
                    nvm_erase(gNvmInternalInterface_c, gNvmType_SST_c, 0x00FFFFFF);
                #endif
            }
            if (f_block == block) {
                uint8_t err = nvm_write(gNvmInternalInterface_c, gNvmType_SST_c, (uint8_t *) (payload + 2), block * BLOCKSIZE, pay_len - 2);
                PRINTF("\rBlock %4u erhalten und an %5u geschrieben: %u", block, block * BLOCKSIZE, err);
                f_block++;
            } else {
                PRINTF("\nBlock %u ein weiteres Mal empfangen.\n", block);
            }
        }
        REST.set_response_status(response, CHANGED_2_04);
    }
}
