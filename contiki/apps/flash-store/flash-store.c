#include "flash-store.h"

#define RES_BLOCK_11     0x18000
#define RES_BLOCK_12     0x19000
#define RES_BLOCK_21     0x1A000
#define RES_BLOCK_22     0x1B000
#define LEN_BLOCK_XX     0x1000
#define LEN_BLOCK        0x01

#define STACK_NUM        (RES_STACK / LEN_STACK)

#define DEBUG 0

#if DEBUG
    #include <stdio.h>
    #include "mc1322x.h"
    #define PRINTF(...) printf(__VA_ARGS__)
#else
    #define PRINTF(...)
#endif

uint16_t stackPointer;

/* Private Funktionsprototypen --------------------------------------------- */

fpoint_t getAddr(fpoint_t address);

/* Öffentliche Funktionen -------------------------------------------------- */

void nvm_init() {
    PRINTF("Löschen der Random-Zugriffs-Blöcke");

    nvm_erase(gNvmInternalInterface_c, gNvmType_SST_c, 0x0F000000);

    nvm_write(gNvmInternalInterface_c, gNvmType_SST_c, "\001", RES_BLOCK_11, 1);
    nvm_write(gNvmInternalInterface_c, gNvmType_SST_c, "\001", RES_BLOCK_21, 1);

    uint16_t i;
    for (i = 1; i < 0x2000; i++) {
        #if DEBUG
            if (i % 0x400 == 0) PRINTF(" .");
        #endif
        nvm_write(gNvmInternalInterface_c, gNvmType_SST_c, "\0", RES_BLOCK_11 + i, 1);
        nvm_write(gNvmInternalInterface_c, gNvmType_SST_c, "\0", RES_BLOCK_21 + i, 1);
    }

    PRINTF(" Erfolgreich!\n");
}

nvmErr_t nvm_getVar(void *dest, fpoint_t address, uint16_t numBytes) {
    address = getAddr(address);

    if (address >= 0x18000 && address <= 0x1FFFF) {
        PRINTF("Lesen von Adresse: %p\n", address);
        nvmErr_t err = nvm_read(gNvmInternalInterface_c, gNvmType_SST_c, dest, address, numBytes);
        if (err) {
            PRINTF("Lesefehler, nmv_error: %u\n", err);
            return err;
        }
        return gNvmErrNoError_c;
    }

    PRINTF("Lesefehler - Ungültiger Bereich.\n");
    return gNvmErrInvalidPointer_c;
}

nvmErr_t nvm_setVar(void *src, fpoint_t address, uint16_t numBytes) {
    #if DEBUG
        printf("SetVar - START . ");
        uint32_t time = *MACA_CLK;
    #endif

    if (address >= 8192) {
        PRINTF("Schreibfehler - Ungültiger Bereich.\n");
        return gNvmErrInvalidPointer_c;
    }
    uint16_t block_len = (address < 4096 ? LEN_BLOCK_1 : LEN_BLOCK_2);

    address = getAddr(address);

    fpoint_t src_block = address & 0xFF000;
    fpoint_t dst_block = src_block ^ 0x01000;
    address = address & 0x00FFF;

    nvm_erase(gNvmInternalInterface_c, gNvmType_SST_c, 1 << (dst_block / LEN_BLOCK_XX));

    uint32_t i;
    for (i = 0; i < address; i++) {
        uint8_t buf;
        nvm_read(gNvmInternalInterface_c, gNvmType_SST_c, &buf, src_block + i, 1);
        nvm_write(gNvmInternalInterface_c, gNvmType_SST_c, &buf, dst_block + i, 1);
    }
    PRINTF("Schreiben auf Adresse: %p\n", dst_block + i);
    nvm_write(gNvmInternalInterface_c, gNvmType_SST_c, src, dst_block + i, numBytes);
    for (i += numBytes; i < block_len; i++) {
        uint8_t buf;
        nvm_read(gNvmInternalInterface_c, gNvmType_SST_c, &buf, src_block + i, 1);
        nvm_write(gNvmInternalInterface_c, gNvmType_SST_c, &buf, dst_block + i, 1);
    }

    nvm_erase(gNvmInternalInterface_c, gNvmType_SST_c, 1 << (src_block / LEN_BLOCK_XX));

    #if DEBUG
        time = *MACA_CLK - time;
        printf("BEENDET NACH %u MS\n", time / 250);
    #endif

    return gNvmErrNoError_c;
}

nvmErr_t nvm_cmp(void *src, fpoint_t address, uint16_t numBytes) {
    address = getAddr(address);

    return nvm_verify(gNvmInternalInterface_c, gNvmType_SST_c, src, address, numBytes);
}

void stack_init() {
    stackPointer = 0;
    nvm_erase(gNvmInternalInterface_c, gNvmType_SST_c, 1 << STACK_NUM);
}

void stack_push(uint8_t *src, uint16_t numBytes) {
    nvm_write(gNvmInternalInterface_c, gNvmType_SST_c, src, RES_STACK + stackPointer, numBytes);
    stackPointer += numBytes;
}

uint16_t stack_size() {
    return stackPointer;
}

/* Private Funktionen ------------------------------------------------------ */

fpoint_t getAddr(fpoint_t address) {
    if (address >= 0x02000) return address;

    fpoint_t block = (address & 0x01000 ? RES_BLOCK_21 : RES_BLOCK_11);
    uint8_t blockcheck = (nvm_cmp("\001", block, LEN_BLK_X_ACTIVE) == 0 ? 0 : 1);
    return block + (blockcheck << 12) + (address & 0x00FFF);
}
