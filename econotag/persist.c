#include <string.h>

#include "persist.h"

nvmErr_t nvm_getVar(void *dest, uint32_t address, uint32_t numBytes) {
    if (address < 8192) {
        uint32_t block = (address / LEN_BLOCK == 0 ? RES_BLOCK_11 : RES_BLOCK_21);
        uint8_t blockcheck = (nvm_cmp("\001", block, LEN_BLOCK_XX) == 0 ? 0 : 1);
        address = block + (blockcheck * LEN_BLOCK) + (address % LEN_BLOCK);
    }

    if (address >= 0x18000 && address <= 0x1FFFF) {
        //printf("Lesen von Adresse: %p\n", address);
        nvmErr_t err = nvm_read(gNvmInternalInterface_c, gNvmType_SST_c, dest, address, numBytes);
        if (err) {
            //printf("Lesefehler, nmv_error: %u\n", err);
            return err;
        }
        return gNvmErrNoError_c;
    }

    //printf("Lesefehler - Ungültiger Bereich.\n"); // TODO
    return gNvmErrInvalidPointer_c;
}

nvmErr_t nvm_setVar(void *src, uint32_t address, uint32_t numBytes) {
    if (address >= 8192) {
        //printf("Schreibfehler - Ungültiger Bereich.\n"); // TODO
        return gNvmErrInvalidPointer_c;
    }

    uint32_t block = (address / LEN_BLOCK == 0 ? RES_BLOCK_11 : RES_BLOCK_21);
    uint8_t blockcheck = (nvm_cmp("\001", block, LEN_BLOCK_XX) == 0 ? 0 : 1);
    address = block + (blockcheck * LEN_BLOCK) + (address % LEN_BLOCK);

    uint32_t src_block = block + (blockcheck * LEN_BLOCK);
    uint32_t dest_block = block + LEN_BLOCK - (blockcheck * LEN_BLOCK);
    address = address % LEN_BLOCK;

    nvm_erase(gNvmInternalInterface_c, gNvmType_SST_c, 1 << (dest_block / LEN_BLOCK));

    int i;
    for (i = 0; i < address; i++) {
        uint8_t buf;
        nvm_read(gNvmInternalInterface_c, gNvmType_SST_c, &buf, src_block + i, 1);
        nvm_write(gNvmInternalInterface_c, gNvmType_SST_c, &buf, dest_block + i, 1);
    }
    //printf("Schreiben auf Adresse: %p\n", dest_block + i);
    nvm_write(gNvmInternalInterface_c, gNvmType_SST_c, src, dest_block + i, numBytes);
    for (i += numBytes; i < LEN_BLOCK; i++) {
        uint8_t buf;
        nvm_read(gNvmInternalInterface_c, gNvmType_SST_c, &buf, src_block + i, 1);
        nvm_write(gNvmInternalInterface_c, gNvmType_SST_c, &buf, dest_block + i, 1);
    }

    nvm_erase(gNvmInternalInterface_c, gNvmType_SST_c, 1 << (src_block / LEN_BLOCK));

    return gNvmErrNoError_c;
}

nvmErr_t nvm_cmp(void *src, uint32_t address, uint32_t numBytes) {
    if (address < 8192) {
        uint32_t block = (address / LEN_BLOCK == 0 ? RES_BLOCK_11 : RES_BLOCK_21);
        uint8_t blockcheck = (nvm_cmp("\001", block, LEN_BLOCK_XX) == 0 ? 0 : 1);
        address = block + (blockcheck * LEN_BLOCK) + (address % LEN_BLOCK);
    }

    return nvm_verify(gNvmInternalInterface_c, gNvmType_SST_c, src, address, numBytes);
}
