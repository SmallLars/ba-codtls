/* __PERSIST_H__ */
#ifndef __PERSIST_H__
#define __PERSIST_H__

#include <nvm.h>

// Bloecke
// 0x18000 - 0x18FFF Random Zugriff Block 1.1
// 0x19000 - 0x19FFF Random Zugriff Block 1.2
// 0x1A000 - 0x1AFFF Random Zugriff Block 2.1
// 0x1B000 - 0x1BFFF Random Zugriff Block 2.2
// 0x1C000 - 0x1CFFF Fehlermeldungen
// 0x1D000 - 0x1DFFF Fehlermeldungen
// 0x1E000 - 0x1EFFF MAC, UUID, PIN
// 0x1F000 - 0x1FFFF Systemreserviert

#define RES_BLOCK_11     0x18000
#define RES_BLOCK_12     0x19000
#define RES_BLOCK_21     0x1A000
#define RES_BLOCK_22     0x1B000
#define LEN_BLOCK_XX     0x1000

//Read Only Vars
#define RES_MAC          0x1E000
#define LEN_MAC          0x08
#define RES_UUID         0x1E008
#define LEN_UUID         0x10
#define RES_PIN          0x1E018
#define LEN_PIN          0x08
#define RES_NAME         0x1E020
#define LEN_NAME         0x0F
#define RES_MODEL        0x1E040
#define LEN_MODEL        0x0E

#define RES_B_ERR_05     0x1C000
#define LEN_B_ERR_05     73
#define RES_B_ERR_04     0x1C080
#define LEN_B_ERR_04     51
#define RES_B_ERR_03     0x1C100
#define LEN_B_ERR_03     52
#define RES_B_ERR_02     0x1C180
#define LEN_B_ERR_02     31
#define RES_B_ERR_01     0x1C200
#define LEN_B_ERR_01     61

//Random Access Vars - Byte 0 bis 8192
#define RES_BLK_1_ACTIVE       0
#define RES_BLK_2_ACTIVE    4096
#define LEN_BLK_X_ACTIVE       1

#define RES_CLIENT_INFO_LEN    1
#define LEN_CLIENT_INFO_LEN    1

#define RES_CLIENT_INFO        2
#define LEN_CLIENT_INFO      580

#define RES_CLIENT_KEYS_LEN  582
#define LEN_CLIENT_KEYS_LEN    1

#define RES_CLIENT_KEYS      583
#define LEN_CLIENT_KEYS      360



nvmErr_t nvm_getVar(void *dest, uint32_t address, uint32_t numBytes);

nvmErr_t nvm_setVar(void *src, uint32_t address, uint32_t numBytes);

nvmErr_t nvm_cmp(void *src, uint32_t address, uint32_t numBytes);

/*
typedef enum
{
	gNvmErrNoError_c = 0,
	        gNvmErrInvalidInterface_c,
	        gNvmErrInvalidNvmType_c,
	gNvmErrInvalidPointer_c,
	        gNvmErrWriteProtect_c,
	        gNvmErrVerifyError_c,
	gNvmErrAddressSpaceOverflow_c,
	        gNvmErrBlankCheckError_c,
	        gNvmErrRestrictedArea_c,
	        gNvmErrMaxError_c
} nvmErr_t;
*/

#endif /* __PERSIST_H__ */
