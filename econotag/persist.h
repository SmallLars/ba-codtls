/* __PERSIST_H__ */
#ifndef __PERSIST_H__
#define __PERSIST_H__

#include <nvm.h>

// Bloecke
// 0x18000 - 0x18FFF Read Only Gobits Variablen
// 0x19000 - 0x19FFF Random Zugriff Block 1.1
// 0x1A000 - 0x1AFFF Random Zugriff Block 1.2
// 0x1B000 - 0x1BFFF Random Zugriff Block 2.1
// 0x1C000 - 0x1CFFF Random Zugriff Block 2.2
// 0x1D000 - 0x1DFFF Fehlermeldungen
// 0x1E000 - 0x1EFFF MAC + Fehlermeldungen
// 0x1F000 - 0x1FFFF Systemreserviert

//Read Only Vars
#define RES_UUID         0x18000
#define LEN_UUID         36
#define RES_PIN          0x18024
#define LEN_PIN          8

#define RES_BLOCK_11     0x19000
#define RES_BLOCK_12     0x1A000
#define RES_BLOCK_21     0x1B000
#define RES_BLOCK_22     0x1C000
#define LEN_BLOCK_XX     1
#define LEN_BLOCK        0x1000

#define RES_MAC          0x1e000
#define LEN_MAC          8

#define RES_B_ERR_05     0x1ED80
#define LEN_B_ERR_05     73
#define RES_B_ERR_04     0x1EE00
#define LEN_B_ERR_04     51
#define RES_B_ERR_03     0x1EE80
#define LEN_B_ERR_03     52
#define RES_B_ERR_02     0x1EF00
#define LEN_B_ERR_02     31
#define RES_B_ERR_01     0x1EF80
#define LEN_B_ERR_01     61

//Random Access Vars - Byte 0 bis 8192
#define RES_BLK_1_ACTIVE    0
#define LEN_BLK_1_ACTIVE    1

#define RES_AES_KEY         1 //Erstes Byte ist 1 falls Key vorhanden, sonst 0
#define LEN_AES_KEY        17

#define RES_PIN_VERIFIED   18
#define LEN_PIN_VERIFIED    1

#define RES_KEY_CALC       19
#define LEN_KEY_CALC       51

#define RES_BLK_2_ACTIVE 4096
#define LEN_BLK_2_ACTIVE    1

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
