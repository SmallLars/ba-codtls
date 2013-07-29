#include "time.h"

#include "mc1322x.h"
#include "flash-store.h"

uint32_t getTime() {
    uint32_t time;
    nvm_getVar((void *) &time, RES_FLASHTIME, LEN_FLASHTIME);
    return time + (*MACA_CLK / 250000);
}
