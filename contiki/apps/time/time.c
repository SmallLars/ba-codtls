#include "time.h"

// #include "mc1322x.h"
#include "flash-store.h"

uint32_t getTime() {
    uint32_t time;
    nvm_getVar((void *) &time, RES_FLASHTIME, LEN_FLASHTIME);
    return time + clock_seconds();
}

// + (*MACA_CLK / 250000)
// + (*CRM_RTC_COUNT / *CRM_RTC_TIMEOUT);
