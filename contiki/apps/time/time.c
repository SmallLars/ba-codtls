#include "time.h"

#include "flash-store.h"

uint32_t correction = 0;

uint32_t getTime() {
    uint32_t time;
    nvm_getVar((void *) &time, RES_FLASHTIME, LEN_FLASHTIME);
    return time + correction + clock_seconds();
}

void setTime(uint32_t time) {
    correction += (time - getTime());
}
