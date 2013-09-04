/* __ATTRIBUTES_H__ */
#ifndef __ATTRIBUTES_H__
#define __ATTRIBUTES_H__

#include "erbium.h"

RESOURCE(device, METHOD_GET | HAS_SUB_RESOURCES, "d","rt=\"device.information\";if=\"core.rp\";ct=42");

RESOURCE(time, METHOD_POST, "time","rt=\"device.time.update\";if=\"core.b\";ct=0");

#endif /* __ATTRIBUTES_H__ */
