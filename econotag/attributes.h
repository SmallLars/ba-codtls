/* __ATTRIBUTES_H__ */
#ifndef __ATTRIBUTES_H__
#define __ATTRIBUTES_H__

#include "erbium.h"

RESOURCE(device_name, METHOD_GET, "d/name","rt=\"gobi.dev.n\";if=\"core.rp\"");
RESOURCE(device_model, METHOD_GET, "d/model","rt=\"gobi.dev.mdl\";if=\"core.rp\"");
RESOURCE(device_identifier, METHOD_GET, "d/identifier","rt=\"gobi.dev.id\";if=\"core.rp\"");

#endif /* __ATTRIBUTES_H__ */