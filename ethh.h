#pragma once
#include "mac.h"


#pragma pack(push,1)
struct EthH{
    Mac dmac;
    Mac smac;
    uint16_t etype;
};
#pragma pack(pop)
