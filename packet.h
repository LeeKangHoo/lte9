#include "mac.h"
#include "ethh.h"
#include "iph.h"
#include "tcph.h"

struct Packet{
    //EthH eth;
    IpH ip;
    TcpH tcp;
};

struct TcpOption{
    uint32_t mss;
    uint8_t nop1;
    uint32_t ws;
    uint16_t nop2;
    uint16_t sack;
}__attribute__((packed));
