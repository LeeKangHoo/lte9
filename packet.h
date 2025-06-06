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
    uint8_t kind_mss;
    uint8_t length_mss;
    uint16_t value_mss;

    uint8_t kind_sack;
    uint8_t length_sack;

    uint8_t kind_ts;
    uint8_t length_ts;
    uint32_t value_ts;
    uint32_t echo_ts;

    uint8_t nop1;
    //uint16_t nop2;

    uint8_t kind_ws;
    uint8_t length_ws;
    uint8_t count_ws;

}__attribute__((packed));
