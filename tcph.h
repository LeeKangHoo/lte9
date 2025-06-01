#pragma once
#include <stdint.h>

#pragma pack(push,1)
struct TcpH{
    uint16_t sport;
    uint16_t dport;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t offset:4;
    uint8_t resv:4;

    uint8_t cwr:1;
    uint8_t ece:1;
    uint8_t urg:1;
    uint8_t ack:1;
    uint8_t psh:1;
    uint8_t rst:1;
    uint8_t syn:1;
    uint8_t fin:1;

    uint16_t checksum;
    uint16_t urgent;

};
#pragma pack(pop)
