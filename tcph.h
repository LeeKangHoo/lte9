#pragma once
#include <stdint.h>
#include <cstring>

struct Packet;

struct Tcp_Checksum{
    uint32_t saddr;
    uint32_t daddr;
    uint8_t resv;
    uint8_t protocol;
    uint16_t len;
};


enum TcpFlag {
    TCP_SYN = 0x02,
    TCP_ACK = 0x10,
    TCP_SYNACK = 0x12,
    TCP_PSH = 0x08,
    TCP_FIN = 0x01

};

#pragma pack(push,1)
struct TcpH{
    uint16_t sport;
    uint16_t dport;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t offset:4;
    uint8_t resv:4;

    uint8_t flag;
    uint16_t ws;
    uint16_t checksum;
    uint16_t urgent;

    uint16_t calc_checksum(Packet* packet,uint8_t* data,int data_len);

};
#pragma pack(pop)
