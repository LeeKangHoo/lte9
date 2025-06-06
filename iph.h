#pragma once
#include <stdint.h>
#include <arpa/inet.h>
#include <cstdio>

#pragma pack(push,1)
struct IpH{
    uint8_t ihl:4;
    uint8_t version:4;
    uint8_t tos;
    uint16_t len;
    uint16_t id;
    uint16_t offset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t saddr;
    uint32_t daddr;

    uint16_t calc_checksum();
    static uint32_t ip_parse(char* ip);
}__attribute__((packed));
#pragma pack(pop)
