#include "tcph.h"

uint16_t TcpH::calc_checksum(Packet* packet,uint8_t* data,int data_len){
    struct Tcp_Checksum tc;
    tc.saddr = packet.ip.saddr;
    tc.daddr = packet.ip.daddr;
    tc.resv = 0;
    tc.protocol = 0x06;
    tc.len = htons(sizeof(TcpH)+data_len);

    int total_len = sizeof(TcpH) + sizeof(Tcp_Checksum) + data_len;

    uint8_t* buf = new uint8_t[total_len];



    int sum = 0;
    uint16_t* addr = (uint16_t*)this;
    int len = sizeof(IpH);

    while (len>1){
        sum += *addr++;
        len -= 2;
    }

    while (sum>>16){
        sum = (sum&0xffff) + (sum >> 16);
    }
    return htons((uint16_t)~sum);
}


