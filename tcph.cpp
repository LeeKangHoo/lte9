#include "tcph.h"
#include "packet.h"

uint16_t TcpH::calc_checksum(Packet* packet,uint8_t* data,int data_len){
    struct Tcp_Checksum tc;
    tc.saddr = packet->ip.saddr;
    tc.daddr = packet->ip.daddr;
    tc.resv = 0;
    tc.protocol = 0x06;
    tc.len = htons(sizeof(TcpH)+data_len);

    int total_len = sizeof(TcpH) + sizeof(Tcp_Checksum) + data_len;

    uint8_t* buf = new uint8_t[total_len];

    memcpy(buf,&tc,sizeof(Tcp_Checksum));
    memcpy(buf+sizeof(Tcp_Checksum),&packet->tcp,sizeof(TcpH));
    if(data_len > 0){
        memcpy(buf+sizeof(Tcp_Checksum)+sizeof(TcpH),data,data_len);
    }

    uint32_t sum = 0;
    uint16_t* ptr = (uint16_t*)buf;

    if (total_len%2){
        sum += buf[total_len-1];
    }

    for(int i = 0;i<total_len/2;i++){
        sum += ptr[i];
    }

    while(sum>>16){
        sum = (sum&0xffff) + (sum>>16);
    }

    return (uint16_t)~sum;
}


