#include "tcph.h"
#include "packet.h"

uint16_t TcpH::calc_checksum(Packet* packet,TcpOption* tcp_op,uint8_t* data,int data_len,bool is_connected){
    struct Tcp_Checksum tc;

    tc.saddr = packet->ip.saddr;
    tc.daddr = packet->ip.daddr;
    tc.resv = 0;
    tc.protocol = 0x06;


    int total_len;

    if (is_connected){
        total_len = sizeof(Tcp_Checksum) + sizeof(TcpH) + data_len;
        tc.len = htons(sizeof(TcpH)+data_len);
    }
    else{
        total_len = sizeof(Tcp_Checksum) + sizeof(TcpH) + sizeof(TcpOption);
        tc.len = htons(sizeof(TcpH)+sizeof(TcpOption));
        printf("%d",ntohs(tc.len));
    }

    uint8_t* buf = new uint8_t[total_len];

    memset(buf,0,total_len);

    memcpy(buf,&tc,sizeof(Tcp_Checksum));
    memcpy(buf+sizeof(Tcp_Checksum),&packet->tcp,sizeof(TcpH));
    if(data_len > 0 && is_connected){
        memcpy(buf+sizeof(Tcp_Checksum)+sizeof(TcpH),data,data_len);
    }

    if(!is_connected){
        memcpy(buf+sizeof(Tcp_Checksum)+sizeof(TcpH),tcp_op,sizeof(TcpOption));
    }

    uint32_t sum = 0;
    uint16_t* ptr = (uint16_t*)buf;

    for(int i = 0;i<total_len/2;i++){
        sum += ptr[i];
    }
    /*printf("total_len: %d, iterations: %d\n", total_len, total_len/2);
    for(int i = 0; i < total_len/2; i++) {
        uint16_t value = ptr[i];
        uint32_t old_sum = sum;
        sum += value;
        printf("i=%2d: adding %04x (%u) : %08x -> %08x\n",
               i, value, value, old_sum, sum);

        // 어느 부분의 데이터인지 표시
        if(i < sizeof(Tcp_Checksum)/2)
            printf("   (Pseudo Header)\n");
        else if(i < (sizeof(Tcp_Checksum) + sizeof(TcpH))/2)
            printf("   (TCP Header)\n");
        else
            printf("   (TCP Options)\n");
    }
*/


    if (total_len%2){
        sum += (buf[total_len-1]<<8);
    }

    while(sum>>16){
        sum = (sum&0xffff) + (sum>>16);
    }


    delete[] buf;

    return (uint16_t)~sum;
}


