#include "iph.h"

uint16_t IpH::calc_checksum(){
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

uint32_t IpH::ip_parse(char* ip){
    uint32_t a,b,c,d;
    sscanf(ip,"%u.%u.%u.%u",&a,&b,&c,&d);

    return (d<<24) | (c<<16)| (b<<8) | a;
}
