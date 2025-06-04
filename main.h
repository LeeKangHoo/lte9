#include "mac.h"
#include "ethh.h"
#include "iph.h"
#include "tcph.h"

#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <sys/socket.h>
#include <unistd.h>
#include <iostream>
#include <cstring>
#include <stdlib.h>
#include <thread>

#include <ifaddrs.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <random>

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
