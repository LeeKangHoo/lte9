#include "mac.h"
#include "ethh.h"
#include "iph.h"
#include "tcph.h"

#include <pcap.h>
#include <sys/socket.h>
#include <unistd.h>
#include <iostream>
#include <cstring>
#include <stdlib.h>

#include <ifaddrs.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <random>

struct Packet{
    EthH eth;
    IpH ip;
    TcpH tcp;
};
