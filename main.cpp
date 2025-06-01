#include "main.h"


uint32_t client_ip;// in network byte order my ip
uint32_t server_ip;
uint16_t n_port;


void loop_cb(u_char* user,const struct pcap_pkthdr *hdr,const u_char* raw_packet){
    struct Packet packet;

    uint16_t id_count = rand();

    memcpy(&packet.eth,raw_packet,14);
    packet.ip.version = 0x04;
    packet.ip.ihl = 0x05;
    packet.ip.tos = 0;
    packet.ip.len = htons(hdr->len - sizeof(EthH)); // re
    packet.ip.id = htons(rand()&0xFFFF);
    packet.ip.offset = htons(0x4000);
    packet.ip.ttl = 0x40;
    packet.ip.protocol = 0x06;
    packet.ip.checksum = 0x0000;
    packet.ip.saddr = client_ip;
    packet.ip.daddr = server_ip;
    packet.ip.checksum = packet.ip.calc_checksum();

    packet.tcp.sport = n_port;
    packet.tcp.dport = n_port;

}



int main(int argc, char *argv[])
{

    struct sockaddr_in addr;
    int sock = socket(AF_INET,SOCK_STREAM,0);

    struct ifaddrs* ifa;
    getifaddrs(&ifa);

    for(struct ifaddrs* i = ifa;i; i = i->ifa_next){
        if(i->ifa_addr && i->ifa_addr->sa_family == AF_INET && !strcmp(i->ifa_name,argv[1])){
            //memcpy(client_ip,((struct sockaddr_in *)i->ifa_addr)->sin_addr,4);
            client_ip = ((struct sockaddr_in *)i->ifa_addr)->sin_addr.s_addr;
            break;
        }
    }
    freeifaddrs(ifa);

    server_ip = IpH::ip_parse(argv[2]);
    n_port = htons(atoi(argv[3]));

    addr.sin_family = AF_INET;
    addr.sin_port = n_port;
    addr.sin_addr.s_addr = server_ip;

    connect(sock,(struct sockaddr*)&addr,sizeof(addr));

    char err[PCAP_BUF_SIZE];
    pcap_t* pcap = pcap_open_live(argv[1],BUFSIZ,1,1000,err);
    pcap_loop(pcap,-1,loop_cb,NULL);
    pcap_close(pcap);

    /*std::cout<<client_ip<<std::endl;
    printf("0x%08x\n",client_ip);
    printf("IP: %d.%d.%d.%d\n",
           (client_ip >> 24) & 0xFF,
           (client_ip >> 16) & 0xFF,
           (client_ip >> 8) & 0xFF,
           client_ip & 0xFF);
    printf("%08x\n",ntohl(client_ip));
    */
    close(sock);
}
