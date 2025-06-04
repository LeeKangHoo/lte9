#include "main.h"


uint32_t client_ip;// in network byte order my ip
uint32_t server_ip;
uint16_t n_port;
char* intf;

uint32_t seq = htonl(rand()&0xFFFFFFFF);
uint32_t ack = 0;
uint16_t id = htons(rand()&0xFFFF);
bool is_connected = false;

/*void loop_cb(u_char* pcap_handle,const struct pcap_pkthdr *hdr,const u_char* raw_packet){
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

    pcap_t* pcap = (pcap_t*)pcap_handle;
    pcap_sendpacket(pcap,(const uchar*)&packet,packet_size);

}*/

void cb(struct nfq_q_handle* nfq_q_h, struct nfgenmsg* nfmsg, struct nfq_data* data, void* u_data){
    struct Packet packet;
    struct TcpOption tcp_op;
    unsigned char* o_packet;
    struct nfqnl_msg_packet_hdr p_h = nfq_get_msg_packet_hdr(data);
    uint32_t id = ntohl(p_h->packet_id);

    int o_len = nfq_get_payload(data,&o_packet);
    int len = sizeof(Packet) + o_len;


    packet.ip.version = 0x04;
    packet.ip.ihl = 0x05;
    packet.ip.tos = 0;
    packet.ip.len = htons(len);
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
    packet.tcp.seq_num = seq;
    packet.tcp.ack_num = ack;



    if (is_connected){

    }
    else{
        packet.ip.version = 0x04;
        packet.ip.ihl = 0x05;
        packet.ip.tos = 0;
        packet.ip.len = htons(len);
        packet.ip.id = id;
        packet.ip.offset = htons(0x4000);
        packet.ip.ttl = 0x40;
        packet.ip.protocol = 0x06;
        packet.ip.checksum = 0x0000;
        packet.ip.saddr = client_ip;
        packet.ip.daddr = server_ip;
        packet.ip.checksum = packet.ip.calc_checksum();

        packet.tcp.sport = n_port;
        packet.tcp.dport = n_port;
        packet.tcp.seq_num = seq;
        packet.tcp.ack_num = ack;
        packet.tcp.offset = (sizeof(TcpH)+sizeof(TcpOption)) / 4;
        packet.tcp.resv = 0;

        packet.tcp.flag = TCP_SYN;

    }



    unsigned char n_packet[65535];
    memcpy(n_packet,&packet,sizeof(Packet));
    memcpy(n_packet+sizeof(Packet),o_packet,sizeof(o_len));



    return nfq_set_verdict(nfq_q_h,id,NF_ACCEPT,0,NULL);
}

int main(int argc, char *argv[])
{
    struct nfq_handle* nfq_h = nfq_open();

    nfq_unbind_pf(nfq_h,AF_INET);
    nfq_bind_pf(nfq_h,AF_INET);


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

    //global var set
    intf = argv[1];
    server_ip = IpH::ip_parse(argv[2]);
    n_port = 4000; //htons(atoi(argv[3]));

    struct nfq_q_handle* nfq_q_h = nfq_create_queue(nfq_h,0,&cb,NULL);

    nfq_set_mode(nfq_q_h,NFQNL_COPY_PACKET,0xffff);

    int fd = nfq_fd(nfq_h);
    char buf[4096];

    while(1){
        int rv = recv(fd,buf,sizeof(buf),0);
        if (rv>=0) {
            nfq_handle_packet(nfq_h,buf,rv);
        }
    }





}



