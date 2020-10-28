#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <unistd.h>
#include <pcap.h>
#include <libnet.h>
#include <time.h>
#include "ethhdr.h"
#include "arphdr.h"


#pragma pack(push, 1)
struct EthArpPacket {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct packet_info{
    struct libnet_ethernet_hdr ethernet;
    struct libnet_ipv4_hdr ipv4;
    struct libnet_tcp_hdr tcp;
};
#pragma pack(pop)


#define MAC_ALEN 6
#define MAC_BROADCAST "ff:ff:ff:ff:ff:ff"
#define MAC_NULL "00:00:00:00:00:00"


Ip my_ip(const char* interface);
Mac my_mac(const char* interface);
void send_arp(pcap_t* handle, Mac eth_dmac, Mac eht_smac, ArpHdr::Operation todo, Mac arp_smac, Ip arp_sip, Mac arp_tmac, Ip arp_tip);
EthArpPacket recv_arp(pcap_t* handle, Ip send_ip);
void arp_spoof_init(pcap_t* handle, int idx);
Mac get_mac_addr(pcap_t* handle, char* ipaddr);
void relay_packet(pcap_t *handle, packet_info* packet, int idx);
