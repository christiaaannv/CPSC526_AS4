#include "pGen.h"

using namespace std;



int main (int argc, char** argv)
{
	if (argc != 7)
	{
		cout << "Usage .\\pGen [srcIP] [srcPort] [dstIP] [dstPort] [tcp|udp|other] [outFilename]\n";
		return -1;
	}
	

	if (strcmp(argv[5], "tcp") == 0)
	{
		makePacket(argv[1], stoi(argv[2]), argv[3], stoi(argv[4]), true, false, argv[6]);
	}
	else if (strcmp(argv[5], "udp") == 0)
	{
		makePacket(argv[1], stoi(argv[2]), argv[3], stoi(argv[4]), false, true, argv[6]);
	}
	else
	{
		makePacket(argv[1], stoi(argv[2]), argv[3], stoi(argv[4]), false, false, argv[6]);	
	}



	return 0;
}





void makePacket(char* srcIP, int srcPort, char* dstIP, int dstPort, bool isTCP, bool isUDP, string outFilename)
{
	ofstream out;

	struct iphdr*  ipHdr;
	int ipHdrLen;
	
	char data[256];
	char packet[512];
	
	vector<string> packetFilenames;
	

	strcpy(data, "\n\nEXAMPLE DATA.\n\n");

	if (isTCP)
	{
		makeTCPPacket(srcIP, srcPort, dstIP, dstPort, data, packet);
	}
	else if (isUDP)
	{
		makeUDPPacket(srcIP, srcPort, dstIP, dstPort, data, packet);
	}
	else
	{
		makeOtherPacket(srcIP, srcPort, dstIP, dstPort, data, packet);
	}


	ipHdr = (struct iphdr*)(packet);

	out.open(outFilename, std::ios::out | std::ios::binary);
	out.write((char*)packet, ipHdr->tot_len);
	out.close();

	return;
}




void makeTCPPacket(char* srcIP, int srcPort, char* dstIP, int dstPort, char* data, char* packet)
{
 
	struct iphdr* ipHdr;
	struct tcphdr* tcpHdr;
	char* payload;


	memset(packet, 0, sizeof(packet));
	ipHdr = (struct iphdr*) packet;
	tcpHdr = (struct tcphdr*) (packet + sizeof(struct iphdr));
	payload = (char*) (packet + sizeof(struct iphdr) + sizeof(struct tcphdr));
	strcpy(payload, data);


	ipHdr->ihl = 5;
	ipHdr->version = 4;
	ipHdr->tos = 0;
	ipHdr->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + strlen(payload);
	ipHdr->id = htons(54321);
	ipHdr->frag_off = 0x00;
	ipHdr->ttl = 0xFF;
	ipHdr->protocol = IPPROTO_TCP;
	ipHdr->check = 0;
	ipHdr->saddr = inet_addr(srcIP);
	ipHdr->daddr = inet_addr(dstIP);


	tcpHdr->source = htons(srcPort);
	tcpHdr->dest = htons(dstPort);
	tcpHdr->seq = 0x0;
	tcpHdr->ack_seq = 0x0;
	tcpHdr->doff = 5;
	tcpHdr->res1 = 0;
	tcpHdr->cwr = 0;
	tcpHdr->ece = 0;
	tcpHdr->urg = 0;
	tcpHdr->ack = 1;
	tcpHdr->psh = 1;
	tcpHdr->rst = 0;
	tcpHdr->syn = 0;
	tcpHdr->fin = 0;
	tcpHdr->window = htons(155);
	tcpHdr->check = 0;
	tcpHdr->urg_ptr = 0;


	return;
}





void makeUDPPacket(char* srcIP, int srcPort, char* dstIP, int dstPort, char* data, char* packet)
{
 
	struct iphdr* ipHdr;
	struct udphdr* udpHdr;
	char* payload;


	memset(packet, 0, sizeof(packet));
	ipHdr = (struct iphdr*) packet;
	udpHdr = (struct udphdr*) (packet + sizeof(struct iphdr));
	payload = (char*) (packet + sizeof(struct iphdr) + sizeof(struct udphdr));
	strcpy(payload, data);


	
	ipHdr->ihl = 5;
	ipHdr->version = 4;
	ipHdr->tos = 0;
	ipHdr->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + strlen(payload);
	ipHdr->id = htons(54321);
	ipHdr->frag_off = 0x00;
	ipHdr->ttl = 0xFF;
	ipHdr->protocol = IPPROTO_UDP;
	ipHdr->check = 0;
	ipHdr->saddr = inet_addr(srcIP);
	ipHdr->daddr = inet_addr(dstIP);


	udpHdr->source = htons(srcPort);
	udpHdr->dest = htons(dstPort);
	udpHdr->len = sizeof(struct udphdr) + strlen(payload);
	udpHdr->check = 0;



	return;
}





void makeOtherPacket(char* srcIP, int srcPort, char* dstIP, int dstPort, char* data, char* packet)
{
 
	struct iphdr* ipHdr;
	struct udphdr* udpHdr;
	char* payload;


	memset(packet, 0, sizeof(packet));
	ipHdr = (struct iphdr*) packet;
	udpHdr = (struct udphdr*) (packet + sizeof(struct iphdr));
	payload = (char*) (packet + sizeof(struct iphdr) + sizeof(struct udphdr));
	strcpy(payload, data);


	
	ipHdr->ihl = 5;
	ipHdr->version = 4;
	ipHdr->tos = 0;
	ipHdr->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + strlen(payload);
	ipHdr->id = htons(54321);
	ipHdr->frag_off = 0x00;
	ipHdr->ttl = 0xFF;
	ipHdr->protocol = 0;
	ipHdr->check = 0;
	ipHdr->saddr = inet_addr(srcIP);
	ipHdr->daddr = inet_addr(dstIP);


	udpHdr->source = htons(srcPort);
	udpHdr->dest = htons(dstPort);
	udpHdr->len = sizeof(struct udphdr) + strlen(payload);
	udpHdr->check = 0;



	return;
}
