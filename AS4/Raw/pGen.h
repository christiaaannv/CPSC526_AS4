#ifndef PGEN_H
#define PGEN_H


#include <stdio.h>
#include <malloc.h>
#include <string.h>
#include <signal.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <linux/if_packet.h>
#include <netinet/in.h>		 
#include <netinet/if_ether.h>
#include <arpa/inet.h>



#include <stdlib.h>
#include <errno.h>
#include <unistd.h>

#include <time.h>


#include <linux/tcp.h>
#include <linux/ip.h>
#include <linux/udp.h>


#include <string>
#include <vector>

#include <iostream>
#include <fstream>

using namespace std;


void makeTCPPacket(char* srcIP, int srcPort, char* dstIP, int dstPort, char* data, char* packet);
void makeUDPPacket(char* srcIP, int srcPort, char* dstIP, int dstPort, char* data, char* packet);
void makeOtherPacket(char* srcIP, int srcPort, char* dstIP, int dstPort, char* data, char* packet);
void makePacket(char* srcIP, int srcPort, char* dstIP, int dstPort, bool isTCP, bool isUDP, string outFilename); 



#endif
