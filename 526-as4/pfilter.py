import sys
from struct import *
import socket,struct,binascii,os

def main():

    if len(sys.argv) != 3:
        print("Wrong number of args")
        return -1

    # Storing names of files
    script, fRules , fRwPacket= sys.argv

    packet = []
    ipHSize = 20 
    tcpheader = False 

    with open(fRwPacket, "rb") as f:
        temp =""
        i = 0
        while True:
            line = f.read(1)
            if line == b'': 
                break
            if i == 20:
                packet.append(temp)
                temp = ''
                i = 0
            print(line)
            print(len(line))
            packet.append(line)
            i++ 
            


    
        #ip_hdr = struct.unpack("!1s1s1H1H2s1B1B2s4s",packet[0])

        #print ("Source IP", socket.inet_ntoa(ip_hdr[8]))
        #print ("Destination IP", socket.inet_ntoa(ip_hdr[9]))
        #print ("Protocol", ip_hdr[6])

        #print ("\n\nTCP Header:")
        #tcpheader = pkt[0][34:54]
        #tcp_hdr = struct.unpack("!HHII2sH2sH", tcpheader)
        #print ("Source Port:", tcp_hdr[0])
        #print ("Destination Port:", tcp_hdr[1])







main()