# encoding=utf8
import socket, sys
from struct import *
import Project

def MACaddresPasrser(addr):
    return  "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(addr[0]) , ord(addr[1]) , ord(addr[2]), ord(addr[3]), ord(addr[4]) , ord(addr[5]))

#function that gets a packet and parse it acording to the protocol 
def parser(packet):
    print "---------------------------------------------"
    #Ethernet Header
    eth_header = packet[:14]
    packet =  packet[14:]
    eth = unpack("!6s6sH" , eth_header)
    ethernet_protocol = socket.ntohs(eth[2])
    print  "Ethernet: "+"\n" +"Destination MAC:" + MACaddresPasrser(packet[0:6])+"\n"  +"Source MAC: " + MACaddresPasrser(packet[6:12])+"\n"  + "Protocol: " + str(ethernet_protocol) +" \n"
    
    #IP Header
    if  ethernet_protocol == 8 :
        ip_header = packet[:20]#the first 20 bytes are the ip protcol      
        packet = packet[20:]# we slicing the first 20 
        iph = unpack("!BBHHHBBH4s4s" , ip_header)
        vihl = iph[0] #the first 4 bites are the version and the second 4 bits are the ihl 
        version = vihl  >> 4
        ihl = vihl & 0xF 
        iph_length = ihl * 4
        ttl = iph[5]#time to live 
        ip_protocol = iph[6] #tells what is going to be the next protocl 
        s_addr = socket.inet_ntoa(iph[8])#the address that the packet came from 
        d_addr = socket.inet_ntoa(iph[9])# the address that the packet sent to  

        print "IP: "+"\n" + "Version : " + str(version) +"\n" + "IP Header Length : " + str(ihl) +"\n" + "TTL : " + str(ttl) +"\n" + "Protocol : " + str(ip_protocol) +"\n" + "Source Address : " + str(s_addr) +"\n" + "Destination Address : " + str(d_addr)  +" \n"
       
        TCP Header
        if ip_protocol == 6 :
            tcp_header = packet[:20]
            tcph = unpack("!HHLLBBHHH" , tcp_header)            
            source_port = tcph[0]
            dest_port = tcph[1]
            sequence = tcph[2]
            acknowledgement = tcph[3]
            drf = tcph[4] 
            tcph_length = drf  >> 4 #this is the tcp leangth
            falgs = 1
            checksum = tcph[6]
            packet = packet[tcph_length*4:]
            
             
            print "TCP: " +"\n" +"Source Port : " + str(source_port)  +"\n" + "Destination Port : " + str(dest_port)+"\n" + "Sequence Number : " + str(sequence) +"\n" + "Acknowledgement : " + str(acknowledgement)  +"\n"+ "TCP header length : " + str(tcph_length) +"\n" + "checksum: " +str(checksum) +"\n"
            
            data = packet[:]
            print "Data: " + data  
            
        #ICMP Header
        elif ip_protocol == 1:
            icmp_header = packet[:4]
            packet = packet[4:] 
            icmph = unpack("!BBH" , icmp_header)
             
            icmp_type = icmph[0]
            code = icmph[1]
            checksum = icmph[2]
            
            data =  packet[:]
             
            print "ICMP: " +"\n" "Type : " + str(icmp_type)+"\n" + " Code : " + str(code) +"\n" + " Checksum : " + str(checksum)+"\n"            
            print "Data: " +"\n" + data  
           
        #UDP Header
        elif ip_protocol == 17:
            udp_header = packet[:8]
            packet =packet[8:]
            udph = unpack("!HHHH" , udp_header)
             
            s_port = udph[0]
            d_port = udph[1]
            length = udph[2]
            checksum = udph[3]
                        
            data = packet[:]
            
            print  "UDP:"+"\n" +"Source Port : "  + str(s_port) +"\n" + " Dest Port : " + str(d_port) +"\n" +"Checksum : " + str(checksum) +"\n"
            print "Data : " "\n"  + data  
            
        #not IP TCP UDP 
        else :
            print "other than TCP/UDP/ICMP"
            pass

# the main sniffer
def sniff():
    s = socket.socket( socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(0x3))# ip family ,raw type, ethernet protocol 
    while True:
        packet = s.recvfrom(65565) #it is not called packed aleady(frame)
        packet = packet[0] # recvfrom return the packet and sorcue 
        parser(packet) #every frame that we get we will parse and print it
