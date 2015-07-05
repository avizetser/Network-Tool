# encoding=utf8
import socket
import time
import struct
import Project 


def OSF(trg):
    Project.PING(trg)
    Project.PING(trg)
    Project.PING(trg)
    Project.PING(trg)
    s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0800)) # ip packets
    s.bind(("wlan0", 0))
    
    while 1:
        packet= s.recvfrom(65565)
        packet = packet[0] #the socket returns many "stuff" and the first one is the packet is self
        
        packet =  packet[14:] # throwing away the ethernet header
        
        ip_header = packet[:20]#the ip header 
        packet = packet[20:]# slicing the ip header 
        
        iph = struct.unpack("!BBHHHBBH4s4s" , ip_header)
        version_ihl = iph[0]
        
        version = version_ihl >> 4
        ihl = version_ihl & 0xF
 
        iph_length = ihl * 4

        ttl = iph[5]
        protocol = iph[6]
        s_addr = socket.inet_ntoa(iph[8])
        d_addr = socket.inet_ntoa(iph[9])
 
        if protocol  == 0x01 and s_addr == trg:
           
            if(ttl == 64):  
                print "linux or FreeBSD "
            elif ttl == 128:
                print "windows"
            elif ttl == 255:
                print "Cisco IOS"
               
            return True
    
        
      

    

