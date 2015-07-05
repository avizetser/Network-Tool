import socket
import time
import struct
import Project 
  
def AOSF(trg):
    s = socket.socket( socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(0x3))# the mother of sockets
    while True:
    
        packet = s.recvfrom(65565) #it is not called pack aleady but deal with it.(frame)
        packet = packet[0]
        eth_header = packet[:14]
        packet =  packet[14:]
        eth = struct.unpack("!6s6sH" , eth_header)
        ethernet_protocol = socket.ntohs(eth[2])

        #IP Header
        if  ethernet_protocol == 8 :
            ip_header = packet[:20]
            packet = packet[20:]
            iph = struct.unpack("!BBHHHBBH4s4s" , ip_header)
            version_ihl = iph[0]
            version = version_ihl >> 4
            ihl = version_ihl & 0xF
     
            iph_length = ihl * 4

            ttl = iph[5]
            ip_protocol = iph[6]
            s_addr = socket.inet_ntoa(iph[8]);
            d_addr = socket.inet_ntoa(iph[9]);

            # TCP and it comes from the target
            if ip_protocol == 6 and s_addr == trg:
                tcph = struct.unpack('!HHLLBBHHH' ,packet[:20])    
                source_port = tcph[0]
                dest_port = tcph[1]
                sequence = tcph[2]
                acknowledgement = tcph[3]
                doff_reserved = tcph[4]
                tcph_length = doff_reserved >> 4
                header_size = 20 + tcph_length * 4
                data_size = len(packet) - header_size
                 
                #get data from the packet
                data = packet[header_size:]
                if not(data.find("User-Agent:")==-1): # if the header contians USER AGENT
                    lines = data.split('\n')# takes the lines of the header
                    for i in lines:
                        if not i.find("User-Agent:") ==-1:#user agent in line
                        
                            if not i.find("Windows NT 6.1") ==-1:
                                print "windows 7" 
                                return True 
                                
                            if not i.find("Linux") ==-1:
                                print "linux" 
                                
                                if not i.find("Android") ==-1 :
                                    print "Android "+ i[i.find("Android"): i.find(";",i.find("Android"))]
                                    return True 
                                    
                            if not i.find("Windows NT 5.1") ==-1:
                                print "windows XP"
                                return True 
                                
                            if not i.find("Windows NT 6.2") ==-1:
                                print "windows 8"
                                return True
                                
                            if not i.find("Mac") ==-1:
                                print "Mac OS"
                                return True
                                
                            if not i.find("Windows NT 6.0)") ==-1:
                                print "windows VISTA"  
                                return True
                                  
