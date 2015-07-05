import socket #used to  provides access to the socket interface.
import struct 
import commands 
import binascii
from netaddr import *
import time 
import Project

#the "main" function
def ARPSCAN(inteface):
     
    allarp=Project.GetAllIP()   

    #crates a socket that will send all the packet one by one            
    ether_socket = socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.SOCK_RAW)# the sending socket
    ether_socket.bind(("wlan0",socket.SOCK_RAW)) #bing to the corrct interface.
    rawSocket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
    
    for i in allarp: #sending the packet 3 times to insure that it will get to the distination 
        ether_socket.send(i)
        ether_socket.send(i)
        ether_socket.send(i)                    
                        
    
    print "Finshed sending packets"    
    
    # resiving the answers
    
    start = time.time()
    
    #puting all the answers in an array 
    allres =[]
    while (time.time()-start <10): # withing 10 sec to get all the responses 
        response = rawSocket.recvfrom(2048)
       
        trg = socket.inet_ntoa(response[0][28:32])#if we get a packet back from the ip we sent to... that means that he is alive!!! 
        oui  =""
        mac =MACaddresPasrser(response[0][22:28])# the mac addrees of the ip we asked  
		
		#tring to find hardware type in the collection       
        try:
            oui =  EUI(mac).oui
            oui= str(oui.registration().org) 
              
        except :
            pass 
        l= len(trg )
        g= " "*(17-l)
        
        allres.append( trg + g + mac  +"   " + oui)        
			  
    print "IP Address   "+"    MAC Address       "+ "  Hardware Type " 
    print "--------------------------------------------------"  
     
    allres=set(allres)
    allres= list(allres)
    for i in allres:
        print i  
             
# function that crates an arp packet from the host to the trg (target) and returns it 
def ARP(trg):
    #gets the mac and ip of the system 
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
    return Ether +arp
    
#def that returns the mask of the network 
def GETMASK():  
    words = commands.getoutput("ifconfig " + "wlan0").split("wlan0")
    words=words[1]
    words=words.split()
    words= words[ words.index("addr:"+GETIP())+1 ]
    return words[6:]    
    
    
#funtion that returns the MAC address of the host 
def GETAMAC():
    words = commands.getoutput("ifconfig " + "wlan0").split()
    return words[ words.index("HWaddr") + 1 ]

#gets string of mac adresss and displayes it
def MACaddresPasrser(addr):
    return  "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(addr[0]) , ord(addr[1]) , ord(addr[2]), ord(addr[3]), ord(addr[4]) , ord(addr[5]))
    
#function that return the ip of the host 
def GETIP():
    words = commands.getoutput("ifconfig " + "wlan0").split("wlan0")
    words=words[1]
    words=words.split()
    words= words[ words.index("inet") + 1 ]
    words=words[5:]
    return words
 
