import sys #used to get the arguments of the system call
import socket #used to  provides access to the socket interface.
import struct # used to get the struck function that can pack and unpack string and 

from Syn_flood import*
from ARPCP import* 
from ARP_Scan import*
from OSF import*
from OSFA import*
from DNSS import DNSS
from Sniffer import*

#main function 
def main(argv):
	
	#if get only action like help, arp scan 
	if len(argv)== 2:
              
	    act = argv[1]
	    if (act =="AS"):
                ARPSCAN("wlan0")
            if act == "sniff":
                sniff()
            if act =='help':
		myhelp()

	#if gets action and Target.
	if(len(argv)==3 ):
            global trg
            trg = argv[2] #the target
            act = argv[1]
            if(cheakaddr(trg)):
	        if(act =="SF"):
		    flood(trg)
                if act == "AP":
                    Posion(trg)
                if act == "O":
                    OSF(trg) 
                if(act == "AO"):
                    AOSF(trg)
                if act =="DS":
                    DNSS(trg)         
                    
		
	if(len(argv)>3)or(len(argv)==1): # gets more the 2 parmaters or 0  then it doesnt fit any action 
		print "Type help for help"

#Checks if the address is a ip version 4 address
def cheakaddr(string):
    a = string.split('.')
    if len(a) != 4:
        return False
		
    for i in a:
        if(int(i)>255 or int(i)<0):
			return False 
			print "not IP V4 addres"
    return True 

#cheaksum calculting function, takes hex string and returns 16 bit mask of the cheak sum 
def checksumcal(msg): 
	cs = 0 
	for i in range(0, len(msg), 2): # loops over the string in hops of 2.
		w1 = (ord(msg[i]) << 8) # takes the first hex value and shift it by 8
		w2 = (ord(msg[i+1]) ) 
		w = w1+w2 
		cs += w 
		
	cs = (cs>>16) + (cs & 0xffff) # exactly like : takeing the first 4 hex values and adding the other to them   
	s = ~cs & 0xffff # taking the 16 bit mask
	return s

#function that sends a ping requst to traget ip
def PING(trg):
    s= socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_ICMP)
    
    icmp_header = struct.pack("!bbHHh", 8, 0, 0, 0, 1)
    data = (192 -struct.calcsize("d")) * "Q"
    data = struct.pack("d", time.clock()) + data
    icmp_header_cheksum = Project.checksumcal(icmp_header  + data)
    
    icmp_header = struct.pack("!bbHHh", 8, 0, icmp_header_cheksum, 0, 1)
    s.sendto(icmp_header + data, (trg, 0)) 

#function that gets all the ip in the subnet
def GetAllIP():
    BR=GETMASK()
    ST=""
    BR = BR.split(".") # the ip mask 
    #now we will crate the adress in the correct format 
   
    cont =0
    for i in BR:
        if i != "255":
            ST+=i+"."
            cont+=1
    ST =ST[:len(ST)]     
    allarp=[]   
    # making all the packets and then we will send them. if we will try crating and sending, becuse the speed of python it takes time and we lose hosts... 
    
    #if x.x.x.255
    if cont == 3: 
        for i in range(255):
             allarp.append(ARP(ST+str(i)))
     
    #if x.x255.255        
    if cont ==2: 
        for i in range(255):
            for j in range(255):
                allarp.append(ARP(ST+str(i)+"."+str(j)))
    
    return allarp

#function that print the help string 
def myhelp():
    print "The usage of the the program is the action and if needed the target. \nlist of actions: \n Syn Flood - SF \n Scan with ARP -SA \n ARP Cache Posioning - AP\n Active 0perating System Fingerprinting-AOSF\n DNS Spoofing - DS \n 0perating System Fingerprinting -OSF"

def GETGATWAY():
    words = commands.getoutput("sudo route").split()
    words =  words[words.index("default")+1]
    return words 
    
if __name__ == "__main__":
    main(sys.argv)
	 
