#!/usr/bin/env python
import argparse
from scapy.all import *
from python_arptable import ARPTABLE

#Callback function once a packet is sniffed
def arp_display(pkt):
	if pkt[ARP].op == 2:  # is-at (response)
		global arp_hash
		pkt_mac=pkt[ARP].hwsrc
		pkt_ip=pkt[ARP].psrc
		#Check if ARP packet has same IP and different MAC address (poisoning/spoofing)
		if pkt_ip in arp_hash and arp_hash[pkt_ip] != pkt_mac:
			print('IP:{} with MAC:{} received contrasting MAC:{}'.format(pkt_ip, arp_hash[pkt_ip], pkt_mac))

#Cmd line in the following form arpwatch.py [-i interface]
parser=argparse.ArgumentParser()
parser.add_argument("-i","--interface")
args=parser.parse_args()

#Default interface(on my VM atleast)
interface="eth0"
if(args.interface):
	interface=args.interface

#Create dictionary of "Truth" for current entries for interface in question
arp_hash={}
for entry in ARPTABLE:
	if entry['Device'] == interface:
		arp_hash[entry['IP address']]=entry['HW address']
sniff(prn=arp_display, iface=interface, filter='arp', store=0)