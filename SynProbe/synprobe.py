#!/usr/bin/env python
import argparse, socket
from netaddr import IPNetwork
from scapy.all import *
#Cmd line in the following form synprobe.py [-p portLo-portHi] ip
#Accepts TCP ports 1-65535
parser=argparse.ArgumentParser()
parser.add_argument("-p","--ports")
parser.add_argument("ip")
args=parser.parse_args()

#default ports if none provided
ports=[21,22,23,25,53]
if(args.ports):
	r=[int(i) for i in args.ports.split("-")]
	ports=range(r[0],r[1]+1)
#resolve subnet if any provided
subnet=str(IPNetwork(args.ip))

# IP address as [key] and open port as [value]
openPorts={}


#Perform TCP SYN scan for ports
#Multithreaded internals sends to subnet range and port range
ans, unans= sr(IP(dst=subnet)/TCP(sport=RandShort(),dport=ports,flags="S"),timeout=1,verbose=0)
#Only address answered responses
for s,r in ans:
	#print([s,r])
   	if(r[TCP] and r[TCP].flags == 0x12):
   		#destination of request, source of the response
   		dstPort=r[TCP].sport
    	dstIP=r.src
        # IP address as [key] and open port as [value]
        portList=openPorts.get(dstIP)
        if portList is None:
        	portList=[]
        portList.append(dstPort)
        openPorts[dstIP]=portList

#Connect to ports and get first 1024 byte response
#Elicit response if needed
for ip in openPorts:
	for port_p in openPorts[ip]:
		try:
		    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		    s.connect((ip,port_p))
		    response=s.recv(1024)
		    if(response is None):
		    	p = IP(dst=ip)/TCP(flags="S", sport=RandShort(),dport=port_p)/Raw("GET / HTTP/1.1\nHost: "+ip+"\n\n")
		    	s.send(bytes(p))
		    	response=s.recv(1024)
		    print("IP: {0} Open Port: {1}".format(ip, port_p))
		    if(response):
		    	print("Response Message: {0}".format(response))
		    else:
		    	print("Could not get response") 
		except Exception as e:
			raise e