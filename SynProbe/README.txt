This python file is a command line utility to scan for open ports. 
There are default ports statically set, but you may modify this by specifying a subnet through the command line flag: -p.
Once the ports are decided, I used scapy to send SYN packets and store the answered and unanswered in respective variables. 
I consult the TCP flags of the received responses and store the open ports relative to each ip address if they were acknowledged. 
After, I iterate through each port in a given ip and wait to receive a response and ellicit one otherwise.
These responses or failure to obtain a response are logged in the command line.
