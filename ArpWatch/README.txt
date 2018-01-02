This python file is a command line utility to monitor an interface's ARP table and logs any time that there is a "malicious" attempt to change the ARP table.
The interface is set to a static default, but it may be modified through an optional command line flag: -i
After the interface is decided, I create a dictionary of "truth" using the values the interface has currently stored.
Then I sniff for packets and I consult the dictionary and anytime there is a conflicting value for the same IP I log an "attack".
