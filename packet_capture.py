from scapy.all import *
import os

from scapy.layers.inet import TCP

# set up a packet capture filter
filter = "tcp port 22"
filter1 = "tcp port 80"
filter2 = "tcp port 443"


# define the function to capture packets
def capture_packets(pkt):
    if pkt[TCP].dport == 22:
        # if the packet is destined for port 22, print the packet details
        print(pkt.summary())
    if pkt[TCP].dport == 80:
        # if the packet is destined for port 80, print the packet details
        print(pkt.summary())
    if pkt[TCP].dport == 443:
        # if the packet is destined for port 443, print the packet details
        print(pkt.summary())


# start the packet capture
sniff(filter=filter, prn=capture_packets)
sniff(filter1=filter1, prn=capture_packets)
sniff(filter2=filter2, prn=capture_packets)

# define a regular expression pattern for matching HTTP request data in the captured packets
# REQUEST_PATTERN = re.compile(r'(?P<method>\w+) (?P<path>/.*) HTTP/1\.\d')
