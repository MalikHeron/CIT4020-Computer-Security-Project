from scapy.all import *
import re

from scapy.layers.inet import TCP, IP

# define a regular expression pattern for matching HTTP request data in the captured packets
REQUEST_PATTERN = re.compile(r'(?P<method>\w+) (?P<path>/.*) HTTP/1\.\d')


# define a packet handler function
def packet_handler(pkt):
    if pkt.haslayer(TCP) and pkt.haslayer(Raw):
        # extract the source and destination IP addresses and ports from the packet
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        src_port = pkt[TCP].sport
        dst_port = pkt[TCP].dport

        # extract the raw packet data
        raw_data = pkt[Raw].load.decode(errors='ignore')

        # check if the packet contains an HTTP request
        match = REQUEST_PATTERN.search(raw_data)
        if match:
            # extract the HTTP method and path from the request
            method = match.group('method')
            path = match.group('path')

            # log the HTTP request and its source
            print(f'HTTP request received from {src_ip}:{src_port} - {method} {path}')


# start capturing packets on the specified interface
sniff(iface='eth0', prn=packet_handler, filter='tcp and dst port 80')
