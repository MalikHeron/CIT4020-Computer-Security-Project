from scapy.all import *
from scapy.layers.inet import TCP, IP

# keep track of the number of SYN packets received from each source IP address
syn_packets = defaultdict(int)
# keep track of the time when the first SYN packet was received from each source IP address
syn_packets_start_time = {}


def capture_packets(packet):
    # analyze TCP packets
    analyze_tcp_packet(packet)


def analyze_tcp_packet(packet):
    # check if the packet is a TCP packet
    if packet.haslayer(TCP):
        # get the source and destination IP addresses and ports
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport

        # check if the destination port is 22, 80, or 443
        if dst_port == 22 or dst_port == 80 or dst_port == 443:
            print(packet.summary())

        # check for specific patterns or behaviors that could indicate a threat

        # check for port scanning
        if packet[TCP].flags == 'S':  # SYN flag set
            syn_packets[src_ip] += 1
            if src_ip not in syn_packets_start_time:
                syn_packets_start_time[src_ip] = datetime.now()

            # check if the number of SYN packets received from this source IP address exceeds a certain threshold
            # within a certain time period
            time_period = timedelta(seconds=10)
            threshold = 100
            if datetime.now() - syn_packets_start_time[src_ip] < time_period:
                if syn_packets[src_ip] > threshold:
                    print(f'\033[0;33mPossible port scan attempt detected from IP address {src_ip}\033[0m')
                    # reset the count and start time for this source IP address
                    syn_packets[src_ip] = 0
                    syn_packets_start_time[src_ip] = datetime.now()
            else:
                # reset the count and start time for this source IP address
                syn_packets[src_ip] = 0
                syn_packets_start_time[src_ip] = datetime.now()

        # check for SYN flood attack
        threshold = 1000
        if packet[TCP].flags == 'S':  # SYN flag set
            syn_packets[dst_ip] += 1

            # check if the number of SYN packets received exceeds a certain threshold within a certain time period
            time_period = timedelta(seconds=1)
            if dst_ip not in syn_packets_start_time:
                syn_packets_start_time[dst_ip] = datetime.now()

            if datetime.now() - syn_packets_start_time[dst_ip] < time_period:
                if syn_packets[dst_ip] > threshold:
                    print(f'Possible SYN flood attack detected on IP address {dst_ip}')
                    # reset the count and start time for this destination IP address
                    syn_packets[dst_ip] = 0
                    syn_packets_start_time[dst_ip] = datetime.now()
            else:
                # reset the count and start time for this destination IP address
                syn_packets[dst_ip] = 0
                syn_packets_start_time[dst_ip] = datetime.now()


# existing code in your main function
filter = "tcp port 22 or tcp port 80 or tcp port 443"
capture_thread = threading.Thread(target=sniff,
                                  kwargs={'filter': filter,
                                          'prn': capture_packets,
                                          'store': False})
capture_thread.start()
