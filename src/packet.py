from scapy.layers.inet import TCP


def capture_packets(pkt):
    if pkt[TCP].dport == 22 or pkt[TCP].dport == 80 or pkt[TCP].dport == 443:
        print(pkt.summary())
