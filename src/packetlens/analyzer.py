import math
from collections import Counter

from scapy.all import DNSQR, IP, TCP, UDP, rdpcap


def entropy(text):
    """ Mesure how random a text higher = more random """
    counts = Counter(text)
    total = len(text)
    return -sum((n / total) * math.log2(n / total) for n in counts.values())


def looks_random(domain):
    """Heuristic: The first segment of the domain is long and appears random."""
    label = domain.split(".")[0]
    return len(label) >= 10 and entropy(label) > 3.2


def analyze(path):
    """Reads a .pcap file and returns protocols, DNS queries, and TCP connections."""
    packets = rdpcap(path)
    protocols = Counter()
    dns_queries = []
    connections = Counter()

    for pkt in packets:
        if pkt.haslayer(TCP):
            protocols["TCP"] += 1
        elif pkt.haslayer(UDP):
            protocols["UDP"] += 1
        else:
            protocols["Outros"] += 1

        if pkt.haslayer(DNSQR):
            dns_queries.append(pkt[DNSQR].qname.decode().rstrip("."))

        if pkt.haslayer(IP) and pkt.haslayer(TCP):
            chave = (pkt[IP].src, pkt[IP].dst, pkt[TCP].dport)
            connections[chave] += 1

    return {
        "total": len(packets),
        "protocols": protocols,
        "dns": dns_queries,
        "suspicious_dns": [d for d in dns_queries if looks_random(d)],
        "connections": connections.most_common(5),
    }