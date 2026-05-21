from scapy.all import *
import random

packets = []
protocols = ["TCP", "UDP", "ICMP"]
src_ips = [f"192.168.1.{i}" for i in range(1, 20)]
dst_ips = [f"10.0.0.{i}" for i in range(1, 10)]
ports = [80, 443, 22, 53, 8080, 3306, 5432]

for i in range(500):
    src = random.choice(src_ips)
    dst = random.choice(dst_ips)
    sport = random.randint(1024, 65535)
    dport = random.choice(ports)
    size = random.randint(64, 1500)
    proto = random.choice(protocols)

    if proto == "TCP":
        pkt = IP(src=src, dst=dst) / TCP(sport=sport, dport=dport) / Raw(b"X" * size)
    elif proto == "UDP":
        pkt = IP(src=src, dst=dst) / UDP(sport=sport, dport=dport) / Raw(b"X" * size)
    else:
        pkt = IP(src=src, dst=dst) / ICMP()

    packets.append(pkt)

wrpcap("data/samples/test_traffic.pcap", packets)
print(f"Создан PCAP с {len(packets)} пакетами: data/samples/test_traffic.pcap")
