#!/usr/bin/env python3
"""
Task 1: Basic Network Sniffer
- Captures packets using scapy
- Shows source/destination IPs, protocol, ports and payload
- Run with admin/root rights (needed for raw packet capture)

Install:  pip install scapy
   (Windows: also install Npcap from https://npcap.com)

Usage examples:
  sudo python3 network_sniffer.py                    # capture until Ctrl+C
  sudo python3 network_sniffer.py -c 20              # capture 20 packets
  sudo python3 network_sniffer.py -i eth0 -f "tcp port 80"
  sudo python3 network_sniffer.py -c 50 -w out.pcap  # save to pcap file
"""

import argparse
from collections import Counter
from datetime import datetime

from scapy.all import sniff, wrpcap, Raw, Ether, IP, IPv6, TCP, UDP, ICMP, ARP, DNS

packet_count = 0
protocol_stats = Counter()
captured = []

PROTO_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP"}


def format_payload(data: bytes, max_len: int = 64) -> str:
    """Return payload as printable ASCII (non-printable chars become '.')."""
    data = data[:max_len]
    return "".join(chr(b) if 32 <= b < 127 else "." for b in data)


def process_packet(packet):
    global packet_count
    packet_count += 1
    captured.append(packet)

    time_str = datetime.now().strftime("%H:%M:%S")
    print(f"\n{'=' * 60}")
    print(f"Packet #{packet_count}  [{time_str}]  Length: {len(packet)} bytes")

    # ---- Layer 2: Ethernet ----
    if packet.haslayer(Ether):
        eth = packet[Ether]
        print(f"  [Ethernet] {eth.src} -> {eth.dst}")

    # ---- ARP ----
    if packet.haslayer(ARP):
        arp = packet[ARP]
        op = "request" if arp.op == 1 else "reply"
        protocol_stats["ARP"] += 1
        print(f"  [ARP] {op}: {arp.psrc} ({arp.hwsrc}) -> {arp.pdst}")
        return

    # ---- Layer 3: IP ----
    if packet.haslayer(IP):
        ip = packet[IP]
        proto = PROTO_NAMES.get(ip.proto, f"Other({ip.proto})")
        print(f"  [IPv4] {ip.src} -> {ip.dst} | Protocol: {proto} | TTL: {ip.ttl}")
    elif packet.haslayer(IPv6):
        ip6 = packet[IPv6]
        proto = PROTO_NAMES.get(ip6.nh, f"Other({ip6.nh})")
        print(f"  [IPv6] {ip6.src} -> {ip6.dst} | Protocol: {proto}")
    else:
        protocol_stats["Other"] += 1
        print("  [Non-IP packet]")
        return

    protocol_stats[proto] += 1

    # ---- Layer 4: TCP / UDP / ICMP ----
    if packet.haslayer(TCP):
        tcp = packet[TCP]
        print(f"  [TCP] Port {tcp.sport} -> {tcp.dport} | Flags: {tcp.flags} "
              f"| Seq: {tcp.seq} | Ack: {tcp.ack}")
    elif packet.haslayer(UDP):
        udp = packet[UDP]
        print(f"  [UDP] Port {udp.sport} -> {udp.dport} | Length: {udp.len}")
    elif packet.haslayer(ICMP):
        icmp = packet[ICMP]
        print(f"  [ICMP] Type: {icmp.type} | Code: {icmp.code}")

    # ---- Application layer: DNS ----
    if packet.haslayer(DNS) and packet[DNS].qd is not None:
        qname = packet[DNS].qd.qname.decode(errors="ignore")
        print(f"  [DNS] Query: {qname}")

    # ---- Payload ----
    if packet.haslayer(Raw):
        payload = bytes(packet[Raw].load)
        print(f"  [Payload] {len(payload)} bytes")
        print(f"    ASCII: {format_payload(payload)}")
        print(f"    HEX  : {payload[:32].hex(' ')}")


def print_summary():
    print(f"\n{'#' * 60}")
    print(f"Capture finished. Total packets: {packet_count}")
    for proto, count in protocol_stats.most_common():
        print(f"  {proto:<8} {count}")


def main():
    parser = argparse.ArgumentParser(description="Basic Network Sniffer (scapy)")
    parser.add_argument("-i", "--iface", help="Interface to sniff on (default: auto)")
    parser.add_argument("-c", "--count", type=int, default=0,
                        help="Number of packets to capture (0 = until Ctrl+C)")
    parser.add_argument("-f", "--filter", default="",
                        help='BPF filter, e.g. "tcp", "udp port 53", "host 8.8.8.8"')
    parser.add_argument("-w", "--write", help="Save captured packets to a .pcap file")
    args = parser.parse_args()

    print("Starting sniffer... press Ctrl+C to stop.")
    try:
        sniff(iface=args.iface, filter=args.filter or None,
              prn=process_packet, count=args.count, store=False)
    except PermissionError:
        print("Permission denied: run as Administrator/root (sudo).")
        return
    except KeyboardInterrupt:
        pass

    print_summary()

    if args.write and captured:
        wrpcap(args.write, captured)
        print(f"Saved {len(captured)} packets to {args.write}")


if __name__ == "__main__":
    main()
