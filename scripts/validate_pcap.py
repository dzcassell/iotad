#!/usr/bin/env python3
"""Validate that an iotad PCAP contains the required traffic families."""

import argparse
import collections
import sys

from scapy.all import ARP, BOOTP, DNS, Ether, IP, NTP, Raw, TCP, UDP, rdpcap


REQUIRED_TCP_PORTS = {21, 22, 102, 445, 502, 1883, 1911, 2222, 2404, 2575, 4840, 5007, 5094,
                      7878, 11112, 20000}
REQUIRED_UDP_PORTS = {53, 67, 123, 3671, 5353, 5683, 47808}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap")
    args = ap.parse_args()
    packets = rdpcap(args.pcap)
    if not packets:
        sys.exit("PCAP is empty")

    tcp_ports, udp_ports = collections.Counter(), collections.Counter()
    payload_ports = set()
    ether_types = collections.Counter()
    layers = collections.Counter()
    for pkt in packets:
        if pkt.haslayer(Ether):
            ether_types[pkt[Ether].type] += 1
        for layer in (ARP, BOOTP, DNS, NTP):
            if pkt.haslayer(layer):
                layers[layer.__name__] += 1
        if pkt.haslayer(TCP):
            tcp_ports[pkt[TCP].dport] += 1
            tcp_ports[pkt[TCP].sport] += 1
            # Some well-known payloads (notably SMB2) are dissected into a
            # protocol layer rather than left as Scapy Raw.
            if bytes(pkt[TCP].payload):
                payload_ports.add(pkt[TCP].dport)
                payload_ports.add(pkt[TCP].sport)
        if pkt.haslayer(UDP):
            udp_ports[pkt[UDP].dport] += 1
            udp_ports[pkt[UDP].sport] += 1

    missing_layers = [name for name in ("ARP", "BOOTP", "DNS", "NTP") if not layers[name]]
    missing_tcp = sorted(p for p in REQUIRED_TCP_PORTS if not tcp_ports[p])
    missing_payload = sorted(p for p in REQUIRED_TCP_PORTS if p != 102 and p not in payload_ports)
    missing_udp = sorted(p for p in REQUIRED_UDP_PORTS if not udp_ports[p])
    if not ether_types[0x8892]:
        missing_layers.append("PROFINET EtherType 0x8892")
    errors = []
    if missing_layers:
        errors.append("missing layers: " + ", ".join(missing_layers))
    if missing_tcp:
        errors.append("missing TCP ports: " + ", ".join(map(str, missing_tcp)))
    if missing_payload:
        errors.append("missing TCP application payloads: " + ", ".join(map(str, missing_payload)))
    if missing_udp:
        errors.append("missing UDP ports: " + ", ".join(map(str, missing_udp)))
    if errors:
        sys.exit("; ".join(errors))
    print(f"validated {len(packets)} packets; required protocol families present")


if __name__ == "__main__":
    main()
