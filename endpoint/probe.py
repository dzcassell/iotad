#!/usr/bin/env python3
"""End-to-end reachability probe for the controlled iotad endpoint."""

import argparse
import json
import socket
import ssl
import struct
import urllib.request


def tcp_banner(host, port):
    with socket.create_connection((host, port), timeout=3) as sock:
        if port == 445:
            sock.sendall(b"\x00\x00\x00\x44\xfeSMB\x40\x00\x00\x00" + b"\x00" * 56)
        return sock.recv(256).decode("ascii", "replace").strip()


def dns_query(host):
    name = b"\x06beacon\x07example\x00"
    query = (b"\x12\x34" + struct.pack("!HHHHH", 0x0100, 1, 0, 0, 0) +
             name + struct.pack("!HH", 1, 1))
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(3)
        sock.sendto(query, (host, 53))
        response, _ = sock.recvfrom(512)
    return socket.inet_ntoa(response[-4:])


def ntp_query(host):
    request = b"\x23" + b"\x00" * 47
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(3)
        sock.sendto(request, (host, 123))
        response, _ = sock.recvfrom(512)
    return len(response) == 48 and response[0] & 0x7 == 4


def http_get(url, insecure=False):
    context = ssl._create_unverified_context() if insecure else None
    with urllib.request.urlopen(url, timeout=3, context=context) as response:
        return response.status


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("host")
    args = parser.parse_args()
    result = {
        "ftp": tcp_banner(args.host, 21).startswith("220"),
        "ssh": tcp_banner(args.host, 22).startswith("SSH-2.0"),
        "telnet": "login" in tcp_banner(args.host, 23),
        "dns_udp": dns_query(args.host),
        "http": http_get(f"http://{args.host}/healthz") == 200,
        "https": http_get(f"https://{args.host}/healthz", insecure=True) == 200,
        "smb": len(tcp_banner(args.host, 445)) > 0,
        "ssh_nonstandard": tcp_banner(args.host, 2222).startswith("SSH-2.0"),
        "ntp": ntp_query(args.host),
    }
    print(json.dumps(result, sort_keys=True))
    if not all(value is True or key == "dns_udp" and value == args.host
               for key, value in result.items()):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
