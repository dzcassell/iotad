#!/usr/bin/env python3
"""End-to-end reachability probe for the controlled iotad endpoint."""

import argparse
import json
import socket
import ssl
import struct
import time
import urllib.request


def tcp_banner(host, port):
    with socket.create_connection((host, port), timeout=3) as sock:
        if port == 445:
            sock.sendall(b"\x00\x00\x00\x44\xfeSMB\x40\x00\x00\x00" + b"\x00" * 56)
        return sock.recv(256).decode("ascii", "replace").strip()


def ftp_transfer(host):
    with socket.create_connection((host, 21), timeout=3) as sock:
        sock.settimeout(3)
        greeting = sock.recv(256)
        for command in (b"USER service\r\n", b"PASS iotad-lab\r\n", b"TYPE I\r\n",
                        b"STOR diagnostics.bin\r\n", b"QUIT\r\n"):
            sock.sendall(command)
            sock.recv(512)
    return greeting.startswith(b"220")


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


def check(name, function):
    try:
        value = function()
        ok = bool(value)
        return name, {"ok": ok, "value": value}
    except Exception as error:
        return name, {"ok": False, "error": type(error).__name__}


def run_probe(host):
    checks = [
        check("ftp", lambda: ftp_transfer(host)),
        check("ssh", lambda: tcp_banner(host, 22).startswith("SSH-2.0")),
        check("telnet", lambda: "login" in tcp_banner(host, 23)),
        check("dns_udp", lambda: dns_query(host) == "192.168.7.20"),
        check("http", lambda: http_get(f"http://{host}/beacon") == 200),
        check("https", lambda: http_get(f"https://{host}/healthz", insecure=True) == 200),
        check("smb", lambda: len(tcp_banner(host, 445)) > 0),
        check("ssh_nonstandard", lambda: tcp_banner(host, 2222).startswith("SSH-2.0")),
        check("ntp", lambda: ntp_query(host)),
    ]
    return {name: result for name, result in checks}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("host")
    parser.add_argument("--watch", action="store_true")
    parser.add_argument("--interval", type=int, default=900)
    args = parser.parse_args()
    if args.interval < 60:
        parser.error("--interval must be at least 60 seconds")
    while True:
        result = run_probe(args.host)
        print(json.dumps({"target": args.host, "results": result,
                          "timestamp": int(time.time())}, sort_keys=True), flush=True)
        if not args.watch:
            if not all(item["ok"] for item in result.values()):
                raise SystemExit(1)
            return
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
