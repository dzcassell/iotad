#!/usr/bin/env python3
"""Controlled multi-protocol endpoint for iotad RPF lab campaigns."""

import argparse
import ipaddress
import json
import os
import socketserver
import ssl
import struct
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


ENDPOINT_IP = os.environ.get("ENDPOINT_IP", "192.168.7.20")
MAX_ARTIFACT = int(os.environ.get("MAX_ARTIFACT_BYTES", str(1024 * 1024)))
COUNTERS = {}
COUNTER_LOCK = threading.Lock()


def count(name):
    with COUNTER_LOCK:
        COUNTERS[name] = COUNTERS.get(name, 0) + 1


def snapshot():
    with COUNTER_LOCK:
        return dict(COUNTERS)


def dns_name(packet, offset=12):
    labels = []
    while offset < len(packet):
        length = packet[offset]
        offset += 1
        if length == 0:
            break
        if length & 0xC0 or offset + length > len(packet):
            raise ValueError("compressed or malformed DNS question")
        labels.append(packet[offset:offset + length].decode("ascii", "replace"))
        offset += length
    return ".".join(labels).lower(), offset


def dns_response(query):
    if len(query) < 12:
        return b""
    try:
        qname, end = dns_name(query)
    except ValueError:
        return b""
    question_end = end + 4
    if question_end > len(query):
        return b""
    nxdomain = qname.endswith(".invalid") or qname.endswith(".local")
    flags = 0x8183 if nxdomain else 0x8180
    answer_count = 0 if nxdomain else 1
    header = query[:2] + struct.pack("!HHHHH", flags, 1, answer_count, 0, 0)
    question = query[12:question_end]
    if nxdomain:
        return header + question
    address = ipaddress.ip_address(ENDPOINT_IP).packed
    answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 30, len(address)) + address
    return header + question + answer


class ReusableTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class ReusableUDPServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True


class ProtocolHandler(socketserver.BaseRequestHandler):
    def handle(self):
        port = self.server.server_address[1]
        self.request.settimeout(5)
        if port == 21:
            count("ftp")
            self.request.sendall(b"220 iotad controlled FTP endpoint ready\r\n")
            self._ftp()
        elif port in (22, 2222):
            count("ssh" if port == 22 else "ssh_nonstandard")
            self.request.sendall(b"SSH-2.0-OpenSSH_9.9 iotad-rpf-lab\r\n")
            self._read()
        elif port == 23:
            count("telnet")
            self.request.sendall(b"iotad-rpf login: ")
            self._read()
        elif port == 53:
            count("dns_tcp")
            header = self._read_exact(2)
            if header:
                query = self._read_exact(struct.unpack("!H", header)[0])
                response = dns_response(query)
                if response:
                    self.request.sendall(struct.pack("!H", len(response)) + response)
        elif port == 445:
            count("smb")
            data = self._read()
            if data:
                body = b"\xfeSMB\x40\x00\x00\x00" + b"\x00" * 56
                self.request.sendall(struct.pack("!I", len(body)) + body)

    def _read(self):
        try:
            return self.request.recv(8192)
        except (TimeoutError, OSError):
            return b""

    def _read_exact(self, size):
        data = b""
        while len(data) < size:
            try:
                chunk = self.request.recv(size - len(data))
            except (TimeoutError, OSError):
                return b""
            if not chunk:
                return b""
            data += chunk
        return data

    def _ftp(self):
        replies = {
            "USER": b"331 Password required\r\n",
            "PASS": b"230 Login successful\r\n",
            "TYPE": b"200 Type set\r\n",
            "STOR": b"150 Transfer accepted\r\n226 Transfer complete\r\n",
            "QUIT": b"221 Goodbye\r\n",
        }
        for _ in range(8):
            data = self._read()
            if not data:
                break
            command = data.decode("ascii", "ignore").strip().split(" ", 1)[0].upper()
            self.request.sendall(replies.get(command, b"200 OK\r\n"))
            if command == "QUIT":
                break


class DNSUDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        count("dns_udp")
        query, sock = self.request
        response = dns_response(query)
        if response:
            sock.sendto(response, self.client_address)


class NTPUDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        count("ntp")
        request, sock = self.request
        if len(request) < 48:
            return
        now = time.time() + 2208988800
        seconds = int(now)
        fraction = int((now - seconds) * (1 << 32))
        response = bytearray(48)
        response[0] = 0x24  # leap=0, version=4, server mode
        response[1] = 2
        response[2] = request[2]
        response[3] = 0xEC
        response[12:16] = b"IOTA"
        response[24:32] = request[40:48]
        stamp = struct.pack("!II", seconds, fraction)
        response[32:40] = stamp
        response[40:48] = stamp
        sock.sendto(response, self.client_address)


class HTTPHandler(BaseHTTPRequestHandler):
    server_version = "iotad-rpf/1.0"

    def do_GET(self):
        count("https" if isinstance(self.request, ssl.SSLSocket) else "http")
        if self.path.startswith("/healthz"):
            self._json(200, {"status": "ok", "endpoint_ip": ENDPOINT_IP,
                             "counters": snapshot()})
        elif self.path.startswith("/beacon"):
            self._json(200, {"status": "checked-in", "time": int(time.time())})
        elif self.path.startswith("/artifact.bin"):
            size = 65536
            if "size=" in self.path:
                try:
                    size = int(self.path.split("size=", 1)[1].split("&", 1)[0])
                except ValueError:
                    size = 65536
            size = max(0, min(size, MAX_ARTIFACT))
            body = (b"IOTAD-LAB-ARTIFACT\n" * ((size // 19) + 1))[:size]
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self):
        count("upload")
        length = min(int(self.headers.get("Content-Length", "0")), MAX_ARTIFACT)
        received = len(self.rfile.read(length))
        self._json(200, {"status": "received", "bytes": received})

    def _json(self, status, value):
        body = json.dumps(value, sort_keys=True).encode() + b"\n"
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        print("http", self.client_address[0], fmt % args, flush=True)


def ensure_certificate(cert, key):
    if os.path.exists(cert) and os.path.exists(key):
        return
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
        "-keyout", key, "-out", cert, "-days", "30",
        "-subj", "/CN=iotad-rpf-lab.invalid/O=iotad lab",
        "-addext", "subjectAltName=DNS:iotad-rpf-lab.invalid",
    ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def serve():
    cert, key = "/tmp/iotad-cert.pem", "/tmp/iotad-key.pem"
    ensure_certificate(cert, key)
    servers = [
        ReusableTCPServer(("0.0.0.0", port), ProtocolHandler)
        for port in (21, 22, 23, 53, 445, 2222)
    ]
    servers.extend([
        ReusableUDPServer(("0.0.0.0", 53), DNSUDPHandler),
        ReusableUDPServer(("0.0.0.0", 123), NTPUDPHandler),
        ThreadingHTTPServer(("0.0.0.0", 80), HTTPHandler),
    ])
    https = ThreadingHTTPServer(("0.0.0.0", 443), HTTPHandler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    https.socket = context.wrap_socket(https.socket, server_side=True)
    servers.append(https)
    threads = []
    for server in servers:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        threads.append(thread)
    print("iotad endpoint listening on TCP 21,22,23,53,80,443,445,2222 and UDP 53,123",
          flush=True)
    try:
        while all(thread.is_alive() for thread in threads):
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()


def main():
    parser = argparse.ArgumentParser(description="iotad controlled RPF endpoint")
    parser.add_argument("--check", action="store_true", help="validate startup dependencies")
    args = parser.parse_args()
    if args.check:
        ipaddress.ip_address(ENDPOINT_IP)
        print("configuration valid")
        return
    serve()


if __name__ == "__main__":
    main()
