#!/usr/bin/env python3
"""iotad -- IoT/OT traffic simulation daemon.

Populates a lab network with believable IoT/OT assets for testing network
asset-discovery (built for Cato Networks demo/lab enrichment). It instantiates
a deterministic roster of virtual devices -- each with a REAL vendor OUI from
the IEEE registry (see build_catalog.py) -- and emits the L2/L3 traffic those
devices would emit: gratuitous ARP, DHCP with vendor fingerprints, mDNS, SSDP,
LLDP/CDP, OT discovery/poll protocols (BACnet, EtherNet/IP, PROFINET-DCP,
Modbus, S7), and outbound DNS/NTP/TLS check-ins.

It does NOT assign IPs to the host or answer active scans -- it is a passive
emitter. Every frame carries a spoofed source MAC/IP, so run it ONLY on a lab
segment you own and are authorized to test. See README.md.

    iotad.py --config /etc/iotad.conf        # run (foreground; systemd manages it)
    iotad.py --list                          # print the device roster and exit
    iotad.py --once                          # emit one pass of every beacon, then exit
    iotad.py --dry-run                        # build + schedule, print, never transmit
"""
import argparse
import configparser
import ipaddress
import logging
import os
import random
import re
import signal
import socket
import struct
import sys
import time
import uuid
from heapq import heappush, heappop

HERE = os.path.dirname(os.path.abspath(__file__))
log = logging.getLogger("iotad")

# scapy is noisy on import; quiet it before loading.
logging.getLogger("scapy").setLevel(logging.ERROR)
try:
    from scapy.all import (
        Ether, ARP, IP, ICMP, UDP, TCP, BOOTP, DHCP, DNS, DNSQR, DNSRR, DNSRRSRV,
        NTP, LLC, SNAP, Raw, conf, getmacbyip, checksum, AsyncSniffer,
    )
except Exception as e:  # pragma: no cover
    sys.exit(f"iotad: scapy import failed ({e}); install into the venv:\n"
             f"  {sys.executable} -m pip install scapy")

# ---- constants -------------------------------------------------------------
MDNS_MCAST_MAC = "01:00:5e:00:00:fb"
SSDP_MCAST_MAC = "01:00:5e:7f:ff:fa"
LLDP_MCAST_MAC = "01:80:c2:00:00:0e"
CDP_MCAST_MAC = "01:00:0c:cc:cc:cc"
PROFINET_MCAST_MAC = "01:0e:cf:00:00:00"
BCAST_MAC = "ff:ff:ff:ff:ff:ff"

SERVICE_PORTS = {
    "_http._tcp": 80, "_https._tcp": 443, "_rtsp._tcp": 554,
    "_axis-video._tcp": 80, "_printer._tcp": 9100, "_ipp._tcp": 631,
    "_pdl-datastream._tcp": 9100, "_crestron._tcp": 41794,
    "_lutron._tcp": 23, "_dahua._tcp": 80, "_opcua-tcp._tcp": 4840,
    "_ipps._tcp": 631, "_uscan._tcp": 8080, "_scanner._tcp": 9500,
    "_privet._tcp": 8008, "_smb._tcp": 445, "_sip._udp": 5060,
}
TIA_OUI = b"\x00\x12\xbb"  # TIA / LLDP-MED organizationally-specific TLVs

# beacon -> (timing-config key, default seconds). "checkin" is handled specially.
BEACON_INTERVAL = {
    "garp": ("arp_interval", 300),
    "dhcp": ("dhcp_interval", 1800),
    "mdns": ("mdns_interval", 120),
    "ssdp": ("ssdp_interval", 180),
    "lldp": ("lldp_interval", 30),
    "cdp": ("cdp_interval", 60),
    "bacnet_whois": ("discovery_interval", 120),
    "enip": ("discovery_interval", 120),
    "profinet_dcp": ("discovery_interval", 120),
    "ubnt_discover": ("discovery_interval", 120),
    "snmp": ("discovery_interval", 300),
    "modbus": ("poll_interval", 90),
    "s7": ("poll_interval", 90),
    "opcua": ("poll_interval", 90),
    "dnp3": ("poll_interval", 90),
    "fox": ("poll_interval", 90),
    "iec104": ("poll_interval", 90),
    "melsec": ("poll_interval", 90),
    "fins": ("discovery_interval", 120),
    "dns_checkin": ("checkin", 0),
    "tls_checkin": ("checkin", 0),
}
WAN_BEACONS = {"tls_checkin"}  # only run these when outbound scope includes WAN


# ---- configuration ---------------------------------------------------------
class Site:
    """One physical segment / interface, typically fronted by its own Cato
    Socket. Devices belong to a site; cross-site flows route via the site's
    gateway (Socket) so they traverse the WAN."""

    def __init__(self, name, interface, subnet, gateway, ip_start, ip_end):
        self.name = name
        self.interface = interface
        self.subnet = ipaddress.ip_network(subnet, strict=False)
        self.gateway = gateway
        self.ip_start = ipaddress.ip_address(ip_start)
        self.ip_end = ipaddress.ip_address(ip_end)
        self.gw_mac = None                 # resolved at runtime
        self.mac_cache = {}

    def pool(self):
        return [ipaddress.ip_address(a)
                for a in range(int(self.ip_start), int(self.ip_end) + 1)]

    def broadcast(self):
        return str(self.subnet.broadcast_address)


class Config:
    def __init__(self, path):
        cp = configparser.ConfigParser()
        cp.read_dict(self.defaults())
        if path and os.path.exists(path):
            cp.read(path)
        self.cp = cp

        # Sites: one or more [site:NAME] sections, else the legacy [network].
        self.sites = []
        site_secs = [s for s in cp.sections() if s.startswith("site:")]
        if site_secs:
            for sec in site_secs:
                s = cp[sec]
                self.sites.append(Site(
                    sec.split(":", 1)[1], s.get("interface"), s.get("subnet"),
                    s.get("gateway"), s.get("ip_pool_start"), s.get("ip_pool_end")))
        else:
            n = cp["network"]
            self.sites.append(Site(
                "site1", n.get("interface"), n.get("subnet"), n.get("gateway"),
                n.get("ip_pool_start"), n.get("ip_pool_end")))
        # First site's interface is the default for anything single-homed.
        self.interface = self.sites[0].interface

        s = cp["simulation"]
        self.device_count = s.getint("device_count")
        self.seed = s.getint("seed")
        cats = s.get("categories", "").strip()
        self.categories = [c.strip() for c in cats.split(",") if c.strip()]
        # Fraction of OT polls aimed at a peer on ANOTHER site (WAN traffic).
        self.cross_site_ratio = s.getfloat("cross_site_ratio", fallback=0.6)

        o = cp["outbound"]
        self.outbound_enabled = o.getboolean("enabled")
        self.outbound_scope = o.get("scope").strip().lower()  # subnet|wan|both
        self.dns_server = o.get("dns_server")
        self.ntp_server = o.get("ntp_server")

        self.timing = cp["timing"]
        r = cp["runtime"]
        self.pidfile = r.get("pidfile")
        self.logfile = r.get("logfile")
        self.dry_run = r.getboolean("dry_run")
        self.rate_limit = r.getint("max_pps")

    @staticmethod
    def defaults():
        return {
            "network": {
                "interface": "enp10s0", "subnet": "192.168.40.0/24",
                "gateway": "192.168.40.1",
                "ip_pool_start": "192.168.40.50", "ip_pool_end": "192.168.40.229",
            },
            "simulation": {"device_count": "80", "seed": "1337", "categories": ""},
            "timing": {
                "arp_interval": "300", "dhcp_interval": "1800", "mdns_interval": "120",
                "ssdp_interval": "180", "lldp_interval": "30", "cdp_interval": "60",
                "discovery_interval": "120", "poll_interval": "90",
                "checkin_min": "180", "checkin_max": "900",
            },
            "outbound": {
                "enabled": "true", "scope": "both",
                "dns_server": "192.168.40.1", "ntp_server": "pool.ntp.org",
            },
            "runtime": {
                "pidfile": "/run/iotad.pid", "logfile": "",
                "dry_run": "false", "max_pps": "50",
            },
        }


# ---- device roster ---------------------------------------------------------
class Device:
    __slots__ = ("idx", "profile", "mac", "mac_bytes", "ip",
                 "hostname", "serial", "site")

    def __init__(self, idx, profile, mac, ip, hostname, serial, site):
        self.idx, self.profile = idx, profile
        self.mac = mac
        self.mac_bytes = bytes.fromhex(mac.replace(":", ""))
        self.ip, self.hostname, self.serial = ip, hostname, serial
        self.site = site


def build_roster(catalog, cfg):
    """Deterministically create the device list (same seed -> same roster).

    Devices are distributed round-robin across the configured sites; each gets
    an address from its own site's pool. Same seed -> identical rosters, so the
    inventory (and which device lives at which site) is stable across restarts.
    """
    rng = random.Random(cfg.seed)
    profiles = catalog["profiles"]
    if cfg.categories:
        profiles = [p for p in profiles if p["category"] in cfg.categories]
    if not profiles:
        sys.exit("iotad: no catalog profiles match the configured categories")

    # Per-site shuffled address pools, and how many devices each site gets.
    pools = {}
    for si, site in enumerate(cfg.sites):
        p = site.pool()
        rng.shuffle(p)
        pools[site.name] = p
    counts = [cfg.device_count // len(cfg.sites)] * len(cfg.sites)
    for i in range(cfg.device_count % len(cfg.sites)):
        counts[i] += 1
    for site, cnt in zip(cfg.sites, counts):
        if cnt > len(pools[site.name]):
            sys.exit(f"iotad: site '{site.name}' needs {cnt} addresses but its "
                     f"pool holds {len(pools[site.name])}; widen its ip_pool")

    devices = []
    idx = 0
    cursors = {s.name: 0 for s in cfg.sites}
    # Interleave sites so the roster (and cross-site pairing) is well mixed.
    for slot in range(max(counts)):
        for si, site in enumerate(cfg.sites):
            if slot >= counts[si]:
                continue
            p = rng.choice(profiles)
            oui = rng.choice(p["ouis"])
            nic = "%02x:%02x:%02x" % (rng.randint(0, 255), rng.randint(0, 255),
                                      rng.randint(0, 255))
            mac = f"{oui}:{nic}".lower()
            serial = "%06x" % rng.randint(0, 0xFFFFFF)
            hostname = f"{p['host']}-{serial[:4]}"
            ip = str(pools[site.name][cursors[site.name]])
            cursors[site.name] += 1
            devices.append(Device(idx, p, mac, ip, hostname, serial, site))
            idx += 1
    return devices


# ---- transmitter -----------------------------------------------------------
class Tx:
    """Sends crafted frames on the wire (or logs them in dry-run). Holds one
    L2 socket per site interface; frames are sent out the device's own site."""

    def __init__(self, cfg):
        self.cfg = cfg
        self.sent = 0
        self.by_beacon = {}
        self._socks = {}
        self._window_start = time.monotonic()
        self._window_count = 0
        if not cfg.dry_run:
            conf.iface = cfg.interface
            conf.verb = 0
            for site in cfg.sites:
                if site.interface not in self._socks:
                    self._socks[site.interface] = conf.L2socket(iface=site.interface)

    def send(self, beacon, pkt, iface=None):
        self.by_beacon[beacon] = self.by_beacon.get(beacon, 0) + 1
        self.sent += 1
        if self.cfg.dry_run:
            log.info("DRY  %-14s %s", beacon, pkt.summary())
            return
        # crude token-bucket so a burst can't flood the segment
        now = time.monotonic()
        if now - self._window_start >= 1.0:
            self._window_start, self._window_count = now, 0
        if self._window_count >= self.cfg.rate_limit:
            time.sleep(max(0.0, 1.0 - (now - self._window_start)))
            self._window_start, self._window_count = time.monotonic(), 0
        self._window_count += 1
        sock = self._socks.get(iface) or self._socks.get(self.cfg.interface)
        try:
            sock.send(pkt)
        except Exception as e:
            log.warning("send failed (%s): %s", beacon, e)

    def close(self):
        for s in self._socks.values():
            try:
                s.close()
            except Exception:
                pass


# ---- emitters --------------------------------------------------------------
# Each returns a scapy packet (or list) built with the device's spoofed MAC/IP.
class Emitters:
    def __init__(self, cfg, tx, roster):
        self.cfg = cfg
        self.tx = tx
        self.roster = roster
        # index devices by (site, listening-port) for cross-site peer targeting
        self.listeners = {}
        for d in roster:
            for port in d.profile.get("ports", []):
                self.listeners.setdefault(port, []).append(d)
        self.ntp_ip = None
        self._resolve_infra()

    # -- infrastructure resolution --
    def _resolve_infra(self):
        if self.cfg.dry_run:
            for site in self.cfg.sites:
                site.gw_mac = "de:ad:be:ef:00:01"
            return
        for site in self.cfg.sites:
            site.gw_mac = self._mac_for_ip(site, site.gateway) or BCAST_MAC
            log.info("site '%s' gateway %s is at %s",
                     site.name, site.gateway, site.gw_mac)
        try:
            self.ntp_ip = socket.gethostbyname(self.cfg.ntp_server)
        except Exception:
            self.ntp_ip = None

    @staticmethod
    def _is_ip(s):
        try:
            ipaddress.ip_address(s)
            return True
        except ValueError:
            return False

    def _mac_for_ip(self, site, ip):
        if ip in site.mac_cache:
            return site.mac_cache[ip]
        try:
            m = getmacbyip(ip)
        except Exception:
            m = None
        site.mac_cache[ip] = m
        return m

    def _dst_mac_for(self, dev, ip):
        """L2 next-hop MAC for an L3 destination, from dev's site."""
        site = dev.site
        try:
            in_net = ipaddress.ip_address(ip) in site.subnet
        except ValueError:
            in_net = False
        if in_net:
            return self._mac_for_ip(site, ip) or site.gw_mac
        return site.gw_mac                     # off-subnet -> local Socket

    @staticmethod
    def _broadcast_ip(dev):
        return dev.site.broadcast()

    def _peer(self, dev):
        """Any other simulated device (used for generic intra-LAN flows)."""
        if len(self.roster) < 2:
            return None
        for _ in range(8):
            p = random.choice(self.roster)
            if p.idx != dev.idx:
                return p
        return None

    def _pick_peer(self, dev, port):
        """Pick a peer that actually LISTENS on `port`. Prefer a peer on another
        site (so the flow crosses the WAN through both Sockets) per the
        configured cross_site_ratio; otherwise stay on-segment."""
        cands = [d for d in self.listeners.get(port, []) if d.idx != dev.idx]
        if not cands:
            return None
        remote = [d for d in cands if d.site is not dev.site]
        local = [d for d in cands if d.site is dev.site]
        want_remote = remote and (not local or
                                  random.random() < self.cfg.cross_site_ratio)
        return random.choice(remote if want_remote else local)

    def _wan_ok(self):
        return self.cfg.outbound_enabled and self.cfg.outbound_scope in ("wan", "both")

    def _sub_ok(self):
        return self.cfg.outbound_enabled and self.cfg.outbound_scope in ("subnet", "both")

    # -- discovery beacons --
    def garp(self, dev):
        return (Ether(src=dev.mac, dst=BCAST_MAC) /
                ARP(op=1, hwsrc=dev.mac, psrc=dev.ip,
                    hwdst="00:00:00:00:00:00", pdst=dev.ip))

    def dhcp(self, dev):
        opts = [("message-type", "discover"),
                ("hostname", dev.hostname),
                ("vendor_class_id", dev.profile.get("dhcp_class", "")),
                ("param_req_list", [1, 3, 6, 12, 15, 28, 42, 51, 58, 59, 66, 67]),
                ("client_id", b"\x01" + dev.mac_bytes),
                "end"]
        return (Ether(src=dev.mac, dst=BCAST_MAC) /
                IP(src="0.0.0.0", dst="255.255.255.255") /
                UDP(sport=68, dport=67) /
                BOOTP(chaddr=dev.mac_bytes, xid=random.randint(0, 0xFFFFFFFF), flags=0x8000) /
                DHCP(options=opts))

    def mdns(self, dev):
        pkts = []
        for svc in dev.profile.get("mdns", []):
            inst = f"{dev.hostname}.{svc}.local"
            port = SERVICE_PORTS.get(svc, 80)
            an = (DNSRR(rrname=f"{svc}.local", type="PTR", ttl=120, rdata=inst) /
                  DNSRR(rrname=f"{dev.hostname}.local", type="A", ttl=120, rdata=dev.ip))
            dns = DNS(qr=1, aa=1, qd=None, an=an, ancount=2)
            pkts.append(Ether(src=dev.mac, dst=MDNS_MCAST_MAC) /
                        IP(src=dev.ip, dst="224.0.0.251", ttl=255) /
                        UDP(sport=5353, dport=5353) / dns)
        return pkts

    def ssdp(self, dev):
        st = dev.profile.get("ssdp_st") or "urn:schemas-upnp-org:device:Basic:1"
        uuid = f"uuid:{dev.profile['id']}-{dev.serial}"
        payload = (
            "NOTIFY * HTTP/1.1\r\n"
            "HOST: 239.255.255.250:1900\r\n"
            "CACHE-CONTROL: max-age=1800\r\n"
            f"LOCATION: http://{dev.ip}:80/description.xml\r\n"
            f"SERVER: Linux/3.14 UPnP/1.0 {dev.profile['label']}/1.0\r\n"
            f"NT: {st}\r\n"
            "NTS: ssdp:alive\r\n"
            f"USN: {uuid}::{st}\r\n\r\n"
        ).encode()
        return (Ether(src=dev.mac, dst=SSDP_MCAST_MAC) /
                IP(src=dev.ip, dst="239.255.255.250", ttl=2) /
                UDP(sport=1900, dport=1900) / Raw(payload))

    def lldp(self, dev):
        def tlv(t, val):
            return struct.pack("!H", (t << 9) | len(val)) + val
        chassis = tlv(1, b"\x04" + dev.mac_bytes)              # subtype 4 = MAC
        portid = tlv(2, b"\x03" + dev.mac_bytes)               # subtype 3 = MAC
        ttl = tlv(3, struct.pack("!H", 120))
        sysname = tlv(5, dev.hostname.encode())
        sysdesc = tlv(6, dev.profile["label"].encode())
        body = chassis + portid + ttl + sysname + sysdesc
        if dev.profile.get("lldp_med") == "voice":
            body += self._lldp_med_voice()
        body += b"\x00\x00"  # end-of-LLDPDU
        return Ether(src=dev.mac, dst=LLDP_MCAST_MAC, type=0x88CC) / Raw(body)

    @staticmethod
    def _lldp_med_voice():
        """LLDP-MED capabilities + network-policy TLVs -- the signature a
        discovery engine keys on to classify an endpoint as a VoIP phone."""
        def org(payload):                       # TLV type 127, org-specific
            return struct.pack("!H", (127 << 9) | len(payload)) + payload
        # MED capabilities: caps bitmap 0x0033, device type 3 = Endpoint Class III
        caps = TIA_OUI + b"\x01" + struct.pack("!H", 0x0033) + b"\x03"
        # Network policy: application 1 = Voice, tagged VLAN 200, L2 prio 5, DSCP 46
        vlan, prio, dscp = 200, 5, 46
        val = (1 << 22) | (vlan << 9) | (prio << 6) | dscp   # U=0 T=1 X=0
        netpol = TIA_OUI + b"\x02\x01" + struct.pack("!I", val)[1:]
        return org(caps) + org(netpol)

    def cdp(self, dev):
        def tlv(t, val):
            return struct.pack("!HH", t, len(val) + 4) + val
        body = (tlv(1, dev.hostname.encode()) +               # Device ID
                tlv(3, b"GigabitEthernet0/1") +               # Port ID
                tlv(4, struct.pack("!I", 0x00000028)) +       # Capabilities: switch
                tlv(5, b"Cisco IOS Software, iotad-sim") +    # Software version
                tlv(6, b"cisco WS-C2960"))                    # Platform
        hdr = struct.pack("!BB", 2, 180)                      # version, ttl
        cdp = hdr + b"\x00\x00" + body
        cksum = checksum(cdp)
        cdp = hdr + struct.pack("!H", cksum) + body
        return (Ether(src=dev.mac, dst=CDP_MCAST_MAC) /
                LLC(dsap=0xAA, ssap=0xAA, ctrl=3) /
                SNAP(OUI=0x00000C, code=0x2000) / Raw(cdp))

    def bacnet_whois(self, dev):
        # BVLC(Original-Broadcast) + NPDU(global broadcast) + APDU(Who-Is)
        payload = bytes([0x81, 0x0B, 0x00, 0x0C,
                         0x01, 0x20, 0xFF, 0xFF, 0x00, 0xFF,
                         0x10, 0x08])
        return (Ether(src=dev.mac, dst=BCAST_MAC) /
                IP(src=dev.ip, dst=self._broadcast_ip(dev)) /
                UDP(sport=47808, dport=47808) / Raw(payload))

    def enip(self, dev):
        # EtherNet/IP ListIdentity broadcast (command 0x0063)
        payload = struct.pack("<HHII8sI", 0x0063, 0, 0, 0, b"\x00" * 8, 0)
        return (Ether(src=dev.mac, dst=BCAST_MAC) /
                IP(src=dev.ip, dst=self._broadcast_ip(dev)) /
                UDP(sport=random.randint(1024, 65535), dport=44818) / Raw(payload))

    def profinet_dcp(self, dev):
        # PROFINET DCP Identify-All multicast
        xid = random.randint(0, 0xFFFFFFFF)
        payload = struct.pack("!HBBIHH", 0xFEFE, 0x05, 0x00, xid, 0x0000, 0x0004) + \
            bytes([0xFF, 0xFF, 0x00, 0x00])
        return Ether(src=dev.mac, dst=PROFINET_MCAST_MAC, type=0x8892) / Raw(payload)

    def ubnt_discover(self, dev):
        return (Ether(src=dev.mac, dst=BCAST_MAC) /
                IP(src=dev.ip, dst="255.255.255.255") /
                UDP(sport=random.randint(1024, 65535), dport=10001) /
                Raw(b"\x01\x00\x00\x00"))

    def snmp(self, dev):
        # SNMPv2c coldStart trap toward the local Socket (as a manager)
        target = dev.site.gateway
        trap = (b"\x30\x2c\x02\x01\x01\x04\x06public\xa7\x1f"
                b"\x02\x04" + struct.pack("!I", random.randint(0, 0xFFFFFFFF)) +
                b"\x02\x01\x00\x02\x01\x00\x30\x11\x30\x0f\x06\x08"
                b"\x2b\x06\x01\x02\x01\x01\x03\x00\x43\x03\x00\x00\x01")
        return (Ether(src=dev.mac, dst=self._dst_mac_for(dev, target)) /
                IP(src=dev.ip, dst=target) /
                UDP(sport=random.randint(1024, 65535), dport=162) / Raw(trap))

    # -- OT polls (device-to-device; same-site stays on the LAN, cross-site
    #    routes through the local Socket and traverses the WAN) --
    def _syn_to_peer(self, dev, port):
        peer = self._pick_peer(dev, port)
        if not peer:
            return None
        if peer.site is dev.site:              # same segment: direct L2
            if not self._sub_ok():
                return None
            dst_mac = peer.mac
        else:                                  # other site: via local Socket
            if not self._wan_ok():
                return None
            dst_mac = dev.site.gw_mac or BCAST_MAC
        return (Ether(src=dev.mac, dst=dst_mac) /
                IP(src=dev.ip, dst=peer.ip) /
                TCP(sport=random.randint(1024, 65535), dport=port,
                    flags="S", seq=random.randint(0, 0xFFFFFFFF)))

    def modbus(self, dev):
        return self._syn_to_peer(dev, 502)

    def s7(self, dev):
        return self._syn_to_peer(dev, 102)

    def opcua(self, dev):        # OPC UA binary (modern industrial)
        return self._syn_to_peer(dev, 4840)

    def dnp3(self, dev):         # SCADA / utility RTUs and relays
        return self._syn_to_peer(dev, 20000)

    def fox(self, dev):          # Niagara Fox / Tridium building controllers
        return self._syn_to_peer(dev, 1911)

    def iec104(self, dev):       # IEC 60870-5-104 SCADA
        return self._syn_to_peer(dev, 2404)

    def melsec(self, dev):       # Mitsubishi MELSEC / SLMP
        return self._syn_to_peer(dev, 5007)

    def fins(self, dev):
        # Omron FINS/UDP node-address broadcast (controller data read, cmd 0501)
        node = dev.mac_bytes[-1] or 1
        payload = bytes([0x80, 0x00, 0x02, 0x00, 0xFF, 0x00,
                         0x00, node, 0x00, 0x00, 0x05, 0x01, 0x00])
        return (Ether(src=dev.mac, dst=BCAST_MAC) /
                IP(src=dev.ip, dst=self._broadcast_ip(dev)) /
                UDP(sport=9600, dport=9600) / Raw(payload))

    # -- outbound check-ins (routed via the device's own Socket) --
    def dns_checkin(self, dev):
        if not self._sub_ok():
            return None
        hosts = dev.profile.get("checkin") or []
        if not hosts:
            return None
        q = random.choice(hosts)
        resolver = dev.site.gateway            # the local Socket forwards DNS
        return (Ether(src=dev.mac, dst=dev.site.gw_mac or BCAST_MAC) /
                IP(src=dev.ip, dst=resolver) /
                UDP(sport=random.randint(1024, 65535), dport=53) /
                DNS(rd=1, qd=DNSQR(qname=q, qtype="A")))

    def tls_checkin(self, dev):
        if not self._wan_ok():
            return None
        hosts = dev.profile.get("checkin") or []
        if not hosts:
            return None
        host = random.choice(hosts)
        try:
            dst = socket.gethostbyname(host)
        except Exception:
            return None
        return (Ether(src=dev.mac, dst=dev.site.gw_mac or BCAST_MAC) /
                IP(src=dev.ip, dst=dst) /
                TCP(sport=random.randint(1024, 65535), dport=443,
                    flags="S", seq=random.randint(0, 0xFFFFFFFF)))


# ---- minimal BER / SNMP ----------------------------------------------------
# Just enough ASN.1 BER to answer an SNMP v1/v2c walk of the system group --
# the primary fingerprint source for printers, UPS, switches and sensors.
def _ber_len(n):
    if n < 0x80:
        return bytes([n])
    b = []
    while n:
        b.insert(0, n & 0xFF)
        n >>= 8
    return bytes([0x80 | len(b)]) + bytes(b)


def _tlv(tag, val):
    return bytes([tag]) + _ber_len(len(val)) + val


def _enc_int(n):
    if n == 0:
        return _tlv(0x02, b"\x00")
    b = []
    v = n
    while v:
        b.insert(0, v & 0xFF)
        v >>= 8
    if b[0] & 0x80:
        b.insert(0, 0)
    return _tlv(0x02, bytes(b))


def _enc_uint(n):
    """Minimal-length unsigned encoding for the SNMP application types
    Counter32/Gauge32/TimeTicks (no sign-bit padding -- they are unsigned)."""
    n &= 0xFFFFFFFF
    if n == 0:
        return b"\x00"
    b = []
    while n:
        b.insert(0, n & 0xFF)
        n >>= 8
    return bytes(b)


def _enc_oid(oid):
    parts = [int(x) for x in oid.split(".")]
    body = bytes([40 * parts[0] + parts[1]])
    for p in parts[2:]:
        if p < 0x80:
            body += bytes([p])
        else:
            chunk = []
            while p:
                chunk.insert(0, p & 0x7F)
                p >>= 7
            for i in range(len(chunk) - 1):
                chunk[i] |= 0x80
            body += bytes(chunk)
    return _tlv(0x06, body)


def _read_tlv(buf, i):
    tag = buf[i]
    i += 1
    ln = buf[i]
    i += 1
    if ln & 0x80:
        nb = ln & 0x7F
        ln = int.from_bytes(buf[i:i + nb], "big")
        i += nb
    return tag, buf[i:i + ln], i + ln


def _decode_oid(body):
    first = body[0]
    out = [str(first // 40), str(first % 40)]
    val = 0
    for b in body[1:]:
        val = (val << 7) | (b & 0x7F)
        if not (b & 0x80):
            out.append(str(val))
            val = 0
    return ".".join(out)


# ifSpeed (bits/s) advertised per device class in the IF-MIB.
IFSPEED = {
    "networking": 1000000000, "industrial_networking": 1000000000,
    "nvr": 1000000000, "iot_gateway": 1000000000,
}


def _oid_key(oid):
    return tuple(int(x) for x in oid.split("."))


class SnmpAgent:
    """Serves a walkable slice of the SNMP MIB for a device: the system group
    (1.3.6.1.2.1.1), an IF-MIB interface row (1.3.6.1.2.1.2 -- notably
    ifPhysAddress, which surfaces the real vendor OUI over SNMP too), and, for
    printers, the Printer-MIB marker-supplies (toner) group (1.3.6.1.2.1.43).
    GET returns an exact OID; GETNEXT walks the whole set in numeric order, so a
    full snmpwalk returns everything an asset-discovery engine fingerprints on."""

    def __init__(self, dev):
        self.dev = dev
        s = dev.profile.get("snmp", {})
        pen = s.get("pen", 0)
        sysoid = "1.3.6.1.4.1.%d" % pen if pen else "0.0"
        cat = dev.profile["category"]
        seed = int(dev.serial, 16)
        vals = {
            # -- system group --
            "1.3.6.1.2.1.1.1.0": ("str", s.get("descr", dev.profile["label"])),
            "1.3.6.1.2.1.1.2.0": ("oid", sysoid),
            "1.3.6.1.2.1.1.3.0": ("ticks", None),          # sysUpTime (dynamic)
            "1.3.6.1.2.1.1.4.0": ("str", "noc@lab"),
            "1.3.6.1.2.1.1.5.0": ("str", dev.hostname),    # sysName
            "1.3.6.1.2.1.1.6.0": ("str", "iotad-lab"),
            "1.3.6.1.2.1.1.7.0": ("int", 72),
            # -- IF-MIB: one ethernet interface, index 1 --
            "1.3.6.1.2.1.2.1.0": ("int", 1),               # ifNumber
            "1.3.6.1.2.1.2.2.1.1.1": ("int", 1),           # ifIndex
            "1.3.6.1.2.1.2.2.1.2.1": ("str", "GigabitEthernet0/1"
                                      if cat == "networking" else "eth0"),  # ifDescr
            "1.3.6.1.2.1.2.2.1.3.1": ("int", 6),           # ifType ethernetCsmacd
            "1.3.6.1.2.1.2.2.1.4.1": ("int", 1500),        # ifMtu
            "1.3.6.1.2.1.2.2.1.5.1": ("gauge", IFSPEED.get(cat, 100000000)),  # ifSpeed
            "1.3.6.1.2.1.2.2.1.6.1": ("bytes", dev.mac_bytes),   # ifPhysAddress
            "1.3.6.1.2.1.2.2.1.7.1": ("int", 1),           # ifAdminStatus up
            "1.3.6.1.2.1.2.2.1.8.1": ("int", 1),           # ifOperStatus up
            "1.3.6.1.2.1.2.2.1.10.1": ("counter", (seed * 7) & 0xFFFFFFFF),   # ifInOctets
            "1.3.6.1.2.1.2.2.1.16.1": ("counter", (seed * 13) & 0xFFFFFFFF),  # ifOutOctets
        }
        if cat == "printer":
            level = 5 + (seed % 90)                        # 5..94 %
            vals.update({
                # prtGeneralPrinterName
                "1.3.6.1.2.1.43.5.1.1.16.1": ("str", dev.hostname),
                # marker supplies (toner cartridge), unit 1
                "1.3.6.1.2.1.43.11.1.1.6.1.1": ("str", "Black Toner Cartridge"),
                "1.3.6.1.2.1.43.11.1.1.8.1.1": ("int", 100),   # MaxCapacity
                "1.3.6.1.2.1.43.11.1.1.9.1.1": ("int", level),  # current Level
            })
        self.values = vals
        self.order = sorted(vals, key=_oid_key)            # numeric walk order

    def _val(self, oid):
        kind, v = self.values[oid]
        if kind == "str":
            return _tlv(0x04, v.encode())
        if kind == "bytes":
            return _tlv(0x04, v)
        if kind == "oid":
            return _enc_oid(v)
        if kind == "int":
            return _enc_int(v)
        if kind == "counter":
            return _tlv(0x41, _enc_uint(v))
        if kind == "gauge":
            return _tlv(0x42, _enc_uint(v))
        if kind == "ticks":
            ticks = int(time.monotonic() * 100) & 0x7FFFFFFF
            return _tlv(0x43, ticks.to_bytes(4, "big"))
        return _tlv(0x05, b"")

    def respond(self, req):
        """Take a request SNMP message, return the response bytes (or None)."""
        try:
            _, msg, _ = _read_tlv(req, 0)                  # outer SEQUENCE
            tag, ver, i = _read_tlv(msg, 0)                # version
            tag, comm, i = _read_tlv(msg, i)               # community
            pdu_tag, pdu, _ = _read_tlv(msg, i)            # PDU
        except Exception:
            return None
        if pdu_tag not in (0xA0, 0xA1):                    # GET / GETNEXT
            return None
        getnext = pdu_tag == 0xA1
        try:
            _, reqid, j = _read_tlv(pdu, 0)
            _, _errs, j = _read_tlv(pdu, j)
            _, _erri, j = _read_tlv(pdu, j)
            _, vbl, _ = _read_tlv(pdu, j)
            _, vb, _ = _read_tlv(vbl, 0)
            _, oidbody, _ = _read_tlv(vb, 0)
            oid = _decode_oid(oidbody)
        except Exception:
            return None

        if getnext:
            k = _oid_key(oid)
            nxt = next((o for o in self.order if _oid_key(o) > k), None)
            if nxt is None:
                return None
            oid_out, val = nxt, self._val(nxt)
        else:
            if oid not in self.values:
                return None
            oid_out, val = oid, self._val(oid)

        varbind = _tlv(0x30, _enc_oid(oid_out) + val)
        vblist = _tlv(0x30, varbind)
        resp_pdu = _tlv(0xA2, _tlv(0x02, reqid) + _enc_int(0) +
                        _enc_int(0) + vblist)
        msg_out = _tlv(0x30, _tlv(0x02, ver) + _tlv(0x04, comm) + resp_pdu)
        return msg_out


# ---- liveness + service responder ------------------------------------------
class Responder:
    """Answers the active probes a discovery engine uses to CONFIRM and
    FINGERPRINT a device: ARP who-has, ICMP echo, TCP connects on the device's
    real service ports (SYN-ACK, plus an HTTP Server banner), and SNMP system
    group. Ports NOT in the device's profile get a RST (honest "closed"), so it
    behaves like the specific device type -- not a honeypot answering everything.
    """
    MAX_CONNS = 4096

    def __init__(self, cfg, roster, iface=None):
        self.cfg = cfg
        self.iface = iface or cfg.interface
        self.by_ip = {d.ip: d for d in roster}
        self.our_macs = {d.mac for d in roster}
        self.snmp = {d.ip: SnmpAgent(d) for d in roster if d.profile.get("snmp")}
        # EtherNet/IP List Identity + WS-Discovery answerers (application-layer
        # identity, so a discovery engine learns vendor/model, not just "port open")
        self.enip = {d.ip: d for d in roster if d.profile.get("cip")}
        self.ws = {d.ip: d for d in roster if d.profile.get("ws_discovery")}
        # mDNS query index: service-type -> devices, and <host>.local -> device
        self.mdns_svc, self.mdns_host = {}, {}
        for d in roster:
            for svc in d.profile.get("mdns", []) or []:
                self.mdns_svc.setdefault(f"{svc}.local".lower(), []).append(d)
                self.mdns_host[f"{d.hostname}.local".lower()] = d
        self.conns = {}
        self.sniffer = None
        self._sock = None
        self.arp_replies = self.icmp_replies = 0
        self.tcp_opens = self.tcp_banners = self.snmp_replies = 0
        self.enip_replies = self.ws_replies = self.mdns_replies = 0
        self.modbus_replies = 0

    def start(self):
        if self.cfg.dry_run:
            return
        self._sock = conf.L2socket(iface=self.iface)
        # Kernel-side filter: ARP, ICMP, the UDP discovery/identity protocols
        # (SNMP 161, mDNS 5353, WS-Discovery 3702, EtherNet/IP List Identity
        # 44818), and TCP control/data segments (SYN/FIN/RST/PSH -- skip the
        # bare-ACK stream we never generate).
        filt = ("arp or icmp or "
                "(udp port 161 or udp port 5353 or udp port 3702 or udp port 44818) or "
                "(tcp and tcp[13] & 0x0f != 0)")
        self.sniffer = AsyncSniffer(iface=self.iface, store=False,
                                    filter=filt, prn=self._handle)
        self.sniffer.start()
        log.info("responder[%s] listening (ARP/ICMP/TCP/SNMP/mDNS/WS-Disc/EtherNet-IP) "
                 "for %d device IPs", self.iface, len(self.by_ip))

    def _tx(self, dev, l3, dst_mac):
        self._sock.send(Ether(src=dev.mac, dst=dst_mac) / l3)

    def _handle(self, pkt):
        try:
            if not pkt.haslayer(Ether) or pkt[Ether].src in self.our_macs:
                return
            if pkt.haslayer(ARP) and pkt[ARP].op == 1:
                self._arp(pkt)
            elif pkt.haslayer(ICMP) and pkt[ICMP].type == 8:
                self._icmp(pkt)
            elif pkt.haslayer(TCP):
                self._tcp(pkt)
            elif pkt.haslayer(UDP) and pkt.haslayer(IP):
                dport = pkt[UDP].dport
                if dport == 161:
                    self._snmp(pkt)
                elif dport == 5353:
                    self._mdns(pkt)
                elif dport == 3702:
                    self._wsdisc(pkt)
                elif dport == 44818:
                    self._enip(pkt)
        except Exception as e:  # never let a malformed frame kill the thread
            log.debug("responder: %s", e)

    def _arp(self, pkt):
        a = pkt[ARP]
        if a.psrc == a.pdst:                       # gratuitous announce
            return
        dev = self.by_ip.get(a.pdst)
        if not dev:
            return
        self._tx(dev, ARP(op=2, hwsrc=dev.mac, psrc=dev.ip,
                          hwdst=a.hwsrc, pdst=a.psrc), pkt[Ether].src)
        self.arp_replies += 1

    def _icmp(self, pkt):
        dev = self.by_ip.get(pkt[IP].dst)
        if not dev:
            return
        ic = pkt[ICMP]
        data = bytes(ic.payload) if ic.payload else b""
        self._tx(dev, IP(src=dev.ip, dst=pkt[IP].src) /
                 ICMP(type=0, id=ic.id, seq=ic.seq) / Raw(data), pkt[Ether].src)
        self.icmp_replies += 1

    def _snmp(self, pkt):
        agent = self.snmp.get(pkt[IP].dst)
        if not agent:
            return
        resp = agent.respond(bytes(pkt[UDP].payload))
        if not resp:
            return
        self._tx(agent.dev, IP(src=agent.dev.ip, dst=pkt[IP].src) /
                 UDP(sport=161, dport=pkt[UDP].sport) / Raw(resp), pkt[Ether].src)
        self.snmp_replies += 1

    def _tcp(self, pkt):
        ip, t = pkt[IP], pkt[TCP]
        dev = self.by_ip.get(ip.dst)
        if not dev:
            return
        smac = pkt[Ether].src
        port = t.dport
        flags = int(t.flags)
        SYN, ACK, FIN, RST, PSH = 0x02, 0x10, 0x01, 0x04, 0x08
        if port not in dev.profile.get("ports", []):
            if flags & SYN and not flags & ACK:    # closed port -> honest RST
                self._tx(dev, IP(src=dev.ip, dst=ip.src) /
                         TCP(sport=port, dport=t.sport, flags="RA",
                             seq=0, ack=t.seq + 1), smac)
            return
        key = (ip.src, t.sport, port)
        if flags & SYN and not flags & ACK:        # open port -> SYN-ACK
            isn = random.randint(0, 0xFFFFFFFF)
            self.conns[key] = (isn, dev, port)
            if len(self.conns) > self.MAX_CONNS:
                self.conns.pop(next(iter(self.conns)))
            self._tx(dev, IP(src=dev.ip, dst=ip.src) /
                     TCP(sport=port, dport=t.sport, flags="SA",
                         seq=isn, ack=t.seq + 1, window=8192), smac)
            self.tcp_opens += 1
            return
        c = self.conns.get(key)
        if not c:
            return
        isn = c[0]
        payload = bytes(t.payload)
        if payload:                                # client request -> reply+close
            cli_next = t.seq + len(payload)
            seq = (isn + 1) & 0xFFFFFFFF
            reply = self._app_response(dev, port, payload)
            if reply:
                self._tx(dev, IP(src=dev.ip, dst=ip.src) /
                         TCP(sport=port, dport=t.sport, flags="PA",
                             seq=seq, ack=cli_next, window=8192) / Raw(reply), smac)
                seq = (seq + len(reply)) & 0xFFFFFFFF
            self._tx(dev, IP(src=dev.ip, dst=ip.src) /
                     TCP(sport=port, dport=t.sport, flags="FA",
                         seq=seq, ack=cli_next, window=8192), smac)
            self.conns.pop(key, None)
        elif flags & FIN:                          # client close
            self._tx(dev, IP(src=dev.ip, dst=ip.src) /
                     TCP(sport=port, dport=t.sport, flags="A",
                         seq=(isn + 1) & 0xFFFFFFFF, ack=t.seq + 1), smac)
            self.conns.pop(key, None)

    def _app_response(self, dev, port, payload):
        """Application-layer answer to a request on an open port. Returns bytes
        to send (then the connection is FIN'd), or b'' to just close."""
        if port in (80, 8080):
            r = self._http_response(dev, payload)
            if r:
                self.tcp_banners += 1
            return r
        if port == 502:                            # Modbus Read Device ID (43/14)
            r = self._modbus_id(dev, payload)
            if r:
                self.modbus_replies += 1
            return r
        return b""

    @staticmethod
    def _http_response(dev, payload):
        srv = dev.profile.get("http_server")
        if not srv or payload[:4] not in (b"GET ", b"POST", b"HEAD"):
            return b""
        # request path -> serve the UPnP device description if that's what was asked
        path = b""
        try:
            path = payload.split(b" ", 2)[1]
        except Exception:
            pass
        low = payload.lower()
        # UPnP device description is public (unauthenticated), like a real device.
        if b"description.xml" in path and "ssdp" in dev.profile.get("beacons", []):
            body = Responder._upnp_description(dev)
            return Responder._http_status(dev, b"200 OK", body,
                                          b"text/xml; charset=\"utf-8\"")
        # Embedded web UIs challenge for credentials -- the WWW-Authenticate realm
        # is a routinely-scanned fingerprint. Answer 401 unless the request
        # already carries an Authorization header (which a probe won't).
        realm = dev.profile.get("http_realm")
        if realm and b"\r\nauthorization:" not in low:
            return Responder._http_challenge(dev, realm)
        idy = dev.profile.get("identity", {})
        title = "%s %s" % (idy.get("vendor", ""), idy.get("product", dev.hostname))
        body = ("<html><head><title>%s</title></head><body></body></html>"
                % title.strip()).encode()
        return Responder._http_status(dev, b"200 OK", body, b"text/html")

    @staticmethod
    def _http_status(dev, status, body, ctype, extra=b""):
        srv = dev.profile.get("http_server", "lighttpd")
        return (b"HTTP/1.1 " + status + b"\r\nServer: " + srv.encode() +
                b"\r\nContent-Type: " + ctype +
                b"\r\nContent-Length: " + str(len(body)).encode() +
                extra + b"\r\nConnection: close\r\n\r\n" + body)

    @staticmethod
    def _http_challenge(dev, realm):
        scheme = dev.profile.get("http_auth", "Basic")
        r = realm.encode()
        if scheme == "Digest":
            # deterministic-ish nonce per device (real devices rotate it; a
            # fingerprinting scan only reads the realm + scheme, not the nonce).
            nonce = ("%08x%s" % (int(time.monotonic()) & 0xFFFFFFFF, dev.serial))
            auth = (b"Digest realm=\"" + r + b"\", qop=\"auth\", nonce=\"" +
                    nonce.encode() + b"\", algorithm=MD5")
        else:
            auth = b"Basic realm=\"" + r + b"\""
        body = b"<html><head><title>401 Unauthorized</title></head><body></body></html>"
        return Responder._http_status(dev, b"401 Unauthorized", body,
                                      b"text/html", b"\r\nWWW-Authenticate: " + auth)

    @staticmethod
    def _upnp_description(dev):
        idy = dev.profile["identity"]
        st = dev.profile.get("ssdp_st") or "urn:schemas-upnp-org:device:Basic:1"
        udn = "uuid:%s-%s" % (dev.profile["id"], dev.serial)   # matches SSDP USN
        return (
            '<?xml version="1.0"?>\r\n'
            '<root xmlns="urn:schemas-upnp-org:device-1-0">'
            '<specVersion><major>1</major><minor>0</minor></specVersion>'
            '<device>'
            '<deviceType>%s</deviceType>'
            '<friendlyName>%s</friendlyName>'
            '<manufacturer>%s</manufacturer>'
            '<modelName>%s</modelName>'
            '<modelNumber>%s</modelNumber>'
            '<serialNumber>%s</serialNumber>'
            '<UDN>%s</UDN>'
            '</device></root>'
            % (st, dev.hostname, idy["vendor"], idy["product"],
               idy["revision"], dev.serial, udn)
        ).encode()

    @staticmethod
    def _modbus_id(dev, payload):
        """Answer Modbus Read Device Identification (FC 0x2B / MEI 0x0E)."""
        m = dev.profile.get("modbus_id")
        if not m or len(payload) < 11:
            return b""
        # MBAP: transaction(2) protocol(2) length(2) unit(1); PDU: FC(1) MEI(1) ...
        tid, unit, fc, mei = payload[0:2], payload[6], payload[7], payload[8]
        if fc != 0x2B or mei != 0x0E:
            return b""
        read_code = payload[9]
        objs = [(0x00, m["vendor"].encode()[:80]),
                (0x01, m["product"].encode()[:80]),
                (0x02, m["revision"].encode()[:32])]
        pdu = bytes([0x2B, 0x0E, read_code, 0x01, 0x00, 0x00, len(objs)])
        for oid, val in objs:
            pdu += bytes([oid, len(val)]) + val
        mbap = tid + b"\x00\x00" + struct.pack(">H", len(pdu) + 1) + bytes([unit])
        return mbap + pdu

    # -- UDP identity responders --------------------------------------------
    def _enip(self, pkt):
        """EtherNet/IP List Identity (UDP 44818): reply with the CIP identity."""
        data = bytes(pkt[UDP].payload)
        if len(data) < 24:
            return
        cmd, length = struct.unpack_from("<HH", data, 0)
        if cmd != 0x0063 or length != 0:           # only answer REQUESTs (len 0)
            return
        sctx = data[12:20]
        dst = pkt[IP].dst
        if dst in self.enip:
            targets = [self.enip[dst]]
        else:                                      # broadcast -> every enip device
            targets = list(self.enip.values())
        for dev in targets:
            item = self._enip_identity(dev)
            body = (struct.pack("<HH", 0x0063, len(item)) + b"\x00" * 8 +
                    sctx + b"\x00" * 4 + item)
            self._sock.send(Ether(src=dev.mac, dst=pkt[Ether].src) /
                            IP(src=dev.ip, dst=pkt[IP].src) /
                            UDP(sport=44818, dport=pkt[UDP].sport) / Raw(body))
            self.enip_replies += 1

    @staticmethod
    def _enip_identity(dev):
        c = dev.profile["cip"]
        idy = dev.profile["identity"]
        name = idy["product"].encode()[:32]
        addr = bytes(int(o) for o in dev.ip.split("."))       # sin_addr (network)
        item = struct.pack("<H", 1)                            # encap proto version
        item += struct.pack(">hH", 2, 44818) + addr + b"\x00" * 8   # socket addr
        item += struct.pack("<HHH", c["vendor_id"], c["device_type"],
                            c["product_code"])
        item += bytes([c["rev_major"] & 0xFF, c["rev_minor"] & 0xFF])  # revision
        item += struct.pack("<H", 0)                           # status
        item += struct.pack("<I", int(dev.serial, 16))        # serial number
        item += bytes([len(name)]) + name                     # product name
        item += bytes([0x03])                                 # state = operational
        # List Identity item wrapper: type 0x000C, then the item bytes
        return struct.pack("<HHH", 1, 0x000C, len(item)) + item

    def _wsdisc(self, pkt):
        """WS-Discovery Probe (UDP 3702): ONVIF cameras answer ProbeMatches."""
        data = bytes(pkt[UDP].payload)
        if b"Probe" not in data:
            return
        m = re.search(rb"MessageID>\s*([^<\s]+)", data)
        relates = m.group(1).decode("ascii", "ignore") if m else "urn:uuid:0"
        for dev in self.ws.values():
            body = self._wsdisc_match(dev, relates)
            self._sock.send(Ether(src=dev.mac, dst=pkt[Ether].src) /
                            IP(src=dev.ip, dst=pkt[IP].src) /
                            UDP(sport=3702, dport=pkt[UDP].sport) / Raw(body))
            self.ws_replies += 1

    @staticmethod
    def _wsdisc_match(dev, relates):
        u = uuid.uuid5(uuid.NAMESPACE_DNS, dev.mac)
        typ = dev.profile["ws_discovery"]
        scopes = ("onvif://www.onvif.org/type/video_encoder "
                  "onvif://www.onvif.org/name/%s "
                  "onvif://www.onvif.org/hardware/%s "
                  "onvif://www.onvif.org/location/lab"
                  % (dev.hostname, dev.profile["id"]))
        return (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"'
            ' xmlns:a="http://www.w3.org/2005/08/addressing"'
            ' xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery"'
            ' xmlns:dn="http://www.onvif.org/ver10/network/wsdl">'
            '<s:Header>'
            '<a:MessageID>urn:uuid:%s</a:MessageID>'
            '<a:RelatesTo>%s</a:RelatesTo>'
            '<a:To>http://www.w3.org/2005/08/addressing/anonymous</a:To>'
            '<a:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/ProbeMatches</a:Action>'
            '</s:Header><s:Body><d:ProbeMatches><d:ProbeMatch>'
            '<a:EndpointReference><a:Address>urn:uuid:%s</a:Address></a:EndpointReference>'
            '<d:Types>dn:%s</d:Types>'
            '<d:Scopes>%s</d:Scopes>'
            '<d:XAddrs>http://%s/onvif/device_service</d:XAddrs>'
            '<d:MetadataVersion>1</d:MetadataVersion>'
            '</d:ProbeMatch></d:ProbeMatches></s:Body></s:Envelope>'
            % (u, relates, u, typ, scopes, dev.ip)
        ).encode()

    def _mdns(self, pkt):
        """mDNS query (UDP 5353): answer for names this responder's devices own."""
        dns = pkt[DNS]
        if dns.qr != 0 or not dns.qd:              # only answer questions
            return
        q = dns.qd
        name = (q.qname.decode("ascii", "ignore") if isinstance(q.qname, bytes)
                else str(q.qname)).rstrip(".").lower()
        if name == "_services._dns-sd._udp.local":  # service enumeration
            for svc in list(self.mdns_svc)[:20]:
                d = self.mdns_svc[svc][0]
                self._send_mdns(d, [DNSRR(rrname="_services._dns-sd._udp.local",
                                          type="PTR", ttl=4500, rdata=svc)])
            return
        if name in self.mdns_svc:                   # service-type query
            for d in self.mdns_svc[name][:10]:
                self._send_mdns(d, self._mdns_records(d, name))
        elif name in self.mdns_host:                # hostname A query
            d = self.mdns_host[name]
            self._send_mdns(d, [DNSRR(rrname="%s.local" % d.hostname,
                                      type="A", ttl=120, rdata=d.ip)])

    @staticmethod
    def _mdns_records(dev, svc):
        inst = "%s.%s" % (dev.hostname, svc)        # svc already ends in .local
        port = SERVICE_PORTS.get(svc[:-6], 80)      # strip ".local" for the lookup
        idy = dev.profile["identity"]
        txt = [b"model=" + idy["product"].encode(),
               b"vendor=" + idy["vendor"].encode(),
               b"fw=" + idy["revision"].encode()]
        # scapy wants the answer set as a LIST of records, not a '/'-chain.
        return [DNSRR(rrname=svc, type="PTR", ttl=120, rdata=inst),
                DNSRRSRV(rrname=inst, ttl=120, priority=0, weight=0,
                         port=port, target="%s.local" % dev.hostname),
                DNSRR(rrname=inst, type="TXT", ttl=120, rdata=txt),
                DNSRR(rrname="%s.local" % dev.hostname, type="A",
                      ttl=120, rdata=dev.ip)]

    def _send_mdns(self, dev, an):
        dns = DNS(qr=1, aa=1, qd=None, an=an)
        self._sock.send(Ether(src=dev.mac, dst=MDNS_MCAST_MAC) /
                        IP(src=dev.ip, dst="224.0.0.251", ttl=255) /
                        UDP(sport=5353, dport=5353) / dns)
        self.mdns_replies += 1

    def stop(self):
        if self.sniffer:
            try:
                self.sniffer.stop()
            except Exception:
                pass
        if self._sock:
            self._sock.close()
        log.info("responder[%s] answered %d ARP, %d ICMP, %d TCP(open), "
                 "%d HTTP, %d SNMP, %d Modbus-ID, %d EtherNet/IP, %d WS-Disc, "
                 "%d mDNS", self.iface, self.arp_replies, self.icmp_replies,
                 self.tcp_opens, self.tcp_banners, self.snmp_replies,
                 self.modbus_replies, self.enip_replies, self.ws_replies,
                 self.mdns_replies)


# ---- scheduler -------------------------------------------------------------
class Scheduler:
    def __init__(self, cfg, roster, emitters, tx):
        self.cfg, self.roster, self.em, self.tx = cfg, roster, emitters, tx
        self.heap = []
        self.seq = 0
        self.running = True

    @staticmethod
    def _diurnal():
        """Traffic is heavier in business hours and quieter overnight -- stretch
        the interval between beacons the later/earlier it gets. Uses local wall
        clock (the daemon runs on the host, not the UTC container)."""
        h = time.localtime().tm_hour
        if 7 <= h < 19:
            return 1.0          # workday: full cadence
        if 6 <= h < 7 or 19 <= h < 23:
            return 1.5          # shoulder hours
        return 2.2              # 23:00-06:00: quietest

    def _interval(self, beacon):
        key, default = BEACON_INTERVAL[beacon]
        if key == "checkin":
            lo = self.cfg.timing.getint("checkin_min")
            hi = self.cfg.timing.getint("checkin_max")
            base = random.randint(lo, hi)
        else:
            base = self.cfg.timing.getint(key, fallback=default)
        return base * random.uniform(0.75, 1.25) * self._diurnal()  # jitter + diurnal

    def _schedule(self, when, dev, beacon):
        heappush(self.heap, (when, self.seq, dev, beacon))
        self.seq += 1

    def prime(self, now, spread=True):
        for dev in self.roster:
            for beacon in dev.profile["beacons"]:
                if beacon not in BEACON_INTERVAL:
                    continue
                if beacon in WAN_BEACONS and not self.em._wan_ok():
                    continue
                offset = random.uniform(0, 5 if not spread else min(30, self._interval(beacon)))
                self._schedule(now + offset, dev, beacon)

    def emit(self, dev, beacon):
        fn = getattr(self.em, beacon, None)
        if fn is None:
            return
        try:
            pkt = fn(dev)
        except Exception as e:
            log.warning("emit %s/%s build error: %s", dev.hostname, beacon, e)
            return
        if pkt is None:
            return
        for p in (pkt if isinstance(pkt, list) else [pkt]):
            self.tx.send(beacon, p, dev.site.interface)

    def run_once(self):
        """Emit exactly one of every applicable beacon per device (testing)."""
        for dev in self.roster:
            for beacon in dev.profile["beacons"]:
                if beacon in WAN_BEACONS and not self.em._wan_ok():
                    continue
                self.emit(dev, beacon)

    def run(self):
        now = time.monotonic()
        self.prime(now)
        log.info("scheduled %d beacon timers across %d devices",
                 len(self.heap), len(self.roster))
        while self.running:
            if not self.heap:
                time.sleep(0.5)
                continue
            when, _, dev, beacon = self.heap[0]
            now = time.monotonic()
            if when > now:
                time.sleep(min(when - now, 1.0))
                continue
            heappop(self.heap)
            self.emit(dev, beacon)
            self._schedule(now + self._interval(beacon), dev, beacon)

    def stop(self, *_):
        self.running = False


# ---- roster reporting ------------------------------------------------------
def print_roster(roster):
    by_cat = {}
    by_site = {}
    for d in roster:
        by_cat[d.profile["category"]] = by_cat.get(d.profile["category"], 0) + 1
        by_site[d.site.name] = by_site.get(d.site.name, 0) + 1
    multi = len(by_site) > 1
    print(f"{'HOSTNAME':<18} {'IP':<15} {'MAC':<17} {'VENDOR':<26} "
          f"{'CATEGORY':<16} {'SITE' if multi else ''}")
    print("-" * (92 + (8 if multi else 0)))
    for d in sorted(roster, key=lambda x: (x.site.name, x.profile["category"], x.ip)):
        site = d.site.name if multi else ""
        print(f"{d.hostname:<18} {d.ip:<15} {d.mac:<17} {d.profile['label']:<26} "
              f"{d.profile['category']:<16} {site}")
    print("-" * (92 + (8 if multi else 0)))
    print(f"{len(roster)} devices across {len(by_cat)} categories: " +
          ", ".join(f"{k}={v}" for k, v in sorted(by_cat.items())))
    if multi:
        print("sites: " + ", ".join(f"{k}={v}" for k, v in sorted(by_site.items())))


# ---- main ------------------------------------------------------------------
def load_catalog():
    import json
    path = os.path.join(HERE, "catalog.json")
    if not os.path.exists(path):
        sys.exit(f"iotad: {path} missing; run ./build_catalog.py first")
    with open(path) as f:
        return json.load(f)


def setup_logging(cfg, verbose):
    handlers = [logging.StreamHandler(sys.stdout)]
    if cfg.logfile:
        handlers.append(logging.FileHandler(cfg.logfile))
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s iotad %(levelname)s %(message)s",
        handlers=handlers)


def main():
    ap = argparse.ArgumentParser(description="IoT/OT traffic simulation daemon")
    ap.add_argument("-c", "--config", default="/etc/iotad.conf")
    ap.add_argument("--list", action="store_true", help="print roster and exit")
    ap.add_argument("--once", action="store_true", help="emit one pass then exit")
    ap.add_argument("--dry-run", action="store_true", help="never transmit; log frames")
    ap.add_argument("--duration", type=int, default=0, help="run N seconds then exit")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    if not os.path.exists(args.config) and args.config == "/etc/iotad.conf":
        local = os.path.join(HERE, "iotad.conf")
        if os.path.exists(local):
            args.config = local

    cfg = Config(args.config)
    if args.dry_run:
        cfg.dry_run = True
    setup_logging(cfg, args.verbose)

    catalog = load_catalog()
    roster = build_roster(catalog, cfg)

    if args.list:
        print_roster(roster)
        return

    if not cfg.dry_run and os.geteuid() != 0:
        sys.exit("iotad: raw-socket transmit needs root (or --dry-run)")

    sites_desc = ", ".join(f"{s.name}={s.interface}:{s.subnet}" for s in cfg.sites)
    log.info("config=%s sites=[%s] devices=%d dry_run=%s scope=%s",
             args.config, sites_desc, len(roster), cfg.dry_run, cfg.outbound_scope)

    tx = Tx(cfg)
    emitters = Emitters(cfg, tx, roster)
    sched = Scheduler(cfg, roster, emitters, tx)
    # One responder per interface, each owning only that interface's devices.
    responders = []
    for iface in {s.interface for s in cfg.sites}:
        subset = [d for d in roster if d.site.interface == iface]
        responders.append(Responder(cfg, subset, iface=iface))

    if args.once:
        sched.run_once()
        log.info("run-once complete: %d frames (%s)", tx.sent, dict(tx.by_beacon))
        tx.close()
        return

    signal.signal(signal.SIGINT, sched.stop)
    signal.signal(signal.SIGTERM, sched.stop)
    if cfg.pidfile and not cfg.dry_run:
        try:
            with open(cfg.pidfile, "w") as f:
                f.write(str(os.getpid()))
        except OSError as e:
            log.warning("pidfile: %s", e)

    if args.duration:
        def _timeout():
            time.sleep(args.duration)
            sched.stop()
        import threading
        threading.Thread(target=_timeout, daemon=True).start()

    for r in responders:
        r.start()
    try:
        sched.run()
    finally:
        for r in responders:
            r.stop()
        tx.close()
        if cfg.pidfile and os.path.exists(cfg.pidfile):
            try:
                os.remove(cfg.pidfile)
            except OSError:
                pass
        log.info("stopped after %d frames sent %s", tx.sent, dict(tx.by_beacon))


if __name__ == "__main__":
    main()
