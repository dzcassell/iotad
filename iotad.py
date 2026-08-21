#!/usr/bin/env python3
"""iotad -- IoT/OT traffic simulation daemon.

Populates a lab network with believable IoT/OT assets for testing network
asset-discovery (built for Cato Networks demo/lab enrichment). It instantiates
a deterministic roster of virtual devices -- each with a REAL vendor OUI from
the IEEE registry (see build_catalog.py) -- and emits the L2/L3 traffic those
devices would emit: gratuitous ARP, DHCP with vendor fingerprints, mDNS, SSDP,
LLDP/CDP, OT discovery/poll protocols (BACnet, EtherNet/IP, PROFINET-DCP,
Modbus, S7), and outbound DNS/NTP/TLS check-ins.

It does not assign simulated IPs to the host, but it does answer authorized
active discovery probes and emits complete synthetic protocol exchanges. Every
frame carries a spoofed source MAC/IP, so run it ONLY on a lab segment you own
and are authorized to test. See README.md.

    iotad.py --config /etc/iotad.conf        # run (foreground; systemd manages it)
    iotad.py --list                          # print the device roster and exit
    iotad.py --once                          # emit one pass of every beacon, then exit
    iotad.py --dry-run                        # build + schedule, print, never transmit
"""
import argparse
import base64
import configparser
import ipaddress
import json
import logging
import os
import random
import re
import signal
import socket
import struct
import sys
import threading
import time
import uuid
import zlib
from heapq import heappush, heappop

HERE = os.path.dirname(os.path.abspath(__file__))
log = logging.getLogger("iotad")

# scapy is noisy on import; quiet it before loading.
logging.getLogger("scapy").setLevel(logging.ERROR)
try:
    from scapy.all import (
        Ether, ARP, IP, ICMP, UDP, TCP, BOOTP, DHCP, DNS, DNSQR, DNSRR, DNSRRSRV,
        NTP, LLC, SNAP, Raw, Dot1Q, conf, checksum, AsyncSniffer, srp1,
        get_if_addr, get_if_hwaddr, PcapWriter, rdpcap,
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
    "hartip": ("poll_interval", 90),
    "cip_safety": ("poll_interval", 90),
    "dicom": ("poll_interval", 90),
    "hl7": ("poll_interval", 90),
    "mqtt": ("poll_interval", 90),
    "coap": ("poll_interval", 90),
    "knx": ("discovery_interval", 120),
    "iec61850": ("poll_interval", 90),
    "mtconnect": ("poll_interval", 90),
    "scenario_event": ("event_interval", 600),
    "fins": ("discovery_interval", 120),
    "ntp": ("ntp_interval", 900),
    "dns_checkin": ("checkin", 0),
    "tls_checkin": ("checkin", 0),
}
WAN_BEACONS = {"tls_checkin"}  # only run these when outbound scope includes WAN
SUSPICIOUS_BEACON = "suspicious_beacon"
BEHAVIOR_INDICATIONS = {
    "long_dns": ["chaser_long_dns_queries"],
    "nxdomain_dns": ["hunt_dns_response_code"],
    "local_domain_dns": ["outbound_local_domain_dns_queries"],
    "dyndns_dns": ["hunt_dyndns_traffic", "hunt_DynamicDNS_dns_traffic"],
    "ftp_transfer": ["ftp_client_first_time_site_wan", "ftp_events_anomaly_site"],
    "smb_transfer": ["lan_file_transfer_protocols_first_seen",
                     "lan_file_transfer_protocols_activity"],
    "ssh_low_popularity": ["suspicious_protocol_communication"],
    "ssh_nonstandard": ["nonstandard_ports_first_seen_site",
                        "hunt_abnormal_protocol_use"],
}

FACILITY_CATEGORIES = {
    "industrial": {"plc", "rtu", "hmi", "industrial_networking", "drive",
                   "robotics", "safety", "instrumentation", "power"},
    "manufacturing": {"plc", "hmi", "industrial_networking", "drive",
                      "robotics", "safety", "instrumentation", "printer"},
    "cleanroom": {"cleanroom", "environmental", "hvac", "building_automation",
                  "instrumentation", "power", "access_control"},
    "medical": {"medical", "environmental", "hvac", "building_automation",
                "power", "access_control", "printer", "voip"},
    "water": {"water_treatment", "instrumentation", "plc", "drive", "rtu",
              "environmental", "power"},
    "building": {"hvac", "building_automation", "lighting", "access_control",
                 "intercom", "power", "environmental", "networking"},
}
FACILITY_WEIGHTS = {
    "pharma_cleanroom": {"cleanroom": 12, "environmental": 8, "hvac": 7,
                          "building_automation": 6, "instrumentation": 5,
                          "water_treatment": 4, "plc": 3, "drive": 2,
                          "power": 2, "access_control": 2, "networking": 1},
    "hospital": {"medical": 12, "building_automation": 5, "hvac": 5,
                 "environmental": 4, "power": 3, "access_control": 3,
                 "printer": 3, "voip": 3, "networking": 2},
    "automotive": {"robotics": 10, "plc": 9, "safety": 7, "drive": 6,
                   "hmi": 4, "industrial_networking": 4,
                   "instrumentation": 3, "printer": 1, "power": 1},
    "water_treatment": {"water_treatment": 10, "instrumentation": 8,
                        "plc": 6, "drive": 6, "rtu": 4,
                        "environmental": 3, "power": 2,
                        "industrial_networking": 2},
}
# Preserve the original concise preset names as weighted aliases.
for _name, _cats in list(FACILITY_CATEGORIES.items()):
    FACILITY_WEIGHTS[_name] = {category: 1 for category in _cats}
SCENARIO_CADENCE = {
    "baseline": 1.0,
    "commissioning": 0.45,
    "production": 0.8,
    "maintenance": 0.6,
    "incident": 0.3,
}


# ---- configuration ---------------------------------------------------------
class Site:
    """One physical segment / interface, typically fronted by its own Cato
    Socket. Devices belong to a site; cross-site flows route via the site's
    gateway (Socket) so they traverse the WAN."""

    def __init__(self, name, interface, subnet, gateway, ip_start, ip_end,
                 vlan=0, zone=None):
        self.name = name
        self.interface = interface
        self.subnet = ipaddress.ip_network(subnet, strict=False)
        self.gateway = gateway
        self.ip_start = ipaddress.ip_address(ip_start)
        self.ip_end = ipaddress.ip_address(ip_end)
        self.vlan = int(vlan or 0)
        self.zone = zone or name
        self.gw_mac = None                 # resolved at runtime
        self.dns_server = None
        self.mac_cache = {}

    def pool(self):
        return [ipaddress.ip_address(a)
                for a in range(int(self.ip_start), int(self.ip_end) + 1)]

    def broadcast(self):
        return str(self.subnet.broadcast_address)


class Config:
    def __init__(self, path):
        cp = configparser.ConfigParser(inline_comment_prefixes=("#", ";"))
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
                    s.get("gateway"), s.get("ip_pool_start"), s.get("ip_pool_end"),
                    s.getint("vlan", fallback=0), s.get("zone", fallback=None)))
        else:
            n = cp["network"]
            self.sites.append(Site(
                "site1", n.get("interface"), n.get("subnet"), n.get("gateway"),
                n.get("ip_pool_start"), n.get("ip_pool_end"),
                n.getint("vlan", fallback=0), n.get("zone", fallback="site1")))
        # First site's interface is the default for anything single-homed.
        self.interface = self.sites[0].interface

        s = cp["simulation"]
        self.device_count = s.getint("device_count")
        self.seed = s.getint("seed")
        self.facility = s.get("facility", "mixed").strip().lower()
        self.scenario = s.get("scenario", "baseline").strip().lower()
        self.events_enabled = s.getboolean("events_enabled", fallback=True)
        cats = s.get("categories", "").strip()
        self.categories = [c.strip() for c in cats.split(",") if c.strip()]
        # Fraction of OT polls aimed at a peer on ANOTHER site (WAN traffic).
        self.cross_site_ratio = s.getfloat("cross_site_ratio", fallback=0.6)

        o = cp["outbound"]
        self.outbound_enabled = o.getboolean("enabled")
        self.outbound_scope = o.get("scope").strip().lower()  # subnet|wan|both
        self.dns_server = o.get("dns_server")
        self.ntp_server = o.get("ntp_server")
        for site in self.sites:
            sec = f"site:{site.name}" if f"site:{site.name}" in cp else "network"
            site.dns_server = cp[sec].get("dns_server", fallback=self.dns_server)

        x = cp["suspicious"]
        self.suspicious_enabled = x.getboolean("enabled")
        self.suspicious_device_fraction = x.getfloat("device_fraction")
        self.suspicious_interval = x.getint("interval")
        self.suspicious_max_pps = x.getfloat("max_pps")
        self.suspicious_countries = [
            c.strip().lower() for c in x.get("countries").split(",") if c.strip()
        ]
        self.suspicious_behaviors = [
            b.strip().lower() for b in x.get("behaviors").split(",") if b.strip()
        ]
        self.suspicious_targets = {
            country: [a.strip() for a in x.get(f"{country}_targets").split(",")
                      if a.strip()]
            for country in ("china", "iran", "russia")
        }
        self.suspicious_ports = [
            int(p.strip()) for p in x.get("beacon_ports").split(",") if p.strip()
        ]

        self.timing = cp["timing"]
        r = cp["runtime"]
        self.pidfile = r.get("pidfile")
        self.logfile = r.get("logfile")
        self.dry_run = r.getboolean("dry_run")
        self.rate_limit = r.getint("max_pps")
        self.metrics_file = r.get("metrics_file", "/run/iotad/metrics.json")
        self.metrics_interval = r.getint("metrics_interval", fallback=30)
        self._validate()

    def _validate(self):
        if self.device_count <= 0:
            raise ValueError("simulation.device_count must be greater than zero")
        if self.facility != "mixed" and self.facility not in FACILITY_WEIGHTS:
            choices = ", ".join(["mixed"] + sorted(FACILITY_WEIGHTS))
            raise ValueError(f"simulation.facility must be one of: {choices}")
        if self.scenario not in SCENARIO_CADENCE:
            raise ValueError("simulation.scenario must be one of: " +
                             ", ".join(sorted(SCENARIO_CADENCE)))
        if not 0.0 <= self.cross_site_ratio <= 1.0:
            raise ValueError("simulation.cross_site_ratio must be between 0 and 1")
        if self.outbound_scope not in ("subnet", "wan", "both"):
            raise ValueError("outbound.scope must be subnet, wan, or both")
        if self.rate_limit <= 0:
            raise ValueError("runtime.max_pps must be greater than zero")
        if not 0.0 <= self.suspicious_device_fraction <= 1.0:
            raise ValueError("suspicious.device_fraction must be between 0 and 1")
        if self.suspicious_interval <= 0 or self.suspicious_max_pps <= 0:
            raise ValueError("suspicious.interval and suspicious.max_pps must be positive")
        supported_countries = {"china", "iran", "russia"}
        supported_behaviors = {
            "geo_dns", "dga_dns", "dns_tunnel", "port_beacon",
            *BEHAVIOR_INDICATIONS,
        }
        if not self.suspicious_countries or not set(self.suspicious_countries) <= supported_countries:
            raise ValueError("suspicious.countries must contain china, iran, and/or russia")
        if not self.suspicious_behaviors or not set(self.suspicious_behaviors) <= supported_behaviors:
            raise ValueError("suspicious.behaviors contains an unsupported behavior")
        if not self.suspicious_ports or any(not 1 <= p <= 65535 for p in self.suspicious_ports):
            raise ValueError("suspicious.beacon_ports must be in 1..65535")
        for country in self.suspicious_countries:
            if not self.suspicious_targets[country]:
                raise ValueError(f"suspicious.{country}_targets cannot be empty")
            for address in self.suspicious_targets[country]:
                if ipaddress.ip_address(address).version != 4:
                    raise ValueError("suspicious targets must be IPv4 addresses")
        names = set()
        for site in self.sites:
            if not site.name or site.name in names:
                raise ValueError(f"site names must be non-empty and unique: {site.name!r}")
            names.add(site.name)
            gateway = ipaddress.ip_address(site.gateway)
            if site.ip_start.version != site.subnet.version or site.ip_end.version != site.subnet.version:
                raise ValueError(f"site '{site.name}' address family does not match its subnet")
            if site.ip_start > site.ip_end:
                raise ValueError(f"site '{site.name}' ip_pool_start exceeds ip_pool_end")
            if site.ip_start not in site.subnet or site.ip_end not in site.subnet:
                raise ValueError(f"site '{site.name}' IP pool must be inside {site.subnet}")
            if gateway not in site.subnet:
                raise ValueError(f"site '{site.name}' gateway must be inside {site.subnet}")
            if site.vlan not in range(0, 4095):
                raise ValueError(f"site '{site.name}' vlan must be 0 or 1..4094")
            if site.ip_start in (site.subnet.network_address, site.subnet.broadcast_address) or \
                    site.ip_end in (site.subnet.network_address, site.subnet.broadcast_address):
                raise ValueError(f"site '{site.name}' IP pool cannot include network/broadcast addresses")
        lo = self.timing.getint("checkin_min")
        hi = self.timing.getint("checkin_max")
        if lo <= 0 or hi < lo:
            raise ValueError("timing checkin_min/checkin_max range is invalid")
        if self.metrics_interval <= 0:
            raise ValueError("runtime.metrics_interval must be greater than zero")

    @staticmethod
    def defaults():
        return {
            "network": {
                "interface": "enp10s0", "subnet": "192.168.40.0/24",
                "gateway": "192.168.40.1",
                "ip_pool_start": "192.168.40.50", "ip_pool_end": "192.168.40.229",
            },
            "simulation": {"device_count": "80", "seed": "1337", "facility": "mixed",
                           "scenario": "baseline", "categories": ""},
            "timing": {
                "arp_interval": "300", "dhcp_interval": "1800", "mdns_interval": "120",
                "ssdp_interval": "180", "lldp_interval": "30", "cdp_interval": "60",
                "discovery_interval": "120", "poll_interval": "90",
                "ntp_interval": "900",
                "checkin_min": "180", "checkin_max": "900",
                "event_interval": "600",
            },
            "outbound": {
                "enabled": "true", "scope": "both",
                "dns_server": "192.168.40.1", "ntp_server": "pool.ntp.org",
            },
            "suspicious": {
                "enabled": "true", "device_fraction": "0.10", "interval": "300",
                "max_pps": "2", "countries": "china, iran, russia",
                "behaviors": ("geo_dns, dga_dns, dns_tunnel, port_beacon, long_dns, "
                              "nxdomain_dns, local_domain_dns, dyndns_dns, ftp_transfer, "
                              "smb_transfer, ssh_low_popularity, ssh_nonstandard"),
                "china_targets": "223.5.5.5, 223.6.6.6",
                "iran_targets": "178.22.122.100, 185.51.200.2",
                "russia_targets": "77.88.8.8, 77.88.8.1",
                "beacon_ports": "4444, 8081, 8443",
            },
            "runtime": {
                "pidfile": "/run/iotad.pid", "logfile": "",
                "dry_run": "false", "max_pps": "50",
                "metrics_file": "/run/iotad/metrics.json", "metrics_interval": "30",
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


class WireFrame:
    """A crafted frame plus the physical interface it must leave on."""
    __slots__ = ("pkt", "iface")

    def __init__(self, pkt, iface):
        self.pkt, self.iface = pkt, iface


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
    elif cfg.facility != "mixed":
        allowed = set(FACILITY_WEIGHTS[cfg.facility])
        profiles = [p for p in profiles if p["category"] in allowed]
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
    profile_plan = None
    if not cfg.categories and cfg.facility == "mixed" and cfg.device_count >= len(profiles):
        # Guarantee broad protocol coverage in larger mixed labs instead of
        # relying on random sampling to happen to include every archetype.
        profile_plan = list(profiles)
        rng.shuffle(profile_plan)
        profile_plan.extend(rng.choice(profiles)
                            for _ in range(cfg.device_count - len(profile_plan)))
    # Interleave sites so the roster (and cross-site pairing) is well mixed.
    for slot in range(max(counts)):
        for si, site in enumerate(cfg.sites):
            if slot >= counts[si]:
                continue
            if profile_plan is not None:
                p = profile_plan[idx]
            elif cfg.categories or cfg.facility == "mixed":
                p = rng.choice(profiles)
            else:
                weights = [FACILITY_WEIGHTS[cfg.facility][p["category"]]
                           for p in profiles]
                p = rng.choices(profiles, weights=weights, k=1)[0]
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
        self._rate_lock = threading.Lock()
        self._tokens = float(cfg.rate_limit)
        self._token_time = time.monotonic()
        self._pcap = PcapWriter(cfg.pcap_path, append=False, sync=True) \
            if getattr(cfg, "pcap_path", None) else None
        self.failures = 0
        self.throttle_waits = 0
        self._vlan_by_iface = {}
        for site in cfg.sites:
            prior = self._vlan_by_iface.get(site.interface, site.vlan)
            if prior != site.vlan:
                raise ValueError("sites sharing an interface must use the same VLAN")
            self._vlan_by_iface[site.interface] = site.vlan
        if not cfg.dry_run:
            conf.iface = cfg.interface
            conf.verb = 0
            for site in cfg.sites:
                if site.interface not in self._socks:
                    self._socks[site.interface] = conf.L2socket(iface=site.interface)

    def send(self, beacon, pkt, iface=None):
        with self._rate_lock:
            self.by_beacon[beacon] = self.by_beacon.get(beacon, 0) + 1
            self.sent += 1
        iface = iface or self.cfg.interface
        vlan = self._vlan_by_iface.get(iface, 0)
        if vlan and pkt.haslayer(Ether) and not pkt.haslayer(Dot1Q):
            eth = pkt[Ether]
            pkt = (Ether(src=eth.src, dst=eth.dst, type=0x8100) /
                   Dot1Q(vlan=vlan, type=eth.type) / eth.payload)
        if self.cfg.dry_run:
            if self._pcap:
                with self._rate_lock:
                    self._pcap.write(pkt)
            log.info("DRY  %-14s %s", beacon, pkt.summary())
            return
        # Shared monotonic token bucket. Responder traffic uses this path too.
        while True:
            with self._rate_lock:
                now = time.monotonic()
                elapsed = now - self._token_time
                self._tokens = min(float(self.cfg.rate_limit),
                                   self._tokens + elapsed * self.cfg.rate_limit)
                self._token_time = now
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    break
                wait = (1.0 - self._tokens) / self.cfg.rate_limit
                self.throttle_waits += 1
            time.sleep(min(wait, 0.05))
        sock = self._socks.get(iface) or self._socks.get(self.cfg.interface)
        try:
            sock.send(pkt)
        except Exception as e:
            self.failures += 1
            log.warning("send failed (%s): %s", beacon, e)

    def snapshot(self):
        with self._rate_lock:
            return {"sent": self.sent, "by_beacon": dict(self.by_beacon),
                    "send_failures": self.failures,
                    "throttle_waits": self.throttle_waits}

    def close(self):
        for s in self._socks.values():
            try:
                s.close()
            except Exception:
                pass
        if self._pcap:
            self._pcap.close()


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
            for port in set(d.profile.get("ports", [])) | set(d.profile.get("udp_ports", [])):
                self.listeners.setdefault(port, []).append(d)
        self.ntp_ip = None
        self.host_ips = {}
        self._event_seq = 0
        self._suspicious_seq = 0
        self._suspicious_lock = threading.Lock()
        self._suspicious_tokens = float(cfg.suspicious_max_pps)
        self._suspicious_token_time = time.monotonic()
        self.suspicious_by_country = {}
        self.suspicious_by_behavior = {}
        self.suspicious_by_indication = {}
        self.suspicious_rate_drops = 0
        for dev in roster:
            for host in dev.profile.get("checkin", []) or []:
                # Deterministic TEST-NET-3 destination: SNI/DNS stays realistic,
                # but the simulator never contacts a real vendor service.
                self.host_ips[host] = "203.0.113.%d" % (1 + zlib.crc32(host.encode()) % 253)
        self._resolve_infra()

    # -- infrastructure resolution --
    def _resolve_infra(self):
        if self.cfg.dry_run:
            for site in self.cfg.sites:
                site.gw_mac = "de:ad:be:ef:00:01"
        else:
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
            probe = (Ether(src=get_if_hwaddr(site.interface), dst=BCAST_MAC) /
                     ARP(op=1, hwsrc=get_if_hwaddr(site.interface),
                         psrc=get_if_addr(site.interface), pdst=ip))
            ans = srp1(probe, iface=site.interface, timeout=1, verbose=False)
            m = ans[ARP].hwsrc if ans and ans.haslayer(ARP) else None
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

    def _suspicious_allow(self):
        if self.cfg.dry_run:
            return True
        with self._suspicious_lock:
            now = time.monotonic()
            elapsed = now - self._suspicious_token_time
            self._suspicious_tokens = min(
                float(self.cfg.suspicious_max_pps),
                self._suspicious_tokens + elapsed * self.cfg.suspicious_max_pps)
            self._suspicious_token_time = now
            if self._suspicious_tokens < 1.0:
                self.suspicious_rate_drops += 1
                return False
            self._suspicious_tokens -= 1.0
            return True

    def suspicious_snapshot(self):
        with self._suspicious_lock:
            return {
                "enabled": self.cfg.suspicious_enabled,
                "selected_devices": getattr(self, "suspicious_device_count", 0),
                "by_country": dict(self.suspicious_by_country),
                "by_behavior": dict(self.suspicious_by_behavior),
                "by_indication": dict(self.suspicious_by_indication),
                "target_indications": sorted({i for values in BEHAVIOR_INDICATIONS.values()
                                               for i in values}),
                "rate_limited": self.suspicious_rate_drops,
            }

    def suspicious_beacon(self, dev):
        """Emit a bounded, non-exploit suspicious signal to a public resolver."""
        if not self.cfg.suspicious_enabled or not self._wan_ok() or not self._suspicious_allow():
            return None
        seq = self._suspicious_seq
        self._suspicious_seq += 1
        countries = self.cfg.suspicious_countries
        country = ("china" if "huawei" in dev.profile["id"].lower() and
                   "china" in countries else countries[(dev.idx + seq) % len(countries)])
        behavior = self.cfg.suspicious_behaviors[seq % len(self.cfg.suspicious_behaviors)]
        targets = self.cfg.suspicious_targets[country]
        target = targets[(dev.idx + seq) % len(targets)]
        with self._suspicious_lock:
            self.suspicious_by_country[country] = self.suspicious_by_country.get(country, 0) + 1
            self.suspicious_by_behavior[behavior] = self.suspicious_by_behavior.get(behavior, 0) + 1
            for indication in BEHAVIOR_INDICATIONS.get(behavior, []):
                self.suspicious_by_indication[indication] = \
                    self.suspicious_by_indication.get(indication, 0) + 1
        eth = Ether(src=dev.mac, dst=self._dst_mac_for(dev, target))
        ip = IP(src=dev.ip, dst=target)
        if behavior == "port_beacon":
            port = self.cfg.suspicious_ports[seq % len(self.cfg.suspicious_ports)]
            return eth / ip / TCP(sport=40000 + (dev.idx % 20000), dport=port,
                                  flags="S", seq=random.randint(1, 0xFFFFFFFF))
        if behavior in ("ftp_transfer", "smb_transfer", "ssh_low_popularity",
                        "ssh_nonstandard"):
            return self._suspicious_protocol_exchange(dev, behavior)
        if behavior == "long_dns":
            labels = [base64.b32encode(struct.pack("!III", dev.idx, seq, n)).decode()
                      .rstrip("=").lower() for n in range(8)]
            qname, qtype = ".".join(labels) + ".telemetry.invalid", "TXT"
        elif behavior == "nxdomain_dns":
            qname, qtype = f"missing-{dev.serial}-{seq}.invalid", "A"
        elif behavior == "local_domain_dns":
            qname, qtype = f"plc-{dev.serial}.operations.local", "A"
        elif behavior == "dyndns_dns":
            qname, qtype = f"iotad-{dev.serial}.duckdns.org", "A"
        elif behavior == "geo_dns":
            qname, qtype = f"telemetry-{dev.serial}.iotad-lab.invalid", "A"
        elif behavior == "dga_dns":
            raw = struct.pack("!III", self.cfg.seed, dev.idx, seq)
            qname = base64.b32encode(raw).decode().rstrip("=").lower() + ".update.invalid"
            qtype = "A"
        else:
            raw = struct.pack("!III", dev.idx, seq, int(time.time()) // 300)
            label = (base64.b32encode(raw).decode().rstrip("=").lower() * 3)[:52]
            qname, qtype = label + ".telemetry.invalid", "TXT"
        return (eth / ip / UDP(sport=49152 + (dev.idx % 16000), dport=53) /
                DNS(id=(dev.idx + seq) & 0xFFFF, rd=1,
                    qd=DNSQR(qname=qname, qtype=qtype)))

    def _suspicious_protocol_exchange(self, dev, behavior):
        """Complete cross-site application conversation for anomaly engines."""
        remote = [d for d in self.roster if d.site is not dev.site and d.idx != dev.idx]
        peers = remote or [d for d in self.roster if d.idx != dev.idx]
        if not peers:
            return None
        peer = peers[(dev.idx + self._suspicious_seq) % len(peers)]
        is_remote = peer.site is not dev.site
        if is_remote and not self._wan_ok():
            return None
        if not is_remote and not self._sub_ok():
            return None
        definitions = {
            "ftp_transfer": (21,
                b"USER service\r\nPASS iotad-lab\r\nTYPE I\r\nSTOR diagnostics.bin\r\n",
                b"220 iotad FTP ready\r\n331 Password required\r\n230 Login ok\r\n"
                b"200 Type set to I\r\n150 Opening data connection\r\n226 Transfer complete\r\n"),
            "smb_transfer": (445,
                b"\x00\x00\x00\x44\xfeSMB\x40\x00\x00\x00" + b"\x00" * 56,
                b"\x00\x00\x00\x44\xfeSMB\x40\x00\x00\x00" + b"\x01" * 56),
            "ssh_low_popularity": (22,
                b"SSH-2.0-PuTTY_Release_0.78\r\n",
                b"SSH-2.0-OpenSSH_8.9p1 iotad-lab\r\n"),
            "ssh_nonstandard": (2222,
                b"SSH-2.0-PuTTY_Release_0.78\r\n",
                b"SSH-2.0-OpenSSH_8.9p1 iotad-lab\r\n"),
        }
        port, request, response = definitions[behavior]
        c_dst = (peer.site.gw_mac if is_remote else peer.mac) or BCAST_MAC
        s_dst = (dev.site.gw_mac if is_remote else dev.mac) or BCAST_MAC
        sport = random.randint(20000, 60000)
        cseq, sseq = random.randint(1, 0x7FFFFFFF), random.randint(1, 0x7FFFFFFF)

        def frame(src, dst, sip, dip, sp, dp, flags, seqno, ackno, payload, iface):
            pkt = (Ether(src=src, dst=dst) / IP(src=sip, dst=dip) /
                   TCP(sport=sp, dport=dp, flags=flags, seq=seqno, ack=ackno))
            return WireFrame(pkt / Raw(payload) if payload else pkt, iface)

        return [
            frame(dev.mac, c_dst, dev.ip, peer.ip, sport, port, "S", cseq, 0, b"",
                  dev.site.interface),
            frame(peer.mac, s_dst, peer.ip, dev.ip, port, sport, "SA", sseq, cseq + 1, b"",
                  peer.site.interface),
            frame(dev.mac, c_dst, dev.ip, peer.ip, sport, port, "PA", cseq + 1, sseq + 1,
                  request, dev.site.interface),
            frame(peer.mac, s_dst, peer.ip, dev.ip, port, sport, "PA", sseq + 1,
                  cseq + 1 + len(request), response, peer.site.interface),
            frame(peer.mac, s_dst, peer.ip, dev.ip, port, sport, "FA",
                  sseq + 1 + len(response), cseq + 1 + len(request), b"", peer.site.interface),
            frame(dev.mac, c_dst, dev.ip, peer.ip, sport, port, "A", cseq + 1 + len(request),
                  sseq + 2 + len(response), b"", dev.site.interface),
        ]

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
            idy = dev.profile["identity"]
            records = [
                DNSRR(rrname=f"{svc}.local", type="PTR", ttl=120, rdata=inst),
                DNSRRSRV(rrname=inst, ttl=120, priority=0, weight=0, port=port,
                         target=f"{dev.hostname}.local"),
                DNSRR(rrname=inst, type="TXT", ttl=120,
                      rdata=[b"model=" + idy["product"].encode(),
                             b"vendor=" + idy["vendor"].encode(),
                             b"fw=" + idy["revision"].encode()]),
                DNSRR(rrname=f"{dev.hostname}.local", type="A", ttl=120, rdata=dev.ip),
            ]
            dns = DNS(qr=1, aa=1, qd=[], an=records, ancount=len(records))
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

    def _tcp_exchange(self, dev, port, request, response):
        """Emit a compact, internally consistent TCP application exchange.

        For cross-site traffic, client-side frames leave the client's interface
        and server-side frames leave the peer's interface, so both Cato Sockets
        observe their half of the routed conversation.
        """
        peer = self._pick_peer(dev, port)
        if not peer:
            return None
        remote = peer.site is not dev.site
        if remote and not self._wan_ok():
            return None
        if not remote and not self._sub_ok():
            return None
        c_dst = (peer.site.gw_mac if remote else peer.mac) or BCAST_MAC
        s_dst = (dev.site.gw_mac if remote else dev.mac) or BCAST_MAC
        sport = random.randint(20000, 60000)
        cseq = random.randint(1, 0x7FFFFFFF)
        sseq = random.randint(1, 0x7FFFFFFF)

        def c(flags, seq, ack=0, data=b""):
            p = (Ether(src=dev.mac, dst=c_dst) / IP(src=dev.ip, dst=peer.ip) /
                 TCP(sport=sport, dport=port, flags=flags, seq=seq, ack=ack))
            return WireFrame(p / Raw(data) if data else p, dev.site.interface)

        def s(flags, seq, ack=0, data=b""):
            p = (Ether(src=peer.mac, dst=s_dst) / IP(src=peer.ip, dst=dev.ip) /
                 TCP(sport=port, dport=sport, flags=flags, seq=seq, ack=ack))
            return WireFrame(p / Raw(data) if data else p, peer.site.interface)

        return [
            c("S", cseq),
            s("SA", sseq, cseq + 1),
            c("PA", cseq + 1, sseq + 1, request),
            s("PA", sseq + 1, cseq + 1 + len(request), response),
            s("FA", sseq + 1 + len(response), cseq + 1 + len(request)),
            c("A", cseq + 1 + len(request), sseq + 2 + len(response)),
        ]

    def _udp_exchange(self, dev, port, request, response):
        peer = self._pick_peer(dev, port)
        if not peer:
            return None
        remote = peer.site is not dev.site
        if remote and not self._wan_ok():
            return None
        if not remote and not self._sub_ok():
            return None
        c_dst = (peer.site.gw_mac if remote else peer.mac) or BCAST_MAC
        s_dst = (dev.site.gw_mac if remote else dev.mac) or BCAST_MAC
        sport = random.randint(20000, 60000)
        req = (Ether(src=dev.mac, dst=c_dst) / IP(src=dev.ip, dst=peer.ip) /
               UDP(sport=sport, dport=port) / Raw(request))
        resp = (Ether(src=peer.mac, dst=s_dst) / IP(src=peer.ip, dst=dev.ip) /
                UDP(sport=port, dport=sport) / Raw(response))
        return [WireFrame(req, dev.site.interface),
                WireFrame(resp, peer.site.interface)]

    def modbus(self, dev):
        tid = random.randint(0, 0xFFFF)
        req = struct.pack(">HHHBBHH", tid, 0, 6, 1, 3, 0, 4)
        resp = struct.pack(">HHHBBBHHHH", tid, 0, 11, 1, 3, 8, 720, 510, 68, 1013)
        return self._tcp_exchange(dev, 502, req, resp)

    def s7(self, dev):
        req = bytes.fromhex("0300001611e00000000100c1020100c2020102c0010a")
        resp = bytes.fromhex("0300001611d00001000000c0010ac1020100c2020102")
        return self._tcp_exchange(dev, 102, req, resp)

    def opcua(self, dev):        # OPC UA binary (modern industrial)
        endpoint = b"opc.tcp://iotad-lab:4840"
        req = b"HEL\x00" + struct.pack("<IIIII", 32 + len(endpoint), 0, 65535, 65535, 0) + \
              struct.pack("<I", len(endpoint)) + endpoint
        resp = b"ACK\x00" + struct.pack("<IIIIII", 28, 0, 65535, 65535, 0, 0)
        return self._tcp_exchange(dev, 4840, req, resp)

    def dnp3(self, dev):         # SCADA / utility RTUs and relays
        return self._tcp_exchange(dev, 20000,
                                  bytes.fromhex("056405c901000004"),
                                  bytes.fromhex("0564050004000001"))

    def fox(self, dev):          # Niagara Fox / Tridium building controllers
        return self._tcp_exchange(dev, 1911, b"fox a 1 -1 fox hello\n",
                                  b"fox a 1 0 fox hello iotad-jace\n")

    def iec104(self, dev):       # IEC 60870-5-104 SCADA
        return self._tcp_exchange(dev, 2404, bytes.fromhex("680407000000"),
                                  bytes.fromhex("68040b000000"))

    def melsec(self, dev):       # Mitsubishi MELSEC / SLMP
        req = bytes.fromhex("500000ffff03000c00100001040000d0000000a80100")
        resp = bytes.fromhex("d00000ffff0300040000000000")
        return self._tcp_exchange(dev, 5007, req, resp)

    def fins(self, dev):
        # Omron FINS/UDP node-address broadcast (controller data read, cmd 0501)
        node = dev.mac_bytes[-1] or 1
        payload = bytes([0x80, 0x00, 0x02, 0x00, 0xFF, 0x00,
                         0x00, node, 0x00, 0x00, 0x05, 0x01, 0x00])
        return (Ether(src=dev.mac, dst=BCAST_MAC) /
                IP(src=dev.ip, dst=self._broadcast_ip(dev)) /
                UDP(sport=9600, dport=9600) / Raw(payload))

    def hartip(self, dev):
        return self._tcp_exchange(dev, 5094, b"HART-IP\x01\x00\x00\x00",
                                  b"HART-IP\x01\x00\x00\x01")

    def cip_safety(self, dev):
        req = struct.pack("<HHII8sI", 0x0065, 4, 0, 0, b"iotadCIP", 0) + b"\x01\x00\x00\x00"
        resp = struct.pack("<HHII8sI", 0x0065, 4, 1, 0, b"iotadCIP", 0) + b"\x01\x00\x00\x00"
        return self._tcp_exchange(dev, 44818, req, resp)

    def dicom(self, dev):
        called, calling = b"IOTAD_SCP".ljust(16), b"IOTAD_SCU".ljust(16)
        body = b"\x00\x01\x00\x00" + called + calling + b"\x00" * 32
        req = b"\x01\x00" + struct.pack(">I", len(body)) + body
        resp = b"\x02\x00" + struct.pack(">I", len(body)) + body
        return self._tcp_exchange(dev, 11112, req, resp)

    def hl7(self, dev):
        msg = (b"\x0bMSH|^~\\&|IOTAD|LAB|EMR|CATO|20260821060000||ORU^R01|1|P|2.5\r"
               b"OBX|1|NM|TEMP||21.4|C|18-25|N\r\x1c\r")
        ack = (b"\x0bMSH|^~\\&|EMR|CATO|IOTAD|LAB|20260821060001||ACK|1|P|2.5\r"
               b"MSA|AA|1\r\x1c\r")
        return self._tcp_exchange(dev, 2575, msg, ack)

    @staticmethod
    def _mqtt_string(value):
        value = value.encode() if isinstance(value, str) else value
        return struct.pack(">H", len(value)) + value

    def mqtt(self, dev):
        client_id = self._mqtt_string(dev.hostname)
        variable = self._mqtt_string("MQTT") + b"\x04\x02\x00\x3c"
        connect_body = variable + client_id
        connect = b"\x10" + bytes([len(connect_body)]) + connect_body
        topic = "spBv1.0/iotad/DDATA/%s" % dev.hostname
        payload = self._mqtt_string(topic) + b"metrics=temperature:21.4,status:online"
        publish = b"\x30" + bytes([len(payload)]) + payload
        return self._tcp_exchange(dev, 1883, connect + publish, b"\x20\x02\x00\x00")

    def coap(self, dev):
        token = dev.mac_bytes[-2:]
        request = b"\x42\x01" + struct.pack(">H", random.randint(1, 65535)) + token + \
                  b"\xb7sensors\x0btemperature"
        response = b"\x62\x45" + request[2:6] + b"\xc1\x00\xff21.4 C"
        return self._udp_exchange(dev, 5683, request, response)

    def knx(self, dev):
        request = bytes.fromhex("06100201000e0801") + b"\x00" * 6
        response = bytes.fromhex("0610020200360801") + b"\x00" * 40
        return self._udp_exchange(dev, 3671, request, response)

    def iec61850(self, dev):
        # TPKT/COTP Data TPDU followed by compact MMS initiate request/response.
        request = bytes.fromhex("0300001602f080a80f80020780810100820100830100")
        response = bytes.fromhex("0300001602f080a90f80020780810100820100830100")
        return self._tcp_exchange(dev, 102, request, response)

    def mtconnect(self, dev):
        request = (b"GET /current HTTP/1.1\r\nHost: mtconnect.local:7878\r\n"
                   b"Accept: application/xml\r\nConnection: close\r\n\r\n")
        body = (b"<?xml version=\"1.0\"?><MTConnectStreams><DeviceStream name=\"cell\">"
                b"<Events><Execution dataItemId=\"exec\">ACTIVE</Execution>"
                b"</Events></DeviceStream></MTConnectStreams>")
        response = (b"HTTP/1.1 200 OK\r\nContent-Type: application/xml\r\nContent-Length: " +
                    str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body)
        return self._tcp_exchange(dev, 7878, request, response)

    def scenario_event(self, dev):
        """Emit a controlled operational event; the global limiter remains final."""
        event = ("shift_change", "maintenance", "alarm", "environmental_excursion",
                 "firmware_update", "device_failure")[self._event_seq % 6]
        self._event_seq += 1
        if event == "shift_change":
            return self.dhcp(dev)
        if event in ("maintenance", "firmware_update"):
            path = b"/maintenance/diagnostics" if event == "maintenance" else b"/firmware/check"
            request = b"GET " + path + b" HTTP/1.1\r\nHost: device.local\r\n\r\n"
            response = (b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                        b"Content-Length: 15\r\n\r\n{\"status\":\"ok\"}")
            return self._tcp_exchange(dev, 80, request, response)
        severity = {"alarm": 3, "environmental_excursion": 4, "device_failure": 2}[event]
        message = (f"<1{severity}4>1 {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} "
                   f"{dev.hostname} iotad - - [event@32473 type=\"{event}\" "
                   f"category=\"{dev.profile['category']}\"] simulated lab event").encode()
        return (Ether(src=dev.mac, dst=dev.site.gw_mac or BCAST_MAC) /
                IP(src=dev.ip, dst=dev.site.gateway) /
                UDP(sport=514, dport=514) / Raw(message))

    # -- outbound check-ins (routed via the device's own Socket) --
    def dns_checkin(self, dev):
        if not self._sub_ok():
            return None
        hosts = dev.profile.get("checkin") or []
        if not hosts:
            return None
        q = random.choice(hosts)
        resolver = dev.site.dns_server or self.cfg.dns_server
        return (Ether(src=dev.mac, dst=self._dst_mac_for(dev, resolver) or BCAST_MAC) /
                IP(src=dev.ip, dst=resolver) /
                UDP(sport=random.randint(1024, 65535), dport=53) /
                DNS(rd=1, qd=DNSQR(qname=q, qtype="A")))

    def ntp(self, dev):
        if not self._wan_ok() or not self.ntp_ip:
            return None
        return (Ether(src=dev.mac, dst=self._dst_mac_for(dev, self.ntp_ip) or BCAST_MAC) /
                IP(src=dev.ip, dst=self.ntp_ip) /
                UDP(sport=random.randint(1024, 65535), dport=123) /
                NTP(version=4, mode=3))

    def tls_checkin(self, dev):
        if not self._wan_ok():
            return None
        hosts = dev.profile.get("checkin") or []
        if not hosts:
            return None
        host = random.choice(hosts)
        dst = self.host_ips[host]
        sport = random.randint(1024, 65535)
        seq = random.randint(0, 0x7FFFFFFF)
        ether = Ether(src=dev.mac, dst=dev.site.gw_mac or BCAST_MAC)
        syn = ether / IP(src=dev.ip, dst=dst) / TCP(sport=sport, dport=443, flags="S", seq=seq)
        hello = self._tls_client_hello(host)
        data = (ether / IP(src=dev.ip, dst=dst) /
                TCP(sport=sport, dport=443, flags="PA", seq=seq + 1, ack=1) / Raw(hello))
        return [syn, data]

    @staticmethod
    def _tls_client_hello(host):
        """Small valid TLS 1.2-compatible ClientHello carrying SNI and TLS 1.3."""
        name = host.encode("idna")[:253]
        sni = b"\x00\x00" + struct.pack(">H", len(name) + 5) + \
              struct.pack(">H", len(name) + 3) + b"\x00" + struct.pack(">H", len(name)) + name
        versions = b"\x00\x2b\x00\x05\x04\x03\x04\x03\x03"
        groups = b"\x00\x0a\x00\x06\x00\x04\x00\x1d\x00\x17"
        exts = sni + versions + groups
        body = (b"\x03\x03" + os.urandom(32) + b"\x00" +
                b"\x00\x06\x13\x01\x13\x02\xc0\x2f" + b"\x01\x00" +
                struct.pack(">H", len(exts)) + exts)
        hs = b"\x01" + len(body).to_bytes(3, "big") + body
        return b"\x16\x03\x01" + struct.pack(">H", len(hs)) + hs


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
    Counter32/Gauge32/TimeTicks. BER still requires a leading zero when the
    high bit is set so the constrained INTEGER value is not decoded negative."""
    n &= 0xFFFFFFFF
    if n == 0:
        return b"\x00"
    b = []
    while n:
        b.insert(0, n & 0xFF)
        n >>= 8
    if b[0] & 0x80:
        b.insert(0, 0)
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

    def __init__(self, cfg, roster, tx, iface=None, known_macs=None):
        self.cfg = cfg
        self.tx = tx
        self.iface = iface or cfg.interface
        self.by_ip = {d.ip: d for d in roster}
        self.our_macs = set(known_macs or (d.mac for d in roster))
        self.snmp = {d.ip: SnmpAgent(d) for d in roster if d.profile.get("snmp")}
        # EtherNet/IP List Identity + WS-Discovery answerers (application-layer
        # identity, so a discovery engine learns vendor/model, not just "port open")
        self.enip = {d.ip: d for d in roster if d.profile.get("cip")}
        self.ws = {d.ip: d for d in roster if d.profile.get("ws_discovery")}
        self.bacnet = {d.ip: d for d in roster if d.profile.get("bacnet")}
        self.profinet = {d.mac: d for d in roster if d.profile.get("profinet")}
        # mDNS query index: service-type -> devices, and <host>.local -> device
        self.mdns_svc, self.mdns_host = {}, {}
        for d in roster:
            for svc in d.profile.get("mdns", []) or []:
                self.mdns_svc.setdefault(f"{svc}.local".lower(), []).append(d)
                self.mdns_host[f"{d.hostname}.local".lower()] = d
        self.conns = {}
        self.sniffer = None
        self.arp_replies = self.icmp_replies = 0
        self.tcp_opens = self.tcp_banners = self.snmp_replies = 0
        self.enip_replies = self.ws_replies = self.mdns_replies = 0
        self.modbus_replies = 0
        self.bacnet_replies = self.profinet_replies = 0

    def start(self):
        if self.cfg.dry_run:
            return
        # Kernel-side filter: ARP, ICMP, the UDP discovery/identity protocols
        # (SNMP 161, mDNS 5353, WS-Discovery 3702, EtherNet/IP List Identity
        # 44818), and TCP control/data segments (SYN/FIN/RST/PSH -- skip the
        # bare-ACK stream we never generate).
        filt = ("arp or icmp or "
                "(udp port 161 or udp port 5353 or udp port 3702 or udp port 44818 or "
                "udp port 47808) or ether proto 0x8892 or "
                "(tcp and tcp[13] & 0x0f != 0)")
        self.sniffer = AsyncSniffer(iface=self.iface, store=False,
                                    filter=filt, prn=self._handle)
        self.sniffer.start()
        log.info("responder[%s] listening (ARP/ICMP/TCP/SNMP/mDNS/WS-Disc/EtherNet-IP) "
                 "for %d device IPs", self.iface, len(self.by_ip))

    def _tx(self, dev, l3, dst_mac):
        self.tx.send("response", Ether(src=dev.mac, dst=dst_mac) / l3, self.iface)

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
            elif pkt[Ether].type == 0x8892:
                self._profinet(pkt)
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
                elif dport == 47808:
                    self._bacnet(pkt)
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
        key = (ip.src, t.sport, ip.dst, port)
        if flags & SYN and not flags & ACK:        # open port -> SYN-ACK
            cutoff = time.monotonic() - 30.0
            for old_key, old in list(self.conns.items()):
                if old[3] < cutoff:
                    self.conns.pop(old_key, None)
            isn = random.randint(0, 0xFFFFFFFF)
            self.conns[key] = (isn, dev, port, time.monotonic())
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
            self._tx(dev, IP(src=dev.ip, dst=pkt[IP].src) /
                     UDP(sport=44818, dport=pkt[UDP].sport) / Raw(body),
                     pkt[Ether].src)
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
        target = self.ws.get(pkt[IP].dst)
        for dev in ([target] if target else self.ws.values()):
            body = self._wsdisc_match(dev, relates)
            self._tx(dev, IP(src=dev.ip, dst=pkt[IP].src) /
                     UDP(sport=3702, dport=pkt[UDP].sport) / Raw(body),
                     pkt[Ether].src)
            self.ws_replies += 1

    def _bacnet(self, pkt):
        """Answer BACnet/IP Who-Is with one I-Am per matching controller."""
        data = bytes(pkt[UDP].payload)
        if len(data) < 4 or data[0] != 0x81 or b"\x10\x08" not in data:
            return
        target = self.bacnet.get(pkt[IP].dst)
        for dev in ([target] if target else self.bacnet.values()):
            b = dev.profile["bacnet"]
            objid = (8 << 22) | (b["device_id"] & 0x3FFFFF)
            apdu = (b"\x10\x00\xc4" + struct.pack(">I", objid) +
                    b"\x22\x05\xc4\x91\x03\x22" + struct.pack(">H", b["vendor_id"]))
            npdu = b"\x01\x00" + apdu
            body = b"\x81\x0a" + struct.pack(">H", len(npdu) + 4) + npdu
            self._tx(dev, IP(src=dev.ip, dst=pkt[IP].src) /
                     UDP(sport=47808, dport=pkt[UDP].sport) / Raw(body),
                     pkt[Ether].src)
            self.bacnet_replies += 1

    def _profinet(self, pkt):
        """Answer DCP Identify-All with station-name identity blocks."""
        data = bytes(pkt[Ether].payload)
        if len(data) < 12 or data[:2] != b"\xfe\xfe" or data[2] != 0x05:
            return
        xid = data[4:8]
        for dev in self.profinet.values():
            name = dev.hostname.encode()[:240]
            block = b"\x02\x02" + struct.pack(">H", len(name) + 2) + b"\x00\x00" + name
            if len(block) & 1:
                block += b"\x00"
            body = b"\xfe\xff\x05\x01" + xid + b"\x00\x00" + struct.pack(">H", len(block)) + block
            self.tx.send("response", Ether(src=dev.mac, dst=pkt[Ether].src, type=0x8892) /
                         Raw(body), self.iface)
            self.profinet_replies += 1

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
        dns = DNS(qr=1, aa=1, qd=[], an=an)
        self.tx.send("response", Ether(src=dev.mac, dst=MDNS_MCAST_MAC) /
                     IP(src=dev.ip, dst="224.0.0.251", ttl=255) /
                     UDP(sport=5353, dport=5353) / dns, self.iface)
        self.mdns_replies += 1

    def stop(self):
        if self.sniffer:
            try:
                self.sniffer.stop()
            except Exception:
                pass
        log.info("responder[%s] answered %d ARP, %d ICMP, %d TCP(open), "
                 "%d HTTP, %d SNMP, %d Modbus-ID, %d EtherNet/IP, %d WS-Disc, "
                  "%d mDNS, %d BACnet, %d PROFINET", self.iface,
                  self.arp_replies, self.icmp_replies,
                 self.tcp_opens, self.tcp_banners, self.snmp_replies,
                 self.modbus_replies, self.enip_replies, self.ws_replies,
                  self.mdns_replies, self.bacnet_replies, self.profinet_replies)

    def snapshot(self):
        return {
            "interface": self.iface,
            "devices": len(self.by_ip),
            "arp": self.arp_replies,
            "icmp": self.icmp_replies,
            "tcp_open": self.tcp_opens,
            "http": self.tcp_banners,
            "snmp": self.snmp_replies,
            "modbus": self.modbus_replies,
            "ethernet_ip": self.enip_replies,
            "ws_discovery": self.ws_replies,
            "mdns": self.mdns_replies,
            "bacnet": self.bacnet_replies,
            "profinet": self.profinet_replies,
            "tcp_state_entries": len(self.conns),
        }


class MetricsReporter:
    """Periodically writes an atomic JSON health/traffic snapshot."""

    def __init__(self, cfg, roster, tx, responders, emitters=None):
        self.cfg, self.roster, self.tx, self.responders = cfg, roster, tx, responders
        self.emitters = emitters
        self.started = time.time()
        self._stop = threading.Event()
        self._thread = None

    def snapshot(self):
        by_category, by_site = {}, {}
        for dev in self.roster:
            by_category[dev.profile["category"]] = by_category.get(dev.profile["category"], 0) + 1
            by_site[dev.site.name] = by_site.get(dev.site.name, 0) + 1
        return {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "uptime_seconds": int(time.time() - self.started),
            "facility": self.cfg.facility,
            "scenario": self.cfg.scenario,
            "devices": len(self.roster),
            "devices_by_category": by_category,
            "devices_by_site": by_site,
            "sites": [{"name": s.name, "interface": s.interface,
                       "zone": s.zone, "vlan": s.vlan, "subnet": str(s.subnet)}
                      for s in self.cfg.sites],
            "transmitter": self.tx.snapshot(),
            "suspicious": (self.emitters.suspicious_snapshot() if self.emitters else {
                "enabled": self.cfg.suspicious_enabled,
            }),
            "responders": [r.snapshot() for r in self.responders],
        }

    def _write(self):
        if not self.cfg.metrics_file:
            return
        directory = os.path.dirname(self.cfg.metrics_file) or "."
        os.makedirs(directory, exist_ok=True)
        tmp = self.cfg.metrics_file + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self.snapshot(), f, indent=2, sort_keys=True)
            f.write("\n")
        os.replace(tmp, self.cfg.metrics_file)

    def _run(self):
        while not self._stop.wait(self.cfg.metrics_interval):
            try:
                self._write()
            except OSError as e:
                log.warning("metrics: %s", e)

    def start(self):
        if not self.cfg.dry_run and self.cfg.metrics_file:
            self._write()
            self._thread = threading.Thread(target=self._run, daemon=True,
                                            name="iotad-metrics")
            self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)
        if not self.cfg.dry_run and self.cfg.metrics_file:
            try:
                self._write()
            except OSError as e:
                log.warning("metrics: %s", e)


# ---- scheduler -------------------------------------------------------------
class Scheduler:
    def __init__(self, cfg, roster, emitters, tx):
        self.cfg, self.roster, self.em, self.tx = cfg, roster, emitters, tx
        self.heap = []
        self.seq = 0
        self.running = True
        count = int(round(len(roster) * cfg.suspicious_device_fraction))
        if cfg.suspicious_enabled and cfg.suspicious_device_fraction > 0 and roster:
            count = max(1, min(len(roster), count))
            rng = random.Random(cfg.seed ^ 0x51A1C10)
            huawei = [d for d in roster if "huawei" in d.profile["id"].lower()]
            others = [d for d in roster if d not in huawei]
            rng.shuffle(huawei)
            rng.shuffle(others)
            self.suspicious_devices = (huawei + others)[:count]
        else:
            self.suspicious_devices = []
        self.em.suspicious_device_count = len(self.suspicious_devices)

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
        if beacon == SUSPICIOUS_BEACON:
            return (self.cfg.suspicious_interval * random.uniform(0.75, 1.25) *
                    self._diurnal() * SCENARIO_CADENCE[self.cfg.scenario])
        key, default = BEACON_INTERVAL[beacon]
        if key == "checkin":
            lo = self.cfg.timing.getint("checkin_min")
            hi = self.cfg.timing.getint("checkin_max")
            base = random.randint(lo, hi)
        else:
            base = self.cfg.timing.getint(key, fallback=default)
        return (base * random.uniform(0.75, 1.25) * self._diurnal() *
                SCENARIO_CADENCE[self.cfg.scenario])

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
        if self.cfg.events_enabled:
            stride = max(1, len(self.roster) // 20)
            for dev in self.roster[::stride]:
                self._schedule(now + random.uniform(5, 30), dev, "scenario_event")
        if self.cfg.suspicious_enabled and self.em._wan_ok():
            for dev in self.suspicious_devices:
                self._schedule(now + random.uniform(10, min(self.cfg.suspicious_interval, 180)),
                               dev, SUSPICIOUS_BEACON)

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
            if isinstance(p, WireFrame):
                self.tx.send(beacon, p.pkt, p.iface)
            else:
                self.tx.send(beacon, p, dev.site.interface)

    def run_once(self):
        """Emit exactly one of every applicable beacon per device (testing)."""
        for dev in self.roster:
            for beacon in dev.profile["beacons"]:
                if beacon in WAN_BEACONS and not self.em._wan_ok():
                    continue
                self.emit(dev, beacon)
        if self.cfg.events_enabled:
            stride = max(1, len(self.roster) // 20)
            for dev in self.roster[::stride]:
                self.emit(dev, "scenario_event")
        if self.cfg.suspicious_enabled and self.em._wan_ok():
            for dev in self.suspicious_devices:
                self.emit(dev, SUSPICIOUS_BEACON)

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
    ap.add_argument("--pcap", metavar="FILE",
                    help="write crafted frames to a PCAP instead of transmitting")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    if not os.path.exists(args.config) and args.config == "/etc/iotad.conf":
        local = os.path.join(HERE, "iotad.conf")
        if os.path.exists(local):
            args.config = local

    try:
        cfg = Config(args.config)
    except (ValueError, configparser.Error, ipaddress.AddressValueError) as e:
        sys.exit(f"iotad: invalid config: {e}")
    if args.dry_run:
        cfg.dry_run = True
    if args.pcap:
        cfg.dry_run = True
        cfg.pcap_path = args.pcap
    else:
        cfg.pcap_path = None
    setup_logging(cfg, args.verbose)

    catalog = load_catalog()
    roster = build_roster(catalog, cfg)

    if args.list:
        print_roster(roster)
        return

    if not cfg.dry_run and os.geteuid() != 0:
        sys.exit("iotad: raw-socket transmit needs root (or --dry-run)")

    sites_desc = ", ".join(f"{s.name}={s.interface}:{s.subnet}" for s in cfg.sites)
    log.info("config=%s sites=[%s] devices=%d facility=%s scenario=%s dry_run=%s scope=%s",
             args.config, sites_desc, len(roster), cfg.facility, cfg.scenario,
             cfg.dry_run, cfg.outbound_scope)

    tx = Tx(cfg)
    emitters = Emitters(cfg, tx, roster)
    sched = Scheduler(cfg, roster, emitters, tx)
    # One responder per interface, each owning only that interface's devices.
    responders = []
    for iface in {s.interface for s in cfg.sites}:
        subset = [d for d in roster if d.site.interface == iface]
        responders.append(Responder(cfg, subset, tx, iface=iface,
                                    known_macs=(d.mac for d in roster)))

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
    metrics = MetricsReporter(cfg, roster, tx, responders, emitters)
    metrics.start()
    try:
        sched.run()
    finally:
        metrics.stop()
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
