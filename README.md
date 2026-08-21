# iotad — IoT/OT traffic simulation daemon

See [CHANGELOG.md](CHANGELOG.md) for the public change history.

Populates a lab network with believable IoT/OT assets so network
asset-discovery (built for **Cato Networks** demo/lab enrichment) has something
rich to find. It runs a deterministic roster of virtual devices — each with a
**real vendor OUI** pulled from the IEEE registry — and continuously emits the
L2/L3 traffic those devices would emit.

> ⚠️ **Authorized lab use only.** Every frame carries a **spoofed source
> MAC/IP** for a device that does not physically exist. Run it only on a
> segment you own and are authorized to test. Do not point it at production or
> any network you don't control.

## What it simulates

| Category | Example vendors | Signature traffic |
|---|---|---|
| IP cameras | Axis, Hikvision, Dahua, Hanwha, Bosch | gratuitous ARP, DHCP, mDNS (`_rtsp`/`_http`), SSDP, cloud DNS/TLS |
| NVR / DVR | Hikvision, Synology | mDNS, SSDP, DHCP, cloud DNS |
| Physical access | HID | ARP, DHCP, mDNS, controller check-in |
| IP intercom / door stations | 2N, Aiphone | mDNS (`_sip`/`_http`), SSDP, DHCP |
| HVAC / building automation | Johnson Controls, Honeywell, Emerson, Tridium (JACE) | **BACnet Who-Is** (UDP 47808), **Niagara Fox** (TCP 1911), DHCP |
| PLCs / ICS | Siemens, Rockwell, Schneider, Beckhoff, WAGO, Phoenix, B&R, Omron, Mitsubishi | LLDP, **S7** (102), **EtherNet/IP** (44818), **PROFINET-DCP**, **Modbus** (502), **OPC UA** (4840), **FINS** (UDP 9600), **MELSEC** (5007) |
| SCADA RTUs / relays | SEL, ABB | **DNP3** (TCP 20000), **IEC 60870-5-104** (TCP 2404) |
| HMI / operator panels | Siemens SIMATIC, Rockwell PanelView | LLDP, S7, EtherNet/IP, PROFINET-DCP |
| Industrial networking | Moxa, Advantech, Hirschmann | LLDP, DHCP, Modbus |
| IT networking | Ubiquiti, Cisco | LLDP, **CDP**, **UBNT discovery** (UDP 10001) |
| VoIP phones | Cisco, Poly/Polycom, Yealink, Avaya | **LLDP-MED** (voice VLAN/network-policy), CDP, DHCP fingerprint |
| Printers / MFPs | HP, Canon, Epson, Brother, Xerox, Lexmark, Ricoh, Konica Minolta, Zebra | mDNS (`_ipp`/`_pdl-datastream`/`_uscan`), SNMP trap, cloud DNS |
| AV / room control | Crestron | mDNS, SSDP |
| Power / UPS | APC, Vertiv/Liebert | SNMP trap, DHCP |
| Environmental / rack sensors | APC NetBotz, AKCP, Sensaphone | SNMP trap, mDNS, DHCP |
| Wireless / IoT gateways | MultiTech (LoRaWAN) | mDNS, cloud DNS/TLS, DHCP |
| Lighting | Lutron | mDNS, DHCP |
| Clean-room systems | Siemens FFU controllers, gas/environment monitors | PROFINET, Modbus, BACnet, SNMP |
| Process utilities | RO/DI skids, process instruments, VFDs | Modbus, OPC UA, HART-IP, EtherNet/IP |
| Manufacturing | ABB robot controllers, Rockwell safety controllers | PROFINET, OPC UA, CIP Safety |
| Medical / clinical | Philips monitors, GE imaging workstations | DICOM, HL7 MLLP, DNS/TLS |

Each device also carries a realistic **DHCP fingerprint** (option 60 vendor
class + option 55 parameter list) and hostname, which is what most discovery
engines key on.

## Active responders (device liveness + fingerprinting)

Emitting chatter alone is **not enough** for Cato asset discovery. The Socket
treats broadcast/DHCP/mDNS traffic as *candidates*, then actively confirms each
one — ARP who-has + ICMP ping — and ages out anything that never answers. A
pure emitter answers nothing, so its devices get discovered and then dropped.

So each simulated device now answers, per its profile:

| Probe | Response |
|---|---|
| **ARP who-has** | ARP reply with the device's vendor MAC (liveness confirm) |
| **ICMP echo** | echo-reply (ping confirm) |
| **TCP SYN** to an open port | SYN-ACK; data → application reply (below) → FIN |
| **TCP SYN** to a closed port | RST |
| **HTTP GET** (80/8080) | embedded web UI: `401` + `WWW-Authenticate` (Basic/Digest realm per class) unless the request is authenticated; `Server:` header per vendor; UPnP `description.xml` served unauthenticated |
| **Modbus** (502) | Read Device Identification (FC 43/14): vendor / product / revision |
| **EtherNet/IP** (UDP 44818) | List Identity: CIP vendor id, device type, product code, revision, serial |
| **WS-Discovery** (UDP 3702) | ONVIF `ProbeMatches` — `NetworkVideoTransmitter`, scopes, ONVIF `XAddrs` |
| **mDNS** (UDP 5353) | PTR/SRV/TXT/A for the device's advertised services |
| **SNMP GET/GETNEXT** (v1/v2c) | walkable MIB — system group (`sysDescr` device class), **IF-MIB** (`ifPhysAddress` = real vendor OUI, `ifType`/`ifSpeed`/`ifOperStatus`, interface counters), and **Printer-MIB** toner-supply level for printers |

Open ports are derived from each device's own protocol beacons + mDNS services
+ a per-category baseline, so they match what the device claims to be. The same
vendor / model / revision / serial is surfaced consistently across SNMP,
HTTP/UPnP, mDNS TXT, EtherNet/IP and Modbus, so a discovery engine that
cross-checks protocols sees one coherent device — which is what turns a
transient candidate into a stable, fingerprinted inventory entry.

Scheduled chatter (ARP/DHCP/mDNS/LLDP + OT polls and cloud check-ins) also
follows a **diurnal** rhythm: full cadence in business hours, quieter overnight.

The OT poll generators produce compact bidirectional TCP conversations rather
than SYN-only probes for Modbus, S7, OPC UA, DNP3, IEC-104, Niagara Fox,
MELSEC, HART-IP, CIP Safety, DICOM, and HL7. This gives flow and application
identification engines request/response payloads to classify.

> A **confirmed** device also passes the Socket's uRPF/anti-spoof filter, so its
> flows route to the WAN — which is what makes true site-to-site OT traffic
> possible (below).

## Multi-site (true WAN site-to-site OT traffic)

A single interface simulates one site. Wire a **second NIC to a second Cato
Socket** and declare `[site:*]` sections (see `iotad.conf`) to simulate two
physical sites with OT traffic crossing the Cato WAN between them:

- devices are distributed round-robin across the sites (each keeps its own
  subnet, gateway, IP pool, and vendor MACs);
- each site gets its own Tx socket **and** responder bound to its interface;
- a share of the OT polls (Modbus/S7/EtherNet-IP/OPC-UA/DNP3/…) target a
  listener in the *other* site, routed via the local Socket's gateway so the
  flow traverses the WAN and appears as genuine inter-site OT traffic.
  `cross_site_ratio` (default 0.6) tunes how much crosses vs stays local.

With one `[network]` block (or one `[site:*]`) it runs exactly as before —
single-site behavior is unchanged.

## Layout

```
/opt/iotad/
  iotad.py          the daemon
  build_catalog.py  filters the IEEE registry -> catalog.json
  catalog.json      generated: 53 profiles, ~262 authentic OUIs
  oui.csv           IEEE OUI registry (refreshable)
  iotad.conf        sample config (installed to /etc/iotad.conf)
  iotad.service     systemd unit
  requirements.txt  Python runtime dependency
  tests/             protocol/config regression tests
  venv/             python venv with scapy
/etc/iotad.conf     active config
```

## Configure

Edit `/etc/iotad.conf`. The important knobs:

- `interface` — NIC to transmit on (default `enp10s0`).
- `subnet` / `ip_pool_start` / `ip_pool_end` — the address space the fake
  devices occupy. **Keep the pool clear of real hosts and outside your DHCP
  scope** so nothing collides.
- `device_count` — roster size (default 150; must fit the IP pool).
- `seed` — same seed ⇒ identical roster across restarts, so the Cato inventory
  stays stable. Change it to reshuffle vendors/MACs/IPs.
- `facility` — population preset: `mixed`, `industrial`, `manufacturing`,
  `cleanroom`, `medical`, `water`, or `building`.
- `scenario` — cadence preset: `baseline`, `commissioning`, `production`,
  `maintenance`, or `incident`; `max_pps` remains the hard safety ceiling.
- `categories` — blank for the full mix, or a comma-separated subset.
  Explicit categories override the facility preset.
- `[outbound] scope` — `subnet` (LAN + broadcast only), `wan` (also reach the
  internet), or `both`. WAN frames use spoofed source IPs and may be dropped by
  BCP38/uRPF upstream — expected and harmless for discovery.
- `max_pps` — global frames/second ceiling (default 50).

## Run

```sh
# inspect the roster without sending anything
/opt/iotad/venv/bin/python /opt/iotad/iotad.py --list

# build + schedule + print every frame, but never transmit
/opt/iotad/venv/bin/python /opt/iotad/iotad.py --dry-run --once

# create a safe offline packet capture for Wireshark/tshark inspection
/opt/iotad/venv/bin/python /opt/iotad/iotad.py --once --pcap /tmp/iotad.pcap

# emit exactly one pass of every beacon, then exit (on-wire smoke test)
sudo /opt/iotad/venv/bin/python /opt/iotad/iotad.py --once

# run under systemd (continuous)
sudo systemctl enable --now iotad
journalctl -u iotad -f
```

Run the regression suite:

```sh
cd /opt/iotad
venv/bin/python -m unittest discover -s tests -v
```

Verify it on the wire from another host or the same box:

```sh
sudo tcpdump -i enp10s0 -nn -e 'arp or port 5353 or port 47808 or ether proto 0x88cc'
```

## Refresh the OUI database

The vendor prefixes come from IEEE, so they stay authentic. To update or add
vendors, edit the `PROFILES` list in `build_catalog.py`, then:

```sh
curl -so /opt/iotad/oui.csv https://standards-oui.ieee.org/oui/oui.csv
/opt/iotad/venv/bin/python /opt/iotad/build_catalog.py
sudo systemctl restart iotad
```

## Notes & limitations

- **Emitter + responder.** It advertises devices (ARP/DHCP/mDNS/LLDP/etc.),
  originates flows, **and** answers liveness/fingerprint probes — ARP, ICMP,
  open-port TCP, HTTP auth-challenge, SNMP walk (system/IF-MIB/Printer-MIB), and
  the application-layer identity protocols (Modbus device-ID, EtherNet/IP List
  Identity, ONVIF/WS-Discovery, mDNS, UPnP) — see *Active responders* above. It
  still assigns no IPs to the host; it answers on the wire as the spoofed device
  MAC. It emulates the **identity/fingerprint** surface, not full device
  function: there is no real web UI to log into and no live Modbus register file
  — enough to discover and classify, not to operate.
- Outbound WAN check-ins are fire-and-forget: return traffic can't route back
  to a spoofed source IP, so handshakes never complete. They still generate the
  outbound request a discovery engine fingerprints.
- Switch **port security / sticky MAC / DHCP snooping** may rate-limit or drop
  many source MACs from one physical port. If devices don't appear, check the
  switchport config.
