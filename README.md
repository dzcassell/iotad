# iotad — IoT/OT traffic simulation daemon

[![Release](https://img.shields.io/github/v/release/dzcassell/iotad)](https://github.com/dzcassell/iotad/releases/latest)
[![CI](https://github.com/dzcassell/iotad/actions/workflows/ci.yml/badge.svg)](https://github.com/dzcassell/iotad/actions/workflows/ci.yml)

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
| Industrial IoT gateways | Huawei | MQTT, LLDP, cloud DNS/TLS, suspicious geo-beacon preference |
| Lighting | Lutron | mDNS, DHCP |
| Clean-room systems | Siemens FFU controllers, gas/environment monitors | PROFINET, Modbus, BACnet, SNMP |
| Process utilities | RO/DI skids, process instruments, VFDs | Modbus, OPC UA, HART-IP, EtherNet/IP |
| Manufacturing | ABB robot controllers, Rockwell safety controllers | PROFINET, OPC UA, CIP Safety |
| Medical / clinical | Philips monitors, GE imaging workstations | DICOM, HL7 MLLP, DNS/TLS |
| Smart facilities | KNX/IP gateways, MQTT/Sparkplug gateways, CoAP sensors | KNXnet/IP, MQTT, Sparkplug B, CoAP |
| Manufacturing gateways | MTConnect cell gateways | HTTP/XML MTConnect, MQTT |
| Electrical substations | ABB RTUs and protection relays | IEC 61850 MMS, IEC-104, DNP3 |

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

Additional modern telemetry includes MQTT with Sparkplug-style topics, CoAP
sensor reads, KNXnet/IP discovery, IEC 61850 MMS initiation, and MTConnect XML.

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
  catalog.json      generated: 66 profiles, 348 authentic OUIs
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
  `cleanroom`, `medical`, `water`, `building`, `pharma_cleanroom`, `hospital`,
  `automotive`, or `water_treatment`. Named facility presets use weighted
  populations so the roster resembles the selected environment.
- `scenario` — cadence preset: `baseline`, `commissioning`, `production`,
  `maintenance`, or `incident`; `max_pps` remains the hard safety ceiling.
- `events_enabled` — enables low-rate shift, maintenance, alarm,
  environmental-excursion, firmware, and failure events.
- `categories` — blank for the full mix, or a comma-separated subset.
  Explicit categories override the facility preset.
- `[outbound] scope` — `subnet` (LAN + broadcast only), `wan` (also reach the
  internet), or `both`. WAN frames use spoofed source IPs and may be dropped by
  BCP38/uRPF upstream — expected and harmless for discovery.
- `max_pps` — global frames/second ceiling (default 50).
- Per-site `zone` labels appear in metrics. Per-site `vlan` can be `0` for
  untagged traffic or `1..4094` to insert an 802.1Q tag. Sites sharing one
  interface must use the same VLAN.

### Suspicious traffic mode

`[suspicious] enabled = true` by default. A deterministic 10% of the roster
(including Huawei devices first) emits low-rate, deliberately suspicious WAN
signals. Set `enabled = false` to disable the feature without changing normal
IoT/OT traffic.

- `device_fraction`, `interval`, and the independent `max_pps` ceiling bound
  participation, cadence, and burst rate. The normal `[runtime] max_pps` cap
  still applies to all frames.
- `countries` selects `china`, `iran`, and/or `russia`; the matching
  `*_targets` values are comma-separated IPv4 destinations. Shipped defaults
  are documented public DNS services: AliDNS, Shecan, and Yandex DNS.
- `behaviors` selects `geo_dns`, `dga_dns`, `dns_tunnel`, and/or
  `port_beacon`, plus the indication-oriented behaviors below. DNS behavior
  carries no real or simulated sensitive data. `port_beacon` sends one TCP SYN
  to a port selected from `beacon_ports`; it does not exploit or authenticate.
- Suspicious traffic requires `[outbound] enabled = true` and `scope = wan` or
  `both`. Country, behavior, selected-device, and rate-limit counters appear
  in `/run/iotad/metrics.json`.

For deterministic Cato demo events, configure Internet Firewall or IPS Geo
Restriction rules for these destination countries and enable event tracking.
DNS Protection may also classify the algorithmic or tunnel-shaped queries,
but heuristic verdicts are policy- and traffic-dependent. TLS Inspection is
recommended where relevant. The simulator intentionally does not ship malware,
exploit payloads, known C2 domains, or credentials; use customer-controlled
custom indicators if a guaranteed anti-bot/reputation event is required.

> This mode intentionally sends traffic beyond the lab. Review the destination
> list and policy first. Prefer addresses you control if the lab is used for
> sustained or higher-rate testing.

#### Cato indication-oriented signals

The default behavior list targets these twelve indication IDs. “Targets” means
the simulator produces the described observable; anomaly engines still depend
on account history, baselines, thresholds, policy, retention, and application
identification, so an event is not guaranteed on the first packet.

| Behavior | Generated observable | Target indication IDs |
|---|---|---|
| `long_dns` | TXT query longer than 150 characters to an external resolver | `chaser_long_dns_queries` |
| `nxdomain_dns` | Unique query below the reserved `.invalid` TLD, expected to return NXDOMAIN | `hunt_dns_response_code` |
| `local_domain_dns` | `.local` name sent to an external resolver | `outbound_local_domain_dns_queries` |
| `dyndns_dns` | Repeated per-device query below `duckdns.org` | `hunt_dyndns_traffic`, `hunt_DynamicDNS_dns_traffic` |
| `ftp_transfer` | Complete FTP control session with a simulated `STOR` across sites | `ftp_client_first_time_site_wan`, `ftp_events_anomaly_site` |
| `smb_transfer` | Complete TCP/445 SMB2-signature conversation across sites | `lan_file_transfer_protocols_first_seen`, `lan_file_transfer_protocols_activity` |
| `ssh_low_popularity` | Complete SSH banner exchange between simulated devices across sites | `suspicious_protocol_communication` |
| `ssh_nonstandard` | SSH banner exchange on TCP/2222 across sites | `nonstandard_ports_first_seen_site`, `hunt_abnormal_protocol_use` |

The dynamic-DNS story explicitly requires at least two days according to the
indication description. The simulator excludes blacklist, sinkhole, Emotet,
malware-certificate, PsExec, and rclone indicators because those require live
threat intelligence, real tool fingerprints, or unsafe third-party targets.

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

Validate a generated capture with Scapy and Wireshark dissectors:

```sh
venv/bin/python iotad.py --config /etc/iotad.conf --once --pcap /tmp/iotad.pcap
venv/bin/python scripts/validate_pcap.py /tmp/iotad.pcap
tshark -r /tmp/iotad.pcap -q -z io,phs
```

## Metrics and health

The daemon atomically refreshes `/run/iotad/metrics.json` by default. The JSON
contains uptime, facility/scenario selection, site/zone/VLAN metadata, device
counts, transmitter totals, rate-limit waits, send failures, suspicious traffic
country/behavior totals, and responder counters. `metrics_file` and
`metrics_interval` are configurable under
`[runtime]`.

## Continuous integration

GitHub Actions compiles the code, runs the regression suite, verifies that
`catalog.json` exactly matches `build_catalog.py` plus `oui.csv`, generates and
validates a PCAP, runs tshark protocol analysis, and scans tracked files for
common credential formats.

Verify it on the wire from another host or the same box:

```sh
sudo tcpdump -i enp10s0 -nn -e 'arp or port 5353 or port 47808 or ether proto 0x88cc'
```

## Controlled Remote Port Forwarding endpoint

`endpoint/` contains a hardened lab-only Docker service intended to sit behind
a Cato Remote Port Forwarding rule. The deployed lab defaults give it a real
plant-LAN identity on `enp8s0f0`:

- IP address: `192.168.7.20`
- MAC address: `02:49:4f:54:41:20`
- Gateway: `192.168.7.1`
- Docker network: macvlan `iotad-rpf-plant`

The endpoint listens on TCP 21 (FTP), 22 (SSH), 23 (Telnet), 53 (DNS), 80
(HTTP), 443 (HTTPS), 445 (SMB), and 2222 (nonstandard SSH), plus UDP 53 (DNS)
and 123 (NTP). HTTP exposes `/healthz`, `/beacon`, `/artifact.bin?size=N`, and
a bounded POST upload receiver. Artifact and upload bodies are capped at 1 MiB
by default. All content is synthetic and contains no malware or exploit code.

Deploy or update it from the repository root:

```sh
docker compose -f endpoint/compose.yaml up -d --build
docker compose -f endpoint/compose.yaml ps
docker inspect --format '{{json .State.Health}}' iotad-rpf-endpoint
```

Suggested Cato RPF mappings preserve the application ports:

| External | Internal destination |
|---|---|
| TCP 21, 22, 23, 53, 80, 443, 445, 2222 | Same port on `192.168.7.20` |
| UDP 53, 123 | Same port on `192.168.7.20` |

Use an RPF allow list restricted to the lab's Cato egress addresses. Do not
publish the endpoint to `0.0.0.0/0`. After the allocated RPF public IP is known,
configure iotad campaigns to use that address; do not target the private
`192.168.7.20` address when the objective is to traverse Cato's public edge.

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
