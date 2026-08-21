# Changelog

All notable changes to iotad are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned

- Automated validation from an external probe host on each lab segment.
- Role-aware controller-to-device relationships and production-line topology.
- Additional IEC 61850 services and layer-2 substation traffic.

## [0.4.0] - 2026-08-21

### Added

- Default-on, independently rate-limited suspicious-traffic simulation with
  country-targeted public DNS contact, DGA-like lookups, DNS tunnel-shaped TXT
  queries, and low-rate odd-port TCP SYN beacons.
- Huawei industrial IoT gateway profile with authentic IEEE OUI selection and
  a China target preference for suspicious traffic.
- Suspicious-device, country, behavior, and rate-limit counters in runtime
  metrics.
- Eight safe indication-oriented generators targeting twelve Cato detection
  IDs: long, NXDOMAIN, local-domain, and Dynamic-DNS queries plus complete
  cross-site FTP, SMB, standard SSH, and nonstandard-port SSH conversations.
- Per-indication target and emission counters in runtime metrics.

### Changed

- Large mixed-facility rosters now include every catalog archetype at least
  once, guaranteeing broad protocol coverage while remaining deterministic.

## [0.3.0] - 2026-08-21

### Added

- GitHub Actions CI for compilation, unit tests, catalog reproducibility,
  credential-pattern scanning, PCAP generation, and tshark analysis.
- Scapy-based PCAP protocol-family validator.
- Atomic JSON runtime metrics with transmitter, responder, site, zone, VLAN,
  facility, scenario, and device-population data.
- Optional per-site 802.1Q VLAN tagging and zone labels.
- Weighted pharmaceutical clean-room, hospital, automotive manufacturing, and
  water-treatment facility templates.
- MQTT/Sparkplug-style telemetry, CoAP sensor reads, KNXnet/IP discovery,
  IEC 61850 MMS initiation, and MTConnect HTTP/XML traffic.
- Controlled shift-change, maintenance, alarm, environmental-excursion,
  firmware-update, and device-failure events.
- Additional KNX building gateway and MTConnect manufacturing gateway profiles.

### Changed

- Vendor TLS check-ins now use deterministic TEST-NET destinations while
  retaining realistic DNS queries and SNI, preventing accidental vendor contact
  and eliminating blocking public-DNS resolution.
- Facility presets now use deterministic weighted category populations.
- Expanded catalog and protocol regression coverage.

### Fixed

- Slow or unavailable public DNS blocking `--once` and PCAP generation.
- Metrics reads racing transmitter counter updates.

## [0.2.0] - 2026-08-21

### Added

- Facility population presets for industrial, manufacturing, clean-room,
  medical, water-treatment, and building environments.
- Activity scenarios for baseline, commissioning, production, maintenance,
  and incident traffic patterns.
- Clean-room, process-instrumentation, water-treatment, drive, robotics,
  safety-controller, and medical-device profiles.
- NTP client traffic and TLS ClientHello messages with SNI.
- BACnet I-Am and PROFINET DCP Identify responders.
- Bidirectional, payload-bearing Modbus, S7, OPC UA, DNP3, IEC-104,
  Niagara Fox, MELSEC, HART-IP, CIP Safety, DICOM, and HL7 exchanges.
- Safe offline PCAP generation with the `--pcap` option.
- Automated configuration, catalog, protocol, and cross-site regression tests.
- Explicit Scapy runtime dependency in `requirements.txt`.

### Changed

- Expanded the generated catalog from 53 to 63 profiles and from 18 to 25
  device categories.
- Routed emitter and responder traffic through a shared token-bucket rate
  limiter governed by `runtime.max_pps`.
- Made DNS resolvers configurable per site.
- Completed unsolicited mDNS announcements with PTR, SRV, TXT, and A records.
- Improved configuration parsing, validation, error reporting, documentation,
  and runtime logging.

### Fixed

- Interface-ambiguous gateway MAC resolution on multi-site hosts.
- TCP responder state collisions between virtual devices using the same port.
- Incorrect BER encoding of high-bit SNMP unsigned values.
- Unbounded age of half-open TCP responder state.
- Directed WS-Discovery probes causing every camera to respond.
- Configured DNS resolver values being ignored.
- Responder traffic bypassing the configured packet-rate ceiling.
- Documentation incorrectly describing the daemon as passive-only.

## [0.1.0] - 2026-08-21

### Added

- Initial public import of the IoT/OT traffic simulation daemon.
- Deterministic virtual-device roster using authentic IEEE vendor OUIs.
- IoT/OT discovery emitters, active liveness responders, service
  fingerprinting, multi-site operation, and systemd service configuration.

[Unreleased]: https://github.com/dzcassell/iotad/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/dzcassell/iotad/releases/tag/v0.4.0
