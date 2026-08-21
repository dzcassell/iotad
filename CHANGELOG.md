# Changelog

All notable changes to iotad are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned

- Additional protocol conformance tests using Wireshark/tshark dissectors.
- VLAN and network-zone modeling.
- Additional industrial protocols and facility scenarios.

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
