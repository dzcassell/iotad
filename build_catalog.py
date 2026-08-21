#!/usr/bin/env python3
"""build_catalog.py -- resolve authentic vendor OUIs from the IEEE registry.

Reads the IEEE OUI registry CSV (oui.csv) and produces catalog.json: the
device profiles used by iotad, each with a list of REAL, IEEE-assigned MAC
prefixes for that vendor. Building the OUI lists from the registry (instead of
hand-typing them) is what makes the simulated MAC addresses believable to an
asset-discovery product.

    ./build_catalog.py [--csv oui.csv] [--out catalog.json] [--max-ouis N]

Refresh the registry any time with:
    curl -so oui.csv https://standards-oui.ieee.org/oui/oui.csv
"""
import argparse
import csv
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))

# Each profile is a device *archetype*. `vendors` is a list of regexes matched
# against the IEEE "Organization Name" column to harvest that vendor's real
# OUIs. `beacons` names the emitters in iotad.py that this device runs.
#
# Fields consumed by the emitters:
#   dhcp_class  -> DHCP option 60 (vendor class id), a real fingerprint string
#   mdns        -> mDNS service types advertised
#   ssdp_st     -> SSDP/UPnP search target / device type
#   checkin     -> outbound hostnames a real unit phones home to
PROFILES = [
    # ---- physical security / video ----
    dict(id="axis_camera", category="ip_camera", label="Axis network camera",
         vendors=[r"Axis Communications"], host="axis-cam",
         beacons=["garp", "dhcp", "mdns", "ssdp", "dns_checkin", "tls_checkin"],
         dhcp_class="AXIS,Network Camera",
         mdns=["_axis-video._tcp", "_rtsp._tcp", "_http._tcp"],
         ssdp_st="urn:axis-com:service:BasicService:1",
         checkin=["fw.axis.com", "dispatch.axis.com"]),
    dict(id="hikvision_camera", category="ip_camera", label="Hikvision IP camera",
         vendors=[r"Hikvision"], host="hik-ipc",
         beacons=["garp", "dhcp", "mdns", "ssdp", "dns_checkin", "tls_checkin"],
         dhcp_class="Hikvision",
         mdns=["_rtsp._tcp", "_http._tcp"],
         ssdp_st="urn:schemas-upnp-org:device:Basic:1",
         checkin=["litedev.hik-connect.com", "www.hikvisioneurope.com"]),
    dict(id="dahua_camera", category="ip_camera", label="Dahua IP camera",
         vendors=[r"Dahua"], host="dahua-ipc",
         beacons=["garp", "dhcp", "mdns", "ssdp", "dns_checkin"],
         dhcp_class="dahua",
         mdns=["_rtsp._tcp", "_http._tcp", "_dahua._tcp"],
         ssdp_st="urn:schemas-upnp-org:device:Basic:1",
         checkin=["www.easy4ip.com", "p2p.dahuasecurity.com"]),
    dict(id="hanwha_camera", category="ip_camera", label="Hanwha/Samsung camera",
         vendors=[r"Hanwha", r"Samsung Techwin"], host="hanwha-cam",
         beacons=["garp", "dhcp", "mdns", "ssdp"],
         dhcp_class="SAMSUNG-NETWORK-CAMERA",
         mdns=["_rtsp._tcp", "_http._tcp"],
         ssdp_st="urn:schemas-upnp-org:device:Basic:1", checkin=[]),
    dict(id="bosch_camera", category="ip_camera", label="Bosch security camera",
         vendors=[r"Bosch Security"], host="bosch-cam",
         beacons=["garp", "dhcp", "mdns", "ssdp"],
         dhcp_class="Bosch", mdns=["_rtsp._tcp", "_http._tcp"],
         ssdp_st="urn:schemas-upnp-org:device:Basic:1", checkin=[]),
    dict(id="hid_reader", category="access_control", label="HID badge reader/controller",
         vendors=[r"HID Global"], host="hid-edge",
         beacons=["garp", "dhcp", "mdns", "dns_checkin"],
         dhcp_class="HID", mdns=["_http._tcp"], ssdp_st=None,
         checkin=["mercury.hidglobal.com"]),

    # ---- HVAC / building automation ----
    dict(id="jci_bas", category="building_automation", label="Johnson Controls Metasys",
         vendors=[r"Johnson Controls"], host="jci-nae",
         beacons=["garp", "dhcp", "bacnet_whois", "dns_checkin"],
         dhcp_class="JCI-Metasys", mdns=[], ssdp_st=None,
         checkin=["updates.johnsoncontrols.com"]),
    dict(id="honeywell_bas", category="building_automation", label="Honeywell controller",
         vendors=[r"Honeywell"], host="hwl-ctrl",
         beacons=["garp", "dhcp", "bacnet_whois"],
         dhcp_class="Honeywell", mdns=[], ssdp_st=None, checkin=[]),
    dict(id="emerson_hvac", category="hvac", label="Emerson environmental controller",
         vendors=[r"Emerson"], host="emerson-env",
         beacons=["garp", "dhcp", "bacnet_whois"],
         dhcp_class="Emerson", mdns=[], ssdp_st=None, checkin=[]),

    # ---- industrial control / PLCs ----
    dict(id="siemens_plc", category="plc", label="Siemens S7 PLC",
         vendors=[r"SIEMENS AG", r"Siemens (Industrial|AG|Numerical|Building)"],
         host="s7-plc",
         beacons=["garp", "dhcp", "lldp", "s7", "profinet_dcp"],
         dhcp_class="Siemens", mdns=[], ssdp_st=None, checkin=[]),
    dict(id="rockwell_plc", category="plc", label="Rockwell/Allen-Bradley PLC",
         vendors=[r"Rockwell", r"Allen-Bradley"], host="ab-logix",
         beacons=["garp", "dhcp", "lldp", "enip"],
         dhcp_class="Allen-Bradley", mdns=[], ssdp_st=None, checkin=[]),
    dict(id="schneider_plc", category="plc", label="Schneider Modicon PLC",
         vendors=[r"Schneider Electric"], host="modicon",
         beacons=["garp", "dhcp", "lldp", "modbus"],
         dhcp_class="Schneider-Electric", mdns=[], ssdp_st=None, checkin=[]),
    dict(id="beckhoff_plc", category="plc", label="Beckhoff industrial PC",
         vendors=[r"Beckhoff"], host="beckhoff",
         beacons=["garp", "dhcp", "lldp", "modbus"],
         dhcp_class="Beckhoff", mdns=[], ssdp_st=None, checkin=[]),
    dict(id="wago_plc", category="plc", label="WAGO fieldbus controller",
         vendors=[r"WAGO"], host="wago-plc",
         beacons=["garp", "dhcp", "modbus"],
         dhcp_class="WAGO", mdns=[], ssdp_st=None, checkin=[]),
    dict(id="phoenix_io", category="plc", label="Phoenix Contact I/O",
         vendors=[r"Phoenix Contact"], host="phoenix-io",
         beacons=["garp", "dhcp", "lldp", "modbus"],
         dhcp_class="PhoenixContact", mdns=[], ssdp_st=None, checkin=[]),

    # ---- industrial networking / gateways ----
    dict(id="moxa_gw", category="industrial_networking", label="Moxa serial device server",
         vendors=[r"Moxa"], host="moxa-nport",
         beacons=["garp", "dhcp", "lldp"],
         dhcp_class="Moxa", mdns=[], ssdp_st=None, checkin=[]),
    dict(id="advantech_gw", category="industrial_networking", label="Advantech edge gateway",
         vendors=[r"Advantech"], host="advantech",
         beacons=["garp", "dhcp", "lldp", "modbus"],
         dhcp_class="Advantech", mdns=[], ssdp_st=None, checkin=[]),
    dict(id="hirschmann_sw", category="industrial_networking", label="Hirschmann industrial switch",
         vendors=[r"Hirschmann"], host="hirschmann",
         beacons=["garp", "dhcp", "lldp"],
         dhcp_class="Hirschmann", mdns=[], ssdp_st=None, checkin=[]),

    # ---- IT networking ----
    dict(id="ubiquiti_ap", category="networking", label="Ubiquiti access point",
         vendors=[r"Ubiquiti"], host="ubnt-ap",
         beacons=["garp", "dhcp", "lldp", "ubnt_discover", "dns_checkin"],
         dhcp_class="ubnt", mdns=[], ssdp_st=None,
         checkin=["fw-update.ubnt.com"]),
    dict(id="cisco_switch", category="networking", label="Cisco switch",
         vendors=[r"Cisco Systems", r"^Cisco$"], host="cisco-sw",
         beacons=["garp", "dhcp", "lldp", "cdp"],
         dhcp_class="Cisco", mdns=[], ssdp_st=None, checkin=[]),

    # ---- printers / barcode ----
    dict(id="zebra_printer", category="printer", label="Zebra label printer",
         vendors=[r"Zebra Techn"], host="zebra-zt",
         beacons=["garp", "dhcp", "mdns", "snmp"],
         dhcp_class="Zebra",
         mdns=["_printer._tcp", "_pdl-datastream._tcp", "_ipp._tcp"],
         ssdp_st=None, checkin=[]),
    dict(id="hp_mfp", category="printer", label="HP LaserJet/OfficeJet MFP",
         vendors=[r"Hewlett[ -]?Packard", r"\bHP\b", r"HP Inc"], host="hp-laserjet",
         beacons=["garp", "dhcp", "mdns", "snmp", "dns_checkin"],
         dhcp_class="Hewlett-Packard JetDirect",
         mdns=["_printer._tcp", "_ipp._tcp", "_ipps._tcp",
               "_pdl-datastream._tcp", "_uscan._tcp", "_http._tcp", "_privet._tcp"],
         ssdp_st="urn:schemas-upnp-org:device:Printer:1",
         checkin=["www.hpeprint.com", "chat.hpeprint.com", "h20180.www2.hp.com"]),
    dict(id="canon_mfp", category="printer", label="Canon imageRUNNER MFP",
         vendors=[r"Canon"], host="canon-ir",
         beacons=["garp", "dhcp", "mdns", "snmp"],
         dhcp_class="Canon",
         mdns=["_printer._tcp", "_ipp._tcp", "_pdl-datastream._tcp",
               "_scanner._tcp", "_http._tcp"],
         ssdp_st="urn:schemas-upnp-org:device:Printer:1", checkin=[]),
    dict(id="epson_mfp", category="printer", label="Epson WorkForce MFP",
         vendors=[r"Seiko Epson"], host="epson-wf",
         beacons=["garp", "dhcp", "mdns", "snmp", "dns_checkin"],
         dhcp_class="EPSON",
         mdns=["_printer._tcp", "_ipp._tcp", "_ipps._tcp",
               "_pdl-datastream._tcp", "_uscan._tcp", "_scanner._tcp", "_http._tcp"],
         ssdp_st="urn:schemas-upnp-org:device:Printer:1",
         checkin=["epsonconnect.com", "pool.epsonconnect.com"]),
    dict(id="brother_mfp", category="printer", label="Brother MFC printer",
         vendors=[r"Brother"], host="brother-mfc",
         beacons=["garp", "dhcp", "mdns", "snmp"],
         dhcp_class="Brother",
         mdns=["_printer._tcp", "_ipp._tcp", "_pdl-datastream._tcp",
               "_scanner._tcp", "_uscan._tcp", "_http._tcp"],
         ssdp_st="urn:schemas-upnp-org:device:Printer:1", checkin=[]),
    dict(id="xerox_mfp", category="printer", label="Xerox WorkCentre MFP",
         vendors=[r"Xerox"], host="xerox-wc",
         beacons=["garp", "dhcp", "mdns", "snmp"],
         dhcp_class="XEROX",
         mdns=["_printer._tcp", "_ipp._tcp", "_pdl-datastream._tcp", "_http._tcp"],
         ssdp_st="urn:schemas-upnp-org:device:Printer:1", checkin=[]),
    dict(id="lexmark_mfp", category="printer", label="Lexmark laser printer",
         vendors=[r"Lexmark"], host="lexmark",
         beacons=["garp", "dhcp", "mdns", "snmp"],
         dhcp_class="Lexmark",
         mdns=["_printer._tcp", "_ipp._tcp", "_pdl-datastream._tcp", "_http._tcp"],
         ssdp_st="urn:schemas-upnp-org:device:Printer:1", checkin=[]),
    dict(id="ricoh_mfp", category="printer", label="Ricoh Aficio MFP",
         vendors=[r"Ricoh"], host="ricoh-aficio",
         beacons=["garp", "dhcp", "mdns", "snmp"],
         dhcp_class="RICOH",
         mdns=["_printer._tcp", "_ipp._tcp", "_pdl-datastream._tcp",
               "_scanner._tcp", "_http._tcp"],
         ssdp_st="urn:schemas-upnp-org:device:Printer:1", checkin=[]),
    dict(id="konica_mfp", category="printer", label="Konica Minolta bizhub MFP",
         vendors=[r"Konica"], host="km-bizhub",
         beacons=["garp", "dhcp", "mdns", "snmp"],
         dhcp_class="KONICA MINOLTA",
         mdns=["_printer._tcp", "_ipp._tcp", "_pdl-datastream._tcp",
               "_scanner._tcp", "_http._tcp"],
         ssdp_st="urn:schemas-upnp-org:device:Printer:1", checkin=[]),

    # ---- AV / room control ----
    dict(id="crestron_av", category="av", label="Crestron control processor",
         vendors=[r"Crestron"], host="crestron",
         beacons=["garp", "dhcp", "mdns", "ssdp"],
         dhcp_class="Crestron",
         mdns=["_crestron._tcp", "_http._tcp"],
         ssdp_st="urn:schemas-upnp-org:device:Basic:1", checkin=[]),

    # ---- power / UPS ----
    dict(id="apc_ups", category="power", label="APC network UPS",
         vendors=[r"American Power Conversion"], host="apc-ups",
         beacons=["garp", "dhcp", "snmp"],
         dhcp_class="APC", mdns=[], ssdp_st=None, checkin=[]),
    dict(id="liebert_ups", category="power", label="Vertiv/Liebert power unit",
         vendors=[r"Liebert", r"Vertiv"], host="liebert",
         beacons=["garp", "dhcp", "snmp"],
         dhcp_class="Liebert", mdns=[], ssdp_st=None, checkin=[]),

    # ---- lighting ----
    dict(id="lutron_lighting", category="lighting", label="Lutron lighting processor",
         vendors=[r"Lutron"], host="lutron",
         beacons=["garp", "dhcp", "mdns"],
         dhcp_class="Lutron", mdns=["_lutron._tcp", "_http._tcp"],
         ssdp_st=None, checkin=[]),

    # ---- VoIP phones (LLDP-MED voice endpoints) ----
    dict(id="cisco_phone", category="voip", label="Cisco IP phone",
         vendors=[r"Cisco Systems"], host="cisco-sep",
         beacons=["garp", "dhcp", "lldp", "cdp"], lldp_med="voice",
         dhcp_class="Cisco Systems, Inc. IP Phone CP-8841",
         mdns=[], ssdp_st=None, checkin=[]),
    dict(id="polycom_phone", category="voip", label="Poly/Polycom VVX phone",
         vendors=[r"Polycom"], host="polycom-vvx",
         beacons=["garp", "dhcp", "lldp"], lldp_med="voice",
         dhcp_class="Polycom-VVX411",
         mdns=[], ssdp_st=None, checkin=[]),
    dict(id="yealink_phone", category="voip", label="Yealink SIP phone",
         vendors=[r"Yealink"], host="yealink-t46",
         beacons=["garp", "dhcp", "lldp"], lldp_med="voice",
         dhcp_class="yealink",
         mdns=[], ssdp_st=None, checkin=[]),
    dict(id="avaya_phone", category="voip", label="Avaya IP phone",
         vendors=[r"Avaya"], host="avaya-j179",
         beacons=["garp", "dhcp", "lldp"], lldp_med="voice",
         dhcp_class="ccp.avaya.com",
         mdns=[], ssdp_st=None, checkin=[]),

    # ---- HMIs / operator panels ----
    dict(id="siemens_hmi", category="hmi", label="Siemens SIMATIC HMI panel",
         vendors=[r"Siemens"], host="simatic-hmi",
         beacons=["garp", "dhcp", "lldp", "s7", "profinet_dcp"],
         dhcp_class="Siemens", mdns=[], ssdp_st=None, checkin=[]),
    dict(id="rockwell_hmi", category="hmi", label="Rockwell PanelView HMI",
         vendors=[r"Rockwell"], host="panelview",
         beacons=["garp", "dhcp", "lldp", "enip"],
         dhcp_class="Allen-Bradley", mdns=[], ssdp_st=None, checkin=[]),

    # ---- NVR / DVR video recorders ----
    dict(id="hikvision_nvr", category="nvr", label="Hikvision NVR",
         vendors=[r"Hangzhou Hikvision"], host="hik-nvr",
         beacons=["garp", "dhcp", "mdns", "ssdp", "dns_checkin"],
         dhcp_class="Hikvision",
         mdns=["_http._tcp", "_rtsp._tcp"],
         ssdp_st="urn:schemas-upnp-org:device:Basic:1",
         checkin=["litedev.hik-connect.com"]),
    dict(id="synology_nvr", category="nvr", label="Synology Surveillance NVR",
         vendors=[r"Synology"], host="synology-nvr",
         beacons=["garp", "dhcp", "mdns", "ssdp"],
         dhcp_class="",
         mdns=["_http._tcp", "_smb._tcp"],
         ssdp_st="urn:schemas-upnp-org:device:Basic:1", checkin=[]),

    # ---- environmental / rack sensors ----
    dict(id="apc_netbotz", category="environmental", label="APC NetBotz rack sensor",
         vendors=[r"American Power Conversion", r"NetBotz"], host="netbotz",
         beacons=["garp", "dhcp", "snmp", "mdns"],
         dhcp_class="APC",
         mdns=["_http._tcp"], ssdp_st=None, checkin=[]),
    dict(id="akcp_sensor", category="environmental", label="AKCP sensorProbe monitor",
         vendors=[r"AKCP"], host="akcp-sp",
         beacons=["garp", "dhcp", "snmp", "mdns"],
         dhcp_class="", mdns=["_http._tcp"], ssdp_st=None, checkin=[]),
    dict(id="sensaphone_env", category="environmental", label="Sensaphone monitor",
         vendors=[r"Sensaphone"], host="sensaphone",
         beacons=["garp", "dhcp", "snmp"],
         dhcp_class="", mdns=[], ssdp_st=None, checkin=[]),

    # ---- IP intercom / door stations ----
    dict(id="twon_intercom", category="intercom", label="2N IP intercom/door station",
         vendors=[r"2N TELEKOMUNIKACE", r"2N Telekomunikace"], host="2n-intercom",
         beacons=["garp", "dhcp", "mdns", "ssdp"],
         dhcp_class="2N",
         mdns=["_http._tcp", "_sip._udp"],
         ssdp_st="urn:schemas-upnp-org:device:Basic:1", checkin=[]),
    dict(id="aiphone_intercom", category="intercom", label="Aiphone IX door station",
         vendors=[r"Aiphone"], host="aiphone-ix",
         beacons=["garp", "dhcp", "mdns", "ssdp"],
         dhcp_class="",
         mdns=["_http._tcp"], ssdp_st="urn:schemas-upnp-org:device:Basic:1",
         checkin=[]),

    # ---- wireless / IoT gateways ----
    dict(id="multitech_lora", category="iot_gateway", label="MultiTech LoRaWAN gateway",
         vendors=[r"Multi-Tech Systems", r"MultiTech"], host="mtcdt-lora",
         beacons=["garp", "dhcp", "mdns", "dns_checkin", "tls_checkin"],
         dhcp_class="",
         mdns=["_http._tcp", "_ssh._tcp"],
         ssdp_st=None, checkin=["updates.multitech.net"]),

    # ---- OPC UA (modern industrial) ----
    dict(id="br_plc", category="plc", label="B&R industrial controller",
         vendors=[r"B&R Industrial", r"Bernecker"], host="br-x20",
         beacons=["garp", "dhcp", "lldp", "opcua", "profinet_dcp"],
         dhcp_class="",
         mdns=["_opcua-tcp._tcp"], ssdp_st=None, checkin=[]),

    # ---- DNP3 / SCADA RTUs & relays ----
    dict(id="sel_rtu", category="rtu", label="SEL protection relay/RTU",
         vendors=[r"Schweitzer"], host="sel-relay",
         beacons=["garp", "dhcp", "dnp3"],
         dhcp_class="", mdns=[], ssdp_st=None, checkin=[]),
    dict(id="abb_rtu", category="rtu", label="ABB substation RTU",
         vendors=[r"^ABB", r"ABB "], host="abb-rtu",
         beacons=["garp", "dhcp", "lldp", "iec104"],
         dhcp_class="", mdns=[], ssdp_st=None, checkin=[]),

    # ---- Niagara Fox / Tridium building controllers ----
    dict(id="tridium_jace", category="building_automation", label="Tridium JACE controller",
         vendors=[r"Tridium"], host="jace",
         beacons=["garp", "dhcp", "fox", "bacnet_whois", "dns_checkin"],
         dhcp_class="niagara",
         mdns=[], ssdp_st=None, checkin=["accounts.niagara-community.com"]),

    # ---- additional PLC vendors (FINS / MELSEC) ----
    dict(id="omron_plc", category="plc", label="Omron PLC",
         vendors=[r"OMRON", r"Omron"], host="omron-nx",
         beacons=["garp", "dhcp", "lldp", "fins", "modbus"],
         dhcp_class="", mdns=[], ssdp_st=None, checkin=[]),
    dict(id="mitsubishi_plc", category="plc", label="Mitsubishi MELSEC PLC",
         vendors=[r"MITSUBISHI ELECTRIC", r"Mitsubishi Electric"], host="melsec-q",
         beacons=["garp", "dhcp", "lldp", "melsec"],
         dhcp_class="", mdns=[], ssdp_st=None, checkin=[]),

    # ---- clean-room / environmental control ----
    dict(id="pms_particle", category="cleanroom",
         label="Particle Measuring Systems airborne particle counter",
         vendors=[r"PARTICLE MEASURING SYSTEMS"], host="particle-ctr",
         beacons=["garp", "dhcp", "modbus", "bacnet_whois", "snmp"],
         dhcp_class="", mdns=["_http._tcp"], ssdp_st=None, checkin=[]),
    dict(id="siemens_ffu", category="cleanroom", label="Siemens fan-filter-unit controller",
         vendors=[r"Siemens"], host="ffu-ctrl",
         beacons=["garp", "dhcp", "lldp", "profinet_dcp", "modbus"],
         dhcp_class="", mdns=[], ssdp_st=None, checkin=[]),
    dict(id="honeywell_gas", category="environmental", label="Honeywell gas detector",
         vendors=[r"Honeywell"], host="gas-det",
         beacons=["garp", "dhcp", "modbus", "snmp"],
         dhcp_class="", mdns=[], ssdp_st=None, checkin=[]),

    # ---- process utilities / filtration ----
    dict(id="eandh_instrument", category="instrumentation",
         label="Endress+Hauser process instrument",
         vendors=[r"Endress.*Hauser"], host="process-xmtr",
         beacons=["garp", "dhcp", "modbus", "hartip"],
         dhcp_class="", mdns=[], ssdp_st=None, checkin=[]),
    dict(id="schneider_ro_skid", category="water_treatment",
         label="Schneider RO/DI filtration skid controller",
         vendors=[r"Schneider Electric"], host="ro-skid",
         beacons=["garp", "dhcp", "modbus", "opcua"],
         dhcp_class="", mdns=["_opcua-tcp._tcp"], ssdp_st=None, checkin=[]),
    dict(id="danfoss_vfd", category="drive", label="Danfoss variable-frequency drive",
         vendors=[r"Danfoss"], host="vfd",
         beacons=["garp", "dhcp", "lldp", "modbus", "enip"],
         dhcp_class="", mdns=[], ssdp_st=None, checkin=[]),

    # ---- manufacturing floor ----
    dict(id="abb_robot", category="robotics", label="ABB industrial robot controller",
         vendors=[r"^ABB", r"ABB "], host="robot-ctrl",
         beacons=["garp", "dhcp", "lldp", "profinet_dcp", "opcua"],
         dhcp_class="", mdns=["_opcua-tcp._tcp"], ssdp_st=None, checkin=[]),
    dict(id="rockwell_safety", category="safety", label="Rockwell safety controller",
         vendors=[r"Rockwell Automation"], host="safety-plc",
         beacons=["garp", "dhcp", "lldp", "enip", "cip_safety"],
         dhcp_class="", mdns=[], ssdp_st=None, checkin=[]),

    # ---- clinical / medical facility ----
    dict(id="philips_monitor", category="medical", label="Philips patient monitor",
         vendors=[r"Philips"], host="patient-mon",
         beacons=["garp", "dhcp", "mdns", "dicom", "hl7", "dns_checkin", "tls_checkin"],
         dhcp_class="", mdns=["_http._tcp"], ssdp_st=None,
         checkin=["devicecloud.philips.com"]),
    dict(id="ge_imaging", category="medical", label="GE medical imaging workstation",
         vendors=[r"General Electric", r"GE Healthcare"], host="dicom-ws",
         beacons=["garp", "dhcp", "dicom", "hl7", "dns_checkin"],
         dhcp_class="", mdns=[], ssdp_st=None, checkin=["gehealthcare.com"]),
]


# ---- service identity ------------------------------------------------------
# A device that SPEAKS a protocol also LISTENS on its port, so we derive the
# open-port set from the profile's own beacons/mDNS services rather than
# hand-listing it. The responder answers SYN on these ports (SYN-ACK), which is
# what an asset-discovery scan fingerprints as "device type X".
PROTO_TCP_PORT = {
    "modbus": 502, "s7": 102, "enip": 44818, "opcua": 4840,
    "dnp3": 20000, "fox": 1911, "iec104": 2404, "melsec": 5007,
    "hartip": 5094, "cip_safety": 44818, "dicom": 11112, "hl7": 2575,
}
MDNS_TCP_PORT = {
    "_http._tcp": 80, "_https._tcp": 443, "_rtsp._tcp": 554,
    "_ipp._tcp": 631, "_ipps._tcp": 631, "_pdl-datastream._tcp": 9100,
    "_printer._tcp": 9100, "_smb._tcp": 445, "_ssh._tcp": 22,
    "_axis-video._tcp": 80,
}
# Baseline management ports each category exposes even without a matching beacon.
CATEGORY_BASE_PORTS = {
    "ip_camera": [80, 554, 443], "nvr": [80, 554, 443],
    "access_control": [80, 443], "intercom": [80, 443],
    "hvac": [80], "building_automation": [80, 443], "plc": [80],
    "rtu": [], "hmi": [80], "industrial_networking": [80, 443],
    "networking": [22, 80, 443], "printer": [80, 9100, 631],
    "av": [80], "power": [80], "environmental": [80],
    "lighting": [80], "voip": [80, 443], "iot_gateway": [22, 80, 443],
    "cleanroom": [80, 502], "instrumentation": [80, 502],
    "water_treatment": [80, 502], "drive": [80, 502],
    "robotics": [80, 4840], "safety": [80, 44818], "medical": [80, 443],
}
# HTTP Server: header the device's web UI returns (embedded-web-server flavored).
HTTP_BANNER = {
    "axis_camera": "gSOAP/2.8", "hikvision_camera": "Hikvision-Webs",
    "hikvision_nvr": "Hikvision-Webs", "dahua_camera": "Boa/0.94.14rc21",
    "hanwha_camera": "iDVR", "bosch_camera": "VideoJet",
    "hp_mfp": "HP HTTP Server", "canon_mfp": "CANON HTTP Server",
    "epson_mfp": "EPSON-HTTP/1.0", "brother_mfp": "debut/1.20",
    "xerox_mfp": "Xerox_MicroServer", "lexmark_mfp": "Lexmark Web Server",
    "ricoh_mfp": "Web-Server/3.0", "konica_mfp": "KM-MFP-Http/1.0",
    "zebra_printer": "Zebra/1.0", "apc_ups": "Aais/1.0",
    "liebert_ups": "Liebert-Web", "apc_netbotz": "NetBotz/1.0",
    "cisco_switch": "cisco-IOS", "ubiquiti_ap": "lighttpd",
}
CATEGORY_HTTP_DEFAULT = {
    "ip_camera": "Boa/0.94.14rc21", "nvr": "Boa/0.94.14rc21",
    "printer": "GoAhead-Webs", "plc": "GoAhead-Webs", "hmi": "GoAhead-Webs",
    "rtu": "GoAhead-Webs", "building_automation": "GoAhead-Webs",
    "networking": "lighttpd", "power": "GoAhead-Webs",
    "environmental": "GoAhead-Webs", "voip": "Allegro-Software-RomPager/4.0",
    "cleanroom": "GoAhead-Webs", "instrumentation": "GoAhead-Webs",
    "water_treatment": "GoAhead-Webs", "drive": "GoAhead-Webs",
    "robotics": "GoAhead-Webs", "safety": "GoAhead-Webs", "medical": "nginx",
}
# HTTP auth challenge: an embedded device's web UI answers "/" with 401 +
# WWW-Authenticate, and the realm string is a routinely-scanned fingerprint.
# Kept generic per device class (not asserting a specific unit's realm) -- the
# same honesty rule as SNMP sysDescr. (auth-scheme, realm). Cameras favour
# Digest; most management UIs use Basic.
HTTP_REALM_VENDOR = {
    "axis_camera": ("Digest", "AXIS Video Server"),
    "hikvision_camera": ("Digest", "Network Camera"),
    "hikvision_nvr": ("Digest", "Network Video Recorder"),
    "dahua_camera": ("Digest", "Login to camera"),
    "hanwha_camera": ("Digest", "iPolis"),
    "bosch_camera": ("Digest", "Bosch Security Camera"),
    "hp_mfp": ("Basic", "HP LaserJet"),
    "canon_mfp": ("Basic", "Canon Remote UI"),
    "xerox_mfp": ("Basic", "Xerox WebUI"),
    "zebra_printer": ("Basic", "Zebra Printer"),
    "apc_ups": ("Basic", "APC Management Card"),
    "liebert_ups": ("Basic", "Liebert Web Card"),
    "cisco_switch": ("Basic", "level_15_access"),
    "ubiquiti_ap": ("Basic", "UniFi"),
}
CATEGORY_HTTP_REALM = {
    "ip_camera": ("Digest", "Network Camera"),
    "nvr": ("Digest", "Network Video Recorder"),
    "access_control": ("Basic", "Access Controller"),
    "intercom": ("Digest", "Door Station"),
    "printer": ("Basic", "Printer"),
    "plc": ("Basic", "Controller"),
    "hmi": ("Basic", "Operator Panel"),
    "rtu": ("Basic", "RTU"),
    "building_automation": ("Basic", "Building Controller"),
    "industrial_networking": ("Basic", "Managed Switch"),
    "networking": ("Basic", "Managed Switch"),
    "power": ("Basic", "Management Card"),
    "environmental": ("Basic", "Monitoring Appliance"),
    "voip": ("Basic", "Phone"),
    "iot_gateway": ("Basic", "Gateway"),
    "av": ("Basic", "Control System"),
    "lighting": ("Basic", "Lighting Controller"),
    "cleanroom": ("Basic", "Environmental Monitor"),
    "instrumentation": ("Basic", "Process Instrument"),
    "water_treatment": ("Basic", "Skid Controller"),
    "drive": ("Basic", "Drive Controller"),
    "robotics": ("Basic", "Robot Controller"),
    "safety": ("Basic", "Safety Controller"),
    "medical": ("Basic", "Clinical Device"),
}
# SNMP sysDescr: the single richest fingerprint field. Real device-class strings
# (not impersonating a specific unit's identity). {label} = the profile label.
SNMP_DESCR = {
    "printer": "{label}; firmware NB.2, embedded print server",
    "ip_camera": "{label}, Linux embedded, IP surveillance",
    "nvr": "{label}, network video recorder",
    "power": "{label}, network management card",
    "environmental": "{label}, environmental monitoring appliance",
    "networking": "{label}, managed switch",
    "industrial_networking": "{label}, industrial ethernet",
    "plc": "{label}, programmable controller",
    "hmi": "{label}, operator interface",
    "building_automation": "{label}, building controller",
    "rtu": "{label}, remote terminal unit",
    "cleanroom": "{label}, clean-room environmental control",
    "instrumentation": "{label}, process instrumentation",
    "water_treatment": "{label}, process skid controller",
    "drive": "{label}, motor drive",
    "robotics": "{label}, robot controller",
    "safety": "{label}, safety controller",
    "medical": "{label}, networked clinical device",
}
# Enterprise PEN (1.3.6.1.4.1.<PEN>) only where confidently known; otherwise the
# responder returns 0.0 ("unknown") rather than risk a misclassifying OID.
VENDOR_PEN = {
    "cisco_switch": 9, "hp_mfp": 11, "apc_ups": 318, "apc_netbotz": 5528,
    "axis_camera": 368, "zebra_printer": 10642, "liebert_ups": 476,
}
SNMP_CATEGORIES = set(SNMP_DESCR)  # which categories answer SNMP at all

# Vendor display name for the identity responders (EtherNet/IP List Identity,
# Modbus device-ID object 0, UPnP description, WS-Discovery scopes). Authentic
# vendor names -- NOT a specific unit's identity; the product string stays the
# device-class label, same honesty rule as SNMP sysDescr.
IDENTITY_VENDOR = {
    "axis_camera": "Axis Communications", "hikvision_camera": "Hikvision",
    "hikvision_nvr": "Hikvision", "dahua_camera": "Dahua Technology",
    "hanwha_camera": "Hanwha Techwin", "bosch_camera": "Bosch Security Systems",
    "hid_reader": "HID Global", "jci_bas": "Johnson Controls",
    "honeywell_bas": "Honeywell", "emerson_hvac": "Emerson",
    "siemens_plc": "Siemens", "siemens_hmi": "Siemens",
    "rockwell_plc": "Rockwell Automation", "rockwell_hmi": "Rockwell Automation",
    "schneider_plc": "Schneider Electric", "beckhoff_plc": "Beckhoff Automation",
    "wago_plc": "WAGO", "phoenix_io": "Phoenix Contact", "moxa_gw": "Moxa",
    "advantech_gw": "Advantech", "hirschmann_sw": "Hirschmann (Belden)",
    "ubiquiti_ap": "Ubiquiti", "cisco_switch": "Cisco Systems",
    "cisco_phone": "Cisco Systems", "zebra_printer": "Zebra Technologies",
    "hp_mfp": "HP", "canon_mfp": "Canon", "epson_mfp": "Seiko Epson",
    "brother_mfp": "Brother", "xerox_mfp": "Xerox", "lexmark_mfp": "Lexmark",
    "ricoh_mfp": "Ricoh", "konica_mfp": "Konica Minolta", "crestron_av": "Crestron",
    "apc_ups": "APC (Schneider Electric)", "apc_netbotz": "APC (Schneider Electric)",
    "liebert_ups": "Vertiv", "lutron_lighting": "Lutron",
    "polycom_phone": "Poly", "yealink_phone": "Yealink", "avaya_phone": "Avaya",
    "synology_nvr": "Synology", "akcp_sensor": "AKCP", "sensaphone_env": "Sensaphone",
    "twon_intercom": "2N (Axis)", "aiphone_intercom": "Aiphone",
    "multitech_lora": "MultiTech", "br_plc": "B&R Industrial Automation",
    "sel_rtu": "Schweitzer Engineering Laboratories", "abb_rtu": "ABB",
    "tridium_jace": "Tridium", "omron_plc": "Omron",
    "mitsubishi_plc": "Mitsubishi Electric",
}
# Real ODVA CIP vendor IDs -- only where confidently known; otherwise 0
# ("unknown"), exactly like the SNMP enterprise PEN, so we never misclassify.
CIP_VENDOR_ID = {"rockwell_plc": 1, "rockwell_hmi": 1}
# ASHRAE BACnet vendor IDs -- only the ones we're confident of; others -> 0.
BACNET_VENDOR_ID = {"jci_bas": 5, "honeywell_bas": 17}
# PROFINET vendor IDs (IEC 61158) -- Siemens = 0x002A; others left 0.
PN_VENDOR_ID = {"siemens_plc": 0x002A, "siemens_hmi": 0x002A}


def _stable(key, mod, base=0):
    """Deterministic small int from a string (FNV-1a) -- stable across rebuilds,
    so a profile's revision/product-code doesn't churn every time we regenerate."""
    h = 2166136261
    for c in key:
        h = ((h ^ ord(c)) * 16777619) & 0xFFFFFFFF
    return base + (h % mod)


def enrich(p):
    """Attach responder identity: open TCP ports, HTTP banner, SNMP profile."""
    p["beacons"] = list(p.get("beacons", []))
    if "ntp" not in p["beacons"]:
        p["beacons"].append("ntp")
    ports = set(CATEGORY_BASE_PORTS.get(p["category"], [80]))
    for b in p.get("beacons", []):
        if b in PROTO_TCP_PORT:
            ports.add(PROTO_TCP_PORT[b])
    for svc in p.get("mdns", []):
        if svc in MDNS_TCP_PORT:
            ports.add(MDNS_TCP_PORT[svc])
    p["ports"] = sorted(ports)
    if 80 in ports or 443 in ports or 8080 in ports:
        p["http_server"] = HTTP_BANNER.get(
            p["id"], CATEGORY_HTTP_DEFAULT.get(p["category"], "lighttpd"))
        auth = HTTP_REALM_VENDOR.get(p["id"]) or CATEGORY_HTTP_REALM.get(p["category"])
        if auth:
            p["http_auth"], p["http_realm"] = auth
    if p["category"] in SNMP_CATEGORIES:
        p["snmp"] = {
            "descr": SNMP_DESCR[p["category"]].format(label=p["label"]),
            "pen": VENDOR_PEN.get(p["id"], 0),
        }

    # -- cross-protocol identity (consistent vendor/model/revision everywhere) --
    beacons = p.get("beacons", [])
    vendor = IDENTITY_VENDOR.get(p["id"]) or p["label"].split(",")[0].split()[0]
    rmaj, rmin = 1 + _stable(p["id"], 6), _stable(p["id"] + "min", 40)
    rev = "%d.%d" % (rmaj, rmin)
    p["identity"] = {"vendor": vendor, "product": p["label"], "revision": rev}
    # EtherNet/IP List Identity (device answers on 44818 only if it emits enip).
    if "enip" in beacons:
        p["cip"] = {
            "vendor_id": CIP_VENDOR_ID.get(p["id"], 0),  # 0 = unknown, not asserted
            "device_type": 0,           # generic; vendor_id + product name classify
            "product_code": 1 + _stable(p["id"] + "pc", 500),
            "rev_major": rmaj, "rev_minor": rmin,
        }
    # Modbus Read Device Identification (FC 43/14) responder.
    if "modbus" in beacons:
        p["modbus_id"] = {"vendor": vendor, "product": p["label"], "revision": rev}
    # ONVIF/WS-Discovery -- the camera discovery path.
    if p["category"] == "ip_camera":
        p["ws_discovery"] = "NetworkVideoTransmitter"
    # BACnet I-Am (device answers Who-Is). device_id is an instance number
    # (0..0x3FFFFF), not a vendor claim -- seeded stable per profile.
    if "bacnet_whois" in beacons:
        p["bacnet"] = {"vendor_id": BACNET_VENDOR_ID.get(p["id"], 0),
                       "device_id": _stable(p["id"] + "bdev", 0x3FFFFF)}
    # PROFINET DCP Identify response (station name = hostname at runtime).
    if "profinet_dcp" in beacons:
        p["profinet"] = {"vendor_id": PN_VENDOR_ID.get(p["id"], 0),
                         "device_id": 1 + _stable(p["id"] + "pdev", 0xFFFE),
                         "role": 0x01}          # 0x01 = IO-Device
    return p


def norm_oui(hexstr):
    h = hexstr.strip().upper()
    return ":".join(h[i:i + 2] for i in range(0, 6, 2))


def build(csv_path, max_ouis):
    rows = []
    with open(csv_path, newline="", encoding="utf-8", errors="replace") as f:
        for r in csv.DictReader(f):
            org = (r.get("Organization Name") or "").strip()
            asn = (r.get("Assignment") or "").strip()
            if len(asn) == 6 and org:
                rows.append((asn, org))

    catalog = []
    total_ouis = 0
    for p in PROFILES:
        pats = [re.compile(v, re.I) for v in p["vendors"]]
        found = []
        seen = set()
        for asn, org in rows:
            if any(pat.search(org) for pat in pats):
                oui = norm_oui(asn)
                if oui not in seen:
                    seen.add(oui)
                    found.append(oui)
        if not found:
            print(f"  WARNING: no OUIs matched for {p['id']} "
                  f"({p['vendors']})", file=sys.stderr)
            continue
        entry = enrich(dict(p))
        entry["vendors_matched"] = len(found)
        entry["ouis"] = found[:max_ouis]
        catalog.append(entry)
        total_ouis += len(entry["ouis"])
        print(f"  {p['id']:<20} {len(entry['ouis']):>2} OUIs "
              f"(of {len(found)} assigned)  e.g. {entry['ouis'][0]}")
    return catalog, total_ouis


def main():
    ap = argparse.ArgumentParser(description="Build iotad device catalog from IEEE OUI registry")
    ap.add_argument("--csv", default=os.path.join(HERE, "oui.csv"))
    ap.add_argument("--out", default=os.path.join(HERE, "catalog.json"))
    ap.add_argument("--max-ouis", type=int, default=8,
                    help="max OUIs to keep per profile (default 8)")
    args = ap.parse_args()

    if not os.path.exists(args.csv):
        sys.exit(f"IEEE registry not found: {args.csv}\n"
                 f"  curl -so {args.csv} https://standards-oui.ieee.org/oui/oui.csv")

    print(f"Reading {args.csv} ...")
    catalog, total = build(args.csv, args.max_ouis)
    with open(args.out, "w") as f:
        json.dump({"profiles": catalog}, f, indent=2)
    print(f"\nWrote {args.out}: {len(catalog)} profiles, {total} OUIs total")


if __name__ == "__main__":
    main()
