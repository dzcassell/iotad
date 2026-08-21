import json
import os
import tempfile
import unittest

import iotad


HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class ConfigTests(unittest.TestCase):
    def test_defaults_validate(self):
        cfg = iotad.Config(None)
        self.assertEqual(cfg.facility, "mixed")

    def test_rejects_pool_outside_subnet(self):
        text = """
[network]
interface = eth0
subnet = 192.0.2.0/24
gateway = 192.0.2.1
ip_pool_start = 198.51.100.10
ip_pool_end = 198.51.100.20
"""
        with tempfile.NamedTemporaryFile("w", delete=False) as f:
            f.write(text)
            path = f.name
        try:
            with self.assertRaisesRegex(ValueError, "IP pool"):
                iotad.Config(path)
        finally:
            os.unlink(path)


class ProtocolTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cfg = iotad.Config(None)
        cls.cfg.dry_run = True
        cls.site_a = iotad.Site("a", "eth0", "192.0.2.0/24", "192.0.2.1",
                                "192.0.2.10", "192.0.2.20")
        cls.site_b = iotad.Site("b", "eth1", "198.51.100.0/24", "198.51.100.1",
                                "198.51.100.10", "198.51.100.20")
        cls.site_a.gw_mac = "00:00:5e:00:53:01"
        cls.site_b.gw_mac = "00:00:5e:00:53:02"
        cls.cfg.sites = [cls.site_a, cls.site_b]
        cls.cfg.interface = "eth0"
        profile = {
            "id": "test", "label": "Test controller", "category": "plc",
            "ports": [80, 102, 502, 1883, 1911, 2404, 2575, 4840, 5007,
                      5094, 7878, 11112, 20000],
            "udp_ports": [3671, 5683],
            "beacons": ["mdns", "modbus", "ntp"],
            "mdns": ["_http._tcp"], "checkin": ["example.invalid"],
            "identity": {"vendor": "Lab", "product": "Controller", "revision": "1.0"},
        }
        cls.client = iotad.Device(1, profile, "00:11:22:33:44:55", "192.0.2.10",
                                  "client", "000001", cls.site_a)
        cls.server = iotad.Device(2, profile, "00:11:22:33:44:66", "198.51.100.10",
                                  "server", "000002", cls.site_b)
        cls.tx = iotad.Tx(cls.cfg)
        cls.em = iotad.Emitters(cls.cfg, cls.tx, [cls.client, cls.server])

    def test_snmp_unsigned_values_have_positive_padding(self):
        self.assertEqual(iotad._enc_uint(0x80), b"\x00\x80")
        self.assertEqual(iotad._enc_uint(0x7F), b"\x7f")

    def test_mdns_announcement_is_complete(self):
        packets = self.em.mdns(self.client)
        self.assertEqual(len(packets), 1)
        self.assertEqual(packets[0][iotad.DNS].ancount, 4)

    def test_dns_uses_configured_resolver(self):
        self.cfg.dns_server = "203.0.113.53"
        pkt = self.em.dns_checkin(self.client)
        self.assertEqual(pkt[iotad.IP].dst, "203.0.113.53")

    def test_ntp_emitter(self):
        pkt = self.em.ntp(self.client)
        self.assertEqual(pkt[iotad.UDP].dport, 123)
        self.assertEqual(pkt[iotad.NTP].mode, 3)

    def test_cross_site_modbus_is_bidirectional(self):
        frames = self.em.modbus(self.client)
        self.assertEqual(len(frames), 6)
        self.assertEqual({f.iface for f in frames}, {"eth0", "eth1"})
        self.assertTrue(any(f.pkt.haslayer(iotad.Raw) for f in frames))

    def test_tls_client_hello_contains_sni(self):
        hello = self.em._tls_client_hello("device.vendor.example")
        self.assertTrue(hello.startswith(b"\x16\x03\x01"))
        self.assertIn(b"device.vendor.example", hello)

    def test_tcp_state_isolated_by_virtual_destination(self):
        responder = iotad.Responder(self.cfg, [self.client, self.server], self.tx,
                                    known_macs=[self.client.mac, self.server.mac])
        for dst in (self.client.ip, self.server.ip):
            pkt = (iotad.Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") /
                   iotad.IP(src="203.0.113.9", dst=dst) /
                   iotad.TCP(sport=40000, dport=80, flags="S", seq=100))
            responder._tcp(pkt)
        self.assertEqual(len(responder.conns), 2)

    def test_bacnet_and_profinet_responders(self):
        profile = self.server.profile
        profile["bacnet"] = {"device_id": 1001, "vendor_id": 15}
        profile["profinet"] = {"vendor_id": 42, "device_id": 1, "role": 1}
        responder = iotad.Responder(self.cfg, [self.server], self.tx,
                                    known_macs=[self.server.mac])
        whois = (iotad.Ether(src="02:00:00:00:00:01", dst=iotad.BCAST_MAC) /
                 iotad.IP(src="198.51.100.8", dst="198.51.100.255") /
                 iotad.UDP(sport=47808, dport=47808) /
                 iotad.Raw(bytes.fromhex("810b000c0120ffff00ff1008")))
        responder._bacnet(whois)
        dcp = (iotad.Ether(src="02:00:00:00:00:01", dst=iotad.PROFINET_MCAST_MAC,
                           type=0x8892) /
               iotad.Raw(bytes.fromhex("fefe05001234567800000004ffff0000")))
        responder._profinet(dcp)
        self.assertEqual(responder.bacnet_replies, 1)
        self.assertEqual(responder.profinet_replies, 1)

    def test_added_protocol_conversations(self):
        checks = {
            "mqtt": 6, "coap": 2, "knx": 2, "iec61850": 6, "mtconnect": 6,
        }
        for name, expected in checks.items():
            with self.subTest(protocol=name):
                frames = getattr(self.em, name)(self.client)
                self.assertEqual(len(frames), expected)
                self.assertTrue(any(f.pkt.haslayer(iotad.Raw) for f in frames))

    def test_scenario_events_cycle(self):
        events = [self.em.scenario_event(self.client) for _ in range(6)]
        self.assertTrue(all(event is not None for event in events))

    def test_vlan_tagging_in_pcap(self):
        old_vlan = self.site_a.vlan
        old_path = getattr(self.cfg, "pcap_path", None)
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
            path = f.name
        try:
            self.site_a.vlan = 123
            self.cfg.pcap_path = path
            tx = iotad.Tx(self.cfg)
            tx.send("test", self.em.garp(self.client), "eth0")
            tx.close()
            packets = iotad.rdpcap(path)
            self.assertEqual(packets[0][iotad.Dot1Q].vlan, 123)
        finally:
            self.site_a.vlan = old_vlan
            self.cfg.pcap_path = old_path
            os.unlink(path)

    def test_metrics_snapshot(self):
        responder = iotad.Responder(self.cfg, [self.client, self.server], self.tx)
        metrics = iotad.MetricsReporter(self.cfg, [self.client, self.server],
                                        self.tx, [responder]).snapshot()
        self.assertEqual(metrics["devices"], 2)
        self.assertIn("transmitter", metrics)
        self.assertEqual(len(metrics["sites"]), 2)


class CatalogTests(unittest.TestCase):
    def test_catalog_has_facility_profiles(self):
        with open(os.path.join(HERE, "catalog.json")) as f:
            profiles = json.load(f)["profiles"]
        categories = {p["category"] for p in profiles}
        self.assertTrue({"medical", "robotics", "cleanroom", "water_treatment"} <= categories)
        self.assertTrue(all("ntp" in p["beacons"] for p in profiles))
        beacons = {b for p in profiles for b in p["beacons"]}
        self.assertTrue({"mqtt", "coap", "knx", "iec61850", "mtconnect"} <= beacons)

    def test_weighted_facility_roster_is_scoped_and_deterministic(self):
        with open(os.path.join(HERE, "catalog.json")) as f:
            catalog = json.load(f)
        cfg = iotad.Config(None)
        cfg.facility = "automotive"
        cfg.device_count = 40
        first = iotad.build_roster(catalog, cfg)
        second = iotad.build_roster(catalog, cfg)
        allowed = set(iotad.FACILITY_WEIGHTS["automotive"])
        self.assertTrue(all(d.profile["category"] in allowed for d in first))
        self.assertEqual([(d.ip, d.mac, d.profile["id"]) for d in first],
                         [(d.ip, d.mac, d.profile["id"]) for d in second])


if __name__ == "__main__":
    unittest.main()
