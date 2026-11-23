"""Run: python -m unittest test_parsers.py"""
import os
import tempfile
import unittest

os.environ.setdefault("DATA_DIR", tempfile.mkdtemp())  # keep test runs from creating ./data

from server import classify, parse_line

PF_V4_TCP = ("<134>1 2026-11-19T12:00:00+03:00 fw.local filterlog 4321 - - 5,,,1000000103,igb0,match,block,in,4,0x0,,"
             "49,54321,0,none,6,tcp,44,185.220.101.5,203.0.113.10,51515,22,0,S,1234567,,1024,,mss")
PF_V4_PASS = PF_V4_TCP.replace(",block,in,", ",pass,in,")
PF_V4_OUT = PF_V4_TCP.replace(",block,in,", ",block,out,")
PF_V6_UDP = ("<134>Nov 19 12:00:00 filterlog[555]: 7,,,1000000105,igb0,match,block,in,6,0x00,0x00000,57,udp,17,40,"
             "2a03:2880:f003:c07:face:b00c::2,2001:db8::1,40000,123,40")
EVE = ('<14>Nov 19 12:00:01 ids suricata[1234]: {"timestamp":"2026-11-19T12:00:01.000+0300","event_type":"alert",'
       '"src_ip":"45.155.205.233","src_port":44211,"dest_ip":"203.0.113.10","dest_port":443,"proto":"TCP",'
       '"alert":{"action":"allowed","signature_id":2011716,"signature":"ET WEB_SERVER Possible SQL Injection Attempt",'
       '"category":"Web Application Attack","severity":1}}')
EVE_FLOW = '<14>suricata[1]: {"event_type":"flow","src_ip":"45.155.205.233"}'
FORTI_TRAFFIC = ('date=2026-11-19 time=12:00:02 devname="FG100F" type="traffic" subtype="forward" level="notice" '
                 'srcip=91.240.118.172 srcport=55120 srcintf="wan1" dstip=203.0.113.10 dstport=3389 proto=6 '
                 'action="deny" policyid=0 policytype="policy"')
FORTI_IPS = ('date=2026-11-19 time=12:00:03 type="utm" subtype="ips" level="alert" srcip=193.42.33.7 dstip=203.0.113.10 '
             'dstport=80 proto=6 action="dropped" attack="Apache.Log4j.Error.Log.Remote.Code.Execution" msg="web_server: Apache.Log4j"')
FORTI_ACCEPT = FORTI_TRAFFIC.replace('action="deny"', 'action="accept"')


class Parsers(unittest.TestCase):
    def test_pf_v4_block(self):
        r = parse_line(PF_V4_TCP)
        self.assertEqual((r["src"], r["port"], r["proto"]), ("185.220.101.5", 22, "tcp"))
        self.assertEqual(classify(r["port"], r["proto"], r["text"]), "brute")

    def test_pf_ignores_pass_and_outbound(self):
        self.assertIsNone(parse_line(PF_V4_PASS))
        self.assertIsNone(parse_line(PF_V4_OUT))

    def test_pf_v6(self):
        r = parse_line(PF_V6_UDP)
        self.assertEqual((r["src"], r["port"], r["proto"]), ("2a03:2880:f003:c07:face:b00c::2", 123, "udp"))
        self.assertEqual(classify(r["port"], r["proto"], r["text"]), "ddos")

    def test_eve_alert(self):
        r = parse_line(EVE)
        self.assertEqual((r["src"], r["port"]), ("45.155.205.233", 443))
        self.assertEqual(classify(r["port"], r["proto"], r["text"]), "web")
        self.assertIsNone(parse_line(EVE_FLOW))

    def test_forti(self):
        r = parse_line(FORTI_TRAFFIC)
        self.assertEqual((r["src"], r["port"], r["proto"]), ("91.240.118.172", 3389, "tcp"))
        self.assertEqual(classify(r["port"], r["proto"], r["text"]), "brute")
        r = parse_line(FORTI_IPS)
        self.assertEqual(classify(r["port"], r["proto"], r["text"]), "web")
        self.assertIsNone(parse_line(FORTI_ACCEPT))

    def test_classify_keywords(self):
        self.assertEqual(classify(23, "tcp", "A Network Trojan was detected ET MALWARE Mirai"), "c2")
        self.assertEqual(classify(5555, "tcp", ""), "scan")


if __name__ == "__main__":
    unittest.main()
