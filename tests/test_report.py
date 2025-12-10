import contextlib
import io
import os
import socket
import tempfile
import sys
import struct
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from pcap_utils import write_pcap_global_header, write_pcap_packet
from report import HOST_CACHE, format_addr, generate_report, parse_ipv4_from_ethernet


def build_ipv4_frame(src_ip, dst_ip, payload, proto=6):
    dest_mac = b"\xaa\xbb\xcc\xdd\xee\xff"
    src_mac = b"\x11\x22\x33\x44\x55\x66"
    eth_header = struct.pack("!6s6sH", dest_mac, src_mac, 0x0800)

    ver_ihl = (4 << 4) | 5
    tos = 0
    total_len = 20 + len(payload)
    ident = 0
    flags_frag = 0
    ttl = 64
    protocol = proto
    checksum = 0
    src_bytes = socket.inet_aton(src_ip)
    dst_bytes = socket.inet_aton(dst_ip)
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        ver_ihl,
        tos,
        total_len,
        ident,
        flags_frag,
        ttl,
        protocol,
        checksum,
        src_bytes,
        dst_bytes,
    )

    return eth_header + ip_header + payload


def build_udp_segment(src_port, dst_port, data):
    udp_len = 8 + len(data)
    return struct.pack("!HHHH", src_port, dst_port, udp_len, 0) + data


def build_dns_query(domain):
    header = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    labels = b"".join(bytes([len(part)]) + part.encode() for part in domain.split(".")) + b"\x00"
    question = labels + struct.pack("!HH", 1, 1)
    return header + question


class ReportTests(unittest.TestCase):
    def test_parse_ipv4_from_ethernet_skips_non_ipv4(self):
        frame = b"\x00" * 14 + b"\x00" * 20
        self.assertIsNone(parse_ipv4_from_ethernet(frame))

    def test_generate_report_aggregates_bytes_and_pkts(self):
        tmp = tempfile.NamedTemporaryFile(delete=False)
        try:
            with open(tmp.name, "wb") as f:
                write_pcap_global_header(f)
                frame1 = build_ipv4_frame("192.0.2.1", "192.0.2.2", b"a" * 10)
                frame2 = build_ipv4_frame("192.0.2.2", "192.0.2.1", b"b" * 20)
                write_pcap_packet(f, frame1, ts=1_000)
                write_pcap_packet(f, frame2, ts=1_030)

            buffer = io.StringIO()
            with contextlib.redirect_stdout(buffer):
                generate_report(tmp.name, time_bucket_sec=60)
            captured = buffer.getvalue()

            self.assertIn("Конечные хосты IPv4", captured)
            lines = captured.splitlines()

            endpoint1 = next(l for l in lines if "192.0.2.1" in l and l.strip().startswith("1"))
            endpoint2 = next(l for l in lines if "192.0.2.2" in l and l.strip().startswith("2"))
            self.assertTrue(endpoint1.strip().endswith("70"))
            self.assertIn("  2", endpoint1)
            self.assertTrue(endpoint2.strip().endswith("70"))
            self.assertIn("  2", endpoint2)

            conv_forward = next(l for l in lines if "192.0.2.1" in l and "192.0.2.2" in l and l.strip().startswith("2"))
            conv_backward = next(l for l in lines if "192.0.2.1" in l and "192.0.2.2" in l and l.strip().startswith("1"))
            self.assertTrue(conv_forward.strip().endswith("30"))
            self.assertIn("->", conv_forward)
            self.assertTrue(conv_backward.strip().endswith("40"))

            self.assertIn("Трафик по времени", captured)
            time_line_1 = next(l for l in lines if "00:16:00" in l)
            time_line_2 = next(l for l in lines if "00:17:00" in l)
            self.assertTrue(time_line_1.strip().endswith("30"))
            self.assertTrue(time_line_2.strip().endswith("40"))
        finally:
            os.unlink(tmp.name)

    def test_generate_report_includes_dns_queries(self):
        tmp = tempfile.NamedTemporaryFile(delete=False)
        try:
            dns_payload = build_dns_query("example.com")
            udp_seg = build_udp_segment(12345, 53, dns_payload)
            frame = build_ipv4_frame("192.0.2.10", "8.8.8.8", udp_seg, proto=17)
            with open(tmp.name, "wb") as f:
                write_pcap_global_header(f)
                write_pcap_packet(f, frame, ts=2_000)

            buffer = io.StringIO()
            with contextlib.redirect_stdout(buffer):
                generate_report(tmp.name, time_bucket_sec=120)
            captured = buffer.getvalue()
            lines = captured.splitlines()

            self.assertIn("DNS запросы", captured)
            dns_line = next(l for l in lines if "example.com" in l)
            self.assertIn("1", dns_line)
        finally:
            os.unlink(tmp.name)

    def test_format_addr_uses_host_cache(self):
        HOST_CACHE.clear()
        HOST_CACHE["10.0.0.1"] = "cached.local"
        formatted = format_addr("10.0.0.1")
        self.assertEqual(formatted, "cached.local (10.0.0.1)")


if __name__ == "__main__":
    unittest.main()
