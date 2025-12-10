import contextlib
import io
import os
import socket
import tempfile
import struct
import unittest

from pcap_utils import write_pcap_global_header, write_pcap_packet
from report import generate_report, parse_ipv4_from_ethernet


def build_ipv4_frame(src_ip, dst_ip, payload):
    dest_mac = b"\xaa\xbb\xcc\xdd\xee\xff"
    src_mac = b"\x11\x22\x33\x44\x55\x66"
    eth_header = struct.pack("!6s6sH", dest_mac, src_mac, 0x0800)

    ver_ihl = (4 << 4) | 5
    tos = 0
    total_len = 20 + len(payload)
    ident = 0
    flags_frag = 0
    ttl = 64
    proto = 6
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
        proto,
        checksum,
        src_bytes,
        dst_bytes,
    )

    return eth_header + ip_header + payload


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

            self.assertIn("192.0.2.1", captured)
            self.assertIn("192.0.2.2", captured)
            self.assertIn("bytes=70", captured)
            self.assertIn("192.0.2.1 -> 192.0.2.2", captured)
            self.assertIn("bytes=30", captured)
            self.assertIn("192.0.2.2 -> 192.0.2.1", captured)
            self.assertIn("bytes=40", captured)
            self.assertIn("bytes=70", captured)
        finally:
            os.unlink(tmp.name)


if __name__ == "__main__":
    unittest.main()
