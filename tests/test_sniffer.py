import contextlib
import io
import os
import struct
import tempfile
import unittest
from unittest import mock

import main


class FakeSocket:
    def __init__(self, iface, packets):
        self.iface = iface
        self._packets = list(packets)
        self.closed = False

    def recvfrom(self, _):
        if not self._packets:
            raise AssertionError("recvfrom called with no packets left")
        return self._packets.pop(0), None

    def close(self):
        self.closed = True


class SnifferTests(unittest.TestCase):
    def test_sniff_writes_packets_from_multiple_interfaces(self):
        sock1 = FakeSocket("if1", [b"aaa"])
        sock2 = FakeSocket("if2", [b"bbbb"])
        sockets_by_iface = {
            "if1": sock1,
            "if2": sock2,
        }

        def fake_create_socket(iface):
            return sockets_by_iface[iface]

        # select will be called repeatedly; first time return both sockets, then raise KeyboardInterrupt to stop loop.
        select_calls = []

        def fake_select(sock_list, *_):
            select_calls.append(list(sock_list))
            if len(select_calls) == 1:
                return sock_list, [], []
            raise KeyboardInterrupt

        tmp = tempfile.NamedTemporaryFile(delete=False)
        try:
            with mock.patch("main.create_socket", side_effect=fake_create_socket), mock.patch(
                "main.select.select", side_effect=fake_select
            ):
                # suppress stdout noise
                with contextlib.redirect_stdout(io.StringIO()):
                    main.sniff(["if1", "if2"], tmp.name)

            with open(tmp.name, "rb") as f:
                global_header = f.read(24)
                self.assertEqual(len(global_header), 24)

                # first packet
                header1 = f.read(16)
                ts_sec1, ts_usec1, incl_len1, orig_len1 = struct.unpack(main.PCAP_PACKET_HEADER_FMT, header1)
                data1 = f.read(incl_len1)

                # second packet
                header2 = f.read(16)
                ts_sec2, ts_usec2, incl_len2, orig_len2 = struct.unpack(main.PCAP_PACKET_HEADER_FMT, header2)
                data2 = f.read(incl_len2)

                # no extra packets
                self.assertEqual(f.read(), b"")

            self.assertEqual(data1, b"aaa")
            self.assertEqual(data2, b"bbbb")
            self.assertEqual(incl_len1, len(data1))
            self.assertEqual(incl_len2, len(data2))

            # sockets were closed
            self.assertTrue(sock1.closed)
            self.assertTrue(sock2.closed)
        finally:
            os.unlink(tmp.name)


if __name__ == "__main__":
    unittest.main()
