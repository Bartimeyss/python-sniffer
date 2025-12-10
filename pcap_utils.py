import struct
import time

PCAP_GLOBAL_HEADER_FMT = "IHHIIII"
PCAP_PACKET_HEADER_FMT = "IIII"

def write_pcap_global_header(f, snaplen=65535, linktype=1):
    header = struct.pack(
        PCAP_GLOBAL_HEADER_FMT,
        0xA1B2C3D4,
        2,
        4,
        0,
        0,
        snaplen,
        linktype,
    )
    f.write(header)

def write_pcap_packet(f, data, ts=None):
    if ts is None:
        ts = time.time()
    ts_sec = int(ts)
    ts_usec = int((ts - ts_sec) * 1_000_000)
    incl_len = len(data)
    pkt_header = struct.pack(
        PCAP_PACKET_HEADER_FMT,
        ts_sec,
        ts_usec,
        incl_len,
        incl_len,
    )
    f.write(pkt_header)
    f.write(data)
