import struct
import socket
import sys
from collections import defaultdict
from datetime import datetime

PCAP_GLOBAL_HEADER_FMT = "IHHIIII"
PCAP_PACKET_HEADER_FMT = "IIII"

ETH_HEADER_LEN = 14

def parse_pcap_packets(path):
    with open(path, "rb") as f:
        global_header = f.read(24)
        if len(global_header) < 24:
            return

        while True:
            header = f.read(16)
            if len(header) < 16:
                break

            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(PCAP_PACKET_HEADER_FMT, header)
            data = f.read(incl_len)
            if len(data) < incl_len:
                break

            yield ts_sec + ts_usec / 1_000_000, data

def parse_ipv4_from_ethernet(frame):
    if len(frame) < ETH_HEADER_LEN + 20:
        return None

    eth_type = struct.unpack("!H", frame[12:14])[0]
    if eth_type != 0x0800:  # не IPv4
        return None

    ip_header = frame[ETH_HEADER_LEN:]
    version_ihl = ip_header[0]
    version = version_ihl >> 4
    ihl = version_ihl & 0x0F

    if version != 4:
        return None

    ip_header_len = ihl * 4
    if len(ip_header) < ip_header_len:
        return None

    total_len = struct.unpack("!H", ip_header[2:4])[0]
    src_ip = socket.inet_ntoa(ip_header[12:16])
    dst_ip = socket.inet_ntoa(ip_header[16:20])

    return src_ip, dst_ip, total_len

def generate_report(pcap_path, time_bucket_sec=60):
    bytes_per_ip = defaultdict(int)
    pkts_per_ip = defaultdict(int)

    bytes_per_pair = defaultdict(int)

    bytes_per_bucket = defaultdict(int)

    for ts, frame in parse_pcap_packets(pcap_path):
        parsed = parse_ipv4_from_ethernet(frame)
        if not parsed:
            continue

        src, dst, total_len = parsed

        bytes_per_ip[src] += total_len
        bytes_per_ip[dst] += total_len
        pkts_per_ip[src] += 1
        pkts_per_ip[dst] += 1

        bytes_per_pair[(src, dst)] += total_len

        bucket = int(ts // time_bucket_sec) * time_bucket_sec
        bytes_per_bucket[bucket] += total_len

    hostnames = {}
    for ip in bytes_per_ip.keys():
        try:
            name, _, _ = socket.gethostbyaddr(ip)
            hostnames[ip] = name
        except Exception:
            hostnames[ip] = None

    print("=== Топ IP по объёму трафика ===")
    for ip, b in sorted(bytes_per_ip.items(), key=lambda x: x[1], reverse=True)[:20]:
        host = hostnames.get(ip)
        host_str = f" ({host})" if host else ""
        print(f"{ip:<15}{host_str:<30}  bytes={b:<10}  pkts={pkts_per_ip[ip]}")

    print("\n=== Топ направлений (src -> dst) по объёму ===")
    for (src, dst), b in sorted(bytes_per_pair.items(), key=lambda x: x[1], reverse=True)[:20]:
        print(f"{src:>15} -> {dst:<15}  bytes={b}")

    print("\n=== Трафик по времени (бакет {} сек) ===".format(time_bucket_sec))
    for bucket_ts in sorted(bytes_per_bucket.keys()):
        dt = datetime.fromtimestamp(bucket_ts)
        print(f"{dt}  bytes={bytes_per_bucket[bucket_ts]}")
