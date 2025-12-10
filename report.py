import struct
import socket
from collections import defaultdict
from datetime import datetime

from pcap_utils import PCAP_PACKET_HEADER_FMT

ETH_HEADER_LEN = 14
HOST_CACHE = {}

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
    if eth_type != 0x0800:
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
    proto = ip_header[9]
    src_ip = socket.inet_ntoa(ip_header[12:16])
    dst_ip = socket.inet_ntoa(ip_header[16:20])

    payload_len = max(total_len - ip_header_len, 0)
    payload = ip_header[ip_header_len : ip_header_len + payload_len]

    src_port = dst_port = None
    if proto in (6, 17) and len(payload) >= 4:
        src_port, dst_port = struct.unpack("!HH", payload[:4])

    return {
        "src": src_ip,
        "dst": dst_ip,
        "len": total_len,
        "proto": proto,
        "payload": payload,
        "src_port": src_port,
        "dst_port": dst_port,
    }

def parse_udp_payload(segment):
    if len(segment) < 8:
        return None
    src_port, dst_port, length, _ = struct.unpack("!HHHH", segment[:8])
    data_len = max(min(length, len(segment)) - 8, 0)
    return src_port, dst_port, segment[8 : 8 + data_len]

def parse_tcp_payload(segment):
    if len(segment) < 20:
        return None
    fields = struct.unpack("!HHIIHHHH", segment[:20])
    src_port, dst_port = fields[0], fields[1]
    data_offset = (fields[4] >> 12) * 4
    if len(segment) < data_offset:
        return None
    return src_port, dst_port, segment[data_offset:]

def decode_dns_name(buf, offset):
    labels = []
    jumped = False
    seen = set()
    while True:
        if offset >= len(buf):
            return None, None
        if offset in seen:
            return None, None
        seen.add(offset)
        length = buf[offset]
        if length == 0:
            offset += 1
            break
        if (length & 0xC0) == 0xC0:
            if offset + 1 >= len(buf):
                return None, None
            pointer = ((length & 0x3F) << 8) | buf[offset + 1]
            offset += 2
            if not jumped:
                jumped = True
            offset = pointer
            continue
        offset += 1
        if offset + length > len(buf):
            return None, None
        labels.append(buf[offset : offset + length].decode(errors="ignore"))
        offset += length
    return ".".join(labels), offset

def parse_dns_queries(payload):
    if len(payload) < 12:
        return []
    qdcount = struct.unpack("!H", payload[4:6])[0]
    offset = 12
    domains = []
    for _ in range(qdcount):
        name, next_off = decode_dns_name(payload, offset)
        if not name:
            break
        offset = next_off
        if offset + 4 > len(payload):
            break
        offset += 4
        domains.append(name.lower().rstrip("."))
    return domains

def parse_tls_sni(payload):
    if len(payload) < 5:
        return None
    content_type = payload[0]
    if content_type != 0x16:
        return None
    rec_len = struct.unpack("!H", payload[3:5])[0]
    if len(payload) < 5 + rec_len:
        return None
    body = payload[5 : 5 + rec_len]
    if len(body) < 4 or body[0] != 0x01:
        return None
    handshake_len = int.from_bytes(body[1:4], "big")
    if len(body) < 4 + handshake_len:
        return None
    idx = 4
    if len(body) < idx + 2 + 32 + 1:
        return None
    idx += 2  # version
    idx += 32  # random
    session_len = body[idx]
    idx += 1
    if len(body) < idx + session_len + 2:
        return None
    idx += session_len
    cipher_len = struct.unpack("!H", body[idx : idx + 2])[0]
    idx += 2 + cipher_len
    if len(body) < idx + 1:
        return None
    comp_len = body[idx]
    idx += 1 + comp_len
    if len(body) < idx + 2:
        return None
    ext_total_len = struct.unpack("!H", body[idx : idx + 2])[0]
    idx += 2
    end_ext = idx + ext_total_len
    while idx + 4 <= len(body) and idx < end_ext:
        ext_type = struct.unpack("!H", body[idx : idx + 2])[0]
        ext_len = struct.unpack("!H", body[idx + 2 : idx + 4])[0]
        ext_data = body[idx + 4 : idx + 4 + ext_len]
        idx += 4 + ext_len
        if ext_type != 0:
            continue
        if len(ext_data) < 2:
            return None
        list_len = struct.unpack("!H", ext_data[:2])[0]
        pos = 2
        while pos + 3 <= len(ext_data) and pos < 2 + list_len:
            name_type = ext_data[pos]
            name_len = struct.unpack("!H", ext_data[pos + 1 : pos + 3])[0]
            pos += 3
            if pos + name_len > len(ext_data):
                return None
            if name_type == 0:
                try:
                    return ext_data[pos : pos + name_len].decode("utf-8")
                except Exception:
                    return None
            pos += name_len
    return None

def resolve_host(ip):
    if ip in HOST_CACHE:
        return HOST_CACHE[ip]
    try:
        name, _, _ = socket.gethostbyaddr(ip)
    except Exception:
        name = None
    HOST_CACHE[ip] = name
    return name

def format_addr(ip):
    host = resolve_host(ip)
    return f"{ip} ({host})" if host else ip

def generate_report(pcap_path, time_bucket_sec=60):
    bytes_per_ip = defaultdict(int)
    pkts_per_ip = defaultdict(int)
    bytes_per_pair = defaultdict(int)
    bytes_per_bucket = defaultdict(int)
    dns_domains = defaultdict(int)
    dns_queries = defaultdict(int)
    sni_domains = defaultdict(int)

    for ts, frame in parse_pcap_packets(pcap_path):
        parsed = parse_ipv4_from_ethernet(frame)
        if not parsed:
            continue

        src = parsed["src"]
        dst = parsed["dst"]
        total_len = parsed["len"]
        proto = parsed["proto"]
        payload = parsed["payload"]

        bytes_per_ip[src] += total_len
        bytes_per_ip[dst] += total_len
        pkts_per_ip[src] += 1
        pkts_per_ip[dst] += 1

        bytes_per_pair[(src, dst)] += total_len

        bucket = int(ts // time_bucket_sec) * time_bucket_sec
        bytes_per_bucket[bucket] += total_len

        if proto == 17:
            udp_parsed = parse_udp_payload(payload)
            if udp_parsed:
                src_port, dst_port, udp_data = udp_parsed
                if src_port == 53 or dst_port == 53:
                    for domain in parse_dns_queries(udp_data):
                        dns_queries[domain] += 1
                        dns_domains[domain] += total_len

        if proto == 6:
            tcp_parsed = parse_tcp_payload(payload)
            if tcp_parsed:
                _, _, tcp_data = tcp_parsed
                sni = parse_tls_sni(tcp_data)
                if sni:
                    sni_domains[sni.lower()] += total_len

    print("=== IP и хосты (по объёму трафика) ===")
    for ip, b in sorted(bytes_per_ip.items(), key=lambda x: x[1], reverse=True)[:20]:
        label = format_addr(ip)
        print(f"{label:<40} bytes={b:<10} pkts={pkts_per_ip[ip]}")

    print("\n=== Направления (src -> dst) ===")
    for (src, dst), b in sorted(bytes_per_pair.items(), key=lambda x: x[1], reverse=True)[:20]:
        print(f"{format_addr(src):>30} -> {format_addr(dst):<30} bytes={b}")

    print("\n=== Трафик по времени (бакет {} сек) ===".format(time_bucket_sec))
    for bucket_ts in sorted(bytes_per_bucket.keys()):
        dt = datetime.fromtimestamp(bucket_ts)
        print(f"{dt}  bytes={bytes_per_bucket[bucket_ts]}")

    if dns_domains:
        print("\n=== Домены из DNS (запросы) ===")
        for dom, b in sorted(dns_domains.items(), key=lambda x: x[1], reverse=True)[:20]:
            print(f"{dom:<40} bytes={b:<10} queries={dns_queries[dom]}")

    if sni_domains:
        print("\n=== Домены из TLS SNI ===")
        for dom, b in sorted(sni_domains.items(), key=lambda x: x[1], reverse=True)[:20]:
            print(f"{dom:<40} bytes={b}")
