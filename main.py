import argparse
import select
import socket
import struct
import sys
import time

from report import generate_report

PCAP_GLOBAL_HEADER_FMT = "IHHIIII"
PCAP_PACKET_HEADER_FMT = "IIII"

def write_pcap_global_header(f, snaplen=65535, linktype=1):
    # magic_number, version_major, version_minor, thiszone, sigfigs, snaplen, network
    global_header = struct.pack(
        PCAP_GLOBAL_HEADER_FMT,
        0xa1b2c3d4,  # magic
        2,           # major
        4,           # minor
        0,           # thiszone
        0,           # sigfigs
        snaplen,     # snaplen
        linktype     # network (1 = Ethernet)
    )
    f.write(global_header)

def write_pcap_packet(f, data, ts=None):
    if ts is None:
        ts = time.time()
    ts_sec = int(ts)
    ts_usec = int((ts - ts_sec) * 1_000_000)

    incl_len = len(data)
    orig_len = len(data)

    pkt_header = struct.pack(
        PCAP_PACKET_HEADER_FMT,
        ts_sec,
        ts_usec,
        incl_len,
        orig_len
    )
    f.write(pkt_header)
    f.write(data)

def create_socket(iface):
    # AF_PACKET + SOCK_RAW — только на Linux
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    sock.bind((iface, 0))
    return sock

def sniff(ifaces, out_file="capture.pcap"):
    if not ifaces:
        ifaces = ["eth0"]

    sockets = []
    with open(out_file, "wb") as f:
        write_pcap_global_header(f)

        try:
            for iface in ifaces:
                sockets.append(create_socket(iface))
        except OSError as e:
            print(f"Не удалось открыть интерфейс {iface}: {e}")
            for s in sockets:
                s.close()
            return

        sock_to_iface = {s: iface for s, iface in zip(sockets, ifaces)}

        print(f"Сниффер запущен на интерфейсах {', '.join(ifaces)}, запись в {out_file}")
        print("Нажмите Ctrl+C, чтобы остановить")

        try:
            while True:
                readable, _, _ = select.select(sockets, [], [])
                for sock in readable:
                    packet, addr = sock.recvfrom(65535)
                    write_pcap_packet(f, packet)
        except KeyboardInterrupt:
            print("\nОстановка сниффера")
        finally:
            for s in sockets:
                s.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Простой сниффер pcap. Требуются права для RAW сокетов."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    sniff_parser = subparsers.add_parser("sniff", help="Захватить трафик и сохранить pcap")
    sniff_parser.add_argument(
        "-i",
        "--interface",
        action="append",
        dest="ifaces",
        help="Интерфейс для захвата (можно указать несколько). По умолчанию eth0.",
    )
    sniff_parser.add_argument(
        "-o",
        "--output",
        default="capture.pcap",
        help="Файл для записи pcap (по умолчанию capture.pcap).",
    )

    report_parser = subparsers.add_parser("report", help="Сгенерировать отчёт по pcap")
    report_parser.add_argument(
        "pcap",
        help="Путь к pcap-файлу для отчёта.",
    )
    report_parser.add_argument(
        "-b",
        "--bucket",
        type=int,
        default=60,
        help="Размер временного бакета в секундах (по умолчанию 60).",
    )

    args = parser.parse_args()
    if args.command == "sniff":
        sniff(args.ifaces, args.output)
    elif args.command == "report":
        generate_report(args.pcap, args.bucket)
