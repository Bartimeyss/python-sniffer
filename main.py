import argparse
import select
import socket
import struct

try:
    from pcap_utils import write_pcap_global_header, write_pcap_packet
    from report import format_addr, generate_report, parse_ipv4_from_ethernet
except ImportError:  # pragma: no cover - fallback for package usage
    from .pcap_utils import write_pcap_global_header, write_pcap_packet
    from .report import format_addr, generate_report, parse_ipv4_from_ethernet

def format_packet_info(packet):
    if len(packet) < 14:
        return "truncated"
    eth_type = struct.unpack("!H", packet[12:14])[0]
    if eth_type == 0x0800:
        parsed = parse_ipv4_from_ethernet(packet)
        if not parsed:
            return "ipv4-parse-error"
        proto_name = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(parsed["proto"], str(parsed["proto"]))
        src = format_addr(parsed["src"])
        dst = format_addr(parsed["dst"])
        return f"{src} -> {dst} {proto_name}"
    return f"ethertype=0x{eth_type:04x}"

def create_socket(iface):
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    sock.bind((iface, 0))
    return sock

def sniff(ifaces, out_file="capture.pcap", verbose=False):
    if not ifaces:
        ifaces = ["eth0"]

    sockets = {}
    with open(out_file, "wb") as f:
        write_pcap_global_header(f)

        try:
            for iface in ifaces:
                sock = create_socket(iface)
                sockets[sock] = iface
        except OSError as e:
            print(f"Не удалось открыть интерфейс {iface}: {e}")
            for s in sockets:
                s.close()
            return

        print(f"Сниффер запущен на интерфейсах {', '.join(ifaces)}, запись в {out_file}")
        print("Нажмите Ctrl+C, чтобы остановить")

        try:
            while True:
                readable, _, _ = select.select(list(sockets), [], [])
                for sock in readable:
                    packet, addr = sock.recvfrom(65535)
                    write_pcap_packet(f, packet)
                    if verbose:
                        iface = sockets.get(sock, "?")
                        info = format_packet_info(packet)
                        print(f"[{iface}] len={len(packet)} {info}")
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
    sniff_parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Показывать сведения о захваченных пакетах в консоли.",
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
        sniff(args.ifaces, args.output, args.verbose)
    elif args.command == "report":
        generate_report(args.pcap, args.bucket)
