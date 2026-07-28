#!/usr/bin/env python3
"""
Howlr Packet Sentinel by Rudy.isk
=====================

Passive packet capture and PCAP triage for networking study, SOC work,
incident-response first look, and authorised penetration-test observation.

This tool does not transmit, modify, replay, or inject packets.
Capture only interfaces and networks you own or are authorised to monitor.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime
from ipaddress import ip_address, ip_network
from pathlib import Path
from typing import Any, TextIO

from scapy.all import (
    ARP,
    DHCP,
    DNS,
    DNSQR,
    Ether,
    ICMP,
    IP,
    IPv6,
    PcapWriter,
    TCP,
    UDP,
    conf,
    show_interfaces,
    sniff,
)
from scapy.error import Scapy_Exception
from scapy.packet import Packet


COMMON_PORTS = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP",
    53: "DNS", 67: "DHCP-SERVER", 68: "DHCP-CLIENT", 80: "HTTP",
    110: "POP3", 123: "NTP", 135: "MS-RPC", 137: "NETBIOS-NS",
    138: "NETBIOS-DGM", 139: "NETBIOS-SSN", 143: "IMAP", 161: "SNMP",
    162: "SNMP-TRAP", 389: "LDAP", 443: "HTTPS", 445: "SMB",
    514: "SYSLOG", 636: "LDAPS", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1521: "ORACLE", 2049: "NFS", 3306: "MYSQL",
    3389: "RDP", 5432: "POSTGRESQL", 5900: "VNC", 5985: "WINRM-HTTP",
    5986: "WINRM-HTTPS", 6379: "REDIS", 8080: "HTTP-ALT",
    8443: "HTTPS-ALT",
}

CLEARTEXT_PORTS = {
    21: "FTP", 23: "TELNET", 80: "HTTP", 110: "POP3",
    143: "IMAP", 389: "LDAP", 5900: "VNC",
}

DHCP_MESSAGE_TYPES = {
    1: "discover", 2: "offer", 3: "request", 4: "decline",
    5: "ack", 6: "nak", 7: "release", 8: "inform",
}


def safe_text(value: Any) -> str:
    """Convert Scapy bytes and field values into readable text."""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace").rstrip(".")
    return str(value)


def packet_timestamp(packet: Packet) -> tuple[float, str]:
    """Return capture epoch and local ISO timestamp."""
    epoch = float(getattr(packet, "time", 0.0) or 0.0)
    if epoch <= 0:
        epoch = datetime.now().timestamp()
    readable = datetime.fromtimestamp(epoch).astimezone().isoformat(
        timespec="milliseconds"
    )
    return epoch, readable


def service_name(port: int) -> str:
    return COMMON_PORTS.get(port, "")


def port_text(port: int) -> str:
    service = service_name(port)
    return f"{port}/{service}" if service else str(port)


def get_dhcp_message_type(packet: Packet) -> str | None:
    if not packet.haslayer(DHCP):
        return None

    for option in packet[DHCP].options:
        if (
            isinstance(option, tuple)
            and len(option) >= 2
            and option[0] == "message-type"
        ):
            value = option[1]
            if isinstance(value, int):
                return DHCP_MESSAGE_TYPES.get(value, str(value))
            return safe_text(value)
    return None


def get_dns_details(packet: Packet) -> dict[str, Any] | None:
    """Extract a small metadata-only DNS summary."""
    if not packet.haslayer(DNS):
        return None

    dns = packet[DNS]
    details: dict[str, Any] = {
        "kind": "response" if int(dns.qr) == 1 else "query",
        "id": int(dns.id),
        "rcode": int(dns.rcode),
        "answers": int(dns.ancount or 0),
    }

    if packet.haslayer(DNSQR):
        details["qname"] = safe_text(packet[DNSQR].qname)
        details["qtype"] = int(packet[DNSQR].qtype)

    return details


def network_direction(
    source: str | None,
    destination: str | None,
    local_networks: list[Any],
) -> str | None:
    """Classify traffic direction when local CIDRs were supplied."""
    if not source or not destination or not local_networks:
        return None

    try:
        src_ip = ip_address(source)
        dst_ip = ip_address(destination)
    except ValueError:
        return None

    src_local = any(src_ip in network for network in local_networks)
    dst_local = any(dst_ip in network for network in local_networks)

    if src_local and dst_local:
        return "LAN"
    if src_local and not dst_local:
        return "OUT"
    if not src_local and dst_local:
        return "IN"
    return "TRANSIT"


@dataclass
class ScanTracker:
    """Identify a possible TCP SYN scan pattern. This is only a heuristic."""

    threshold: int = 20
    window_seconds: int = 10
    events: dict[str, deque[tuple[float, str, int]]] = field(
        default_factory=lambda: defaultdict(deque)
    )
    last_alert: dict[str, float] = field(default_factory=dict)

    def inspect(
        self,
        timestamp: float,
        source_ip: str | None,
        destination_ip: str | None,
        packet: Packet,
    ) -> list[str]:
        if not source_ip or not destination_ip or not packet.haslayer(TCP):
            return []

        flags = int(packet[TCP].flags)
        syn_without_ack = bool(flags & 0x02) and not bool(flags & 0x10)
        if not syn_without_ack:
            return []

        destination_port = int(packet[TCP].dport)
        activity = self.events[source_ip]
        activity.append((timestamp, destination_ip, destination_port))

        cutoff = timestamp - self.window_seconds
        while activity and activity[0][0] < cutoff:
            activity.popleft()

        unique_targets = {(dst, port) for _, dst, port in activity}
        if len(unique_targets) < self.threshold:
            return []

        previous = self.last_alert.get(source_ip, 0.0)
        if timestamp - previous < self.window_seconds:
            return []

        self.last_alert[source_ip] = timestamp
        return [
            f"POSSIBLE_SYN_SCAN:{source_ip}:"
            f"{len(unique_targets)}_targets_in_{self.window_seconds}s"
        ]


@dataclass
class CaptureStats:
    total: int = 0
    protocols: Counter[str] = field(default_factory=Counter)
    source_ips: Counter[str] = field(default_factory=Counter)
    destination_ports: Counter[int] = field(default_factory=Counter)
    observations: Counter[str] = field(default_factory=Counter)

    def update(self, record: dict[str, Any]) -> None:
        self.total += 1

        for protocol in record["protocols"]:
            self.protocols[protocol] += 1

        source_ip = record.get("source_ip")
        if source_ip:
            self.source_ips[source_ip] += 1

        destination_port = record.get("destination_port")
        if destination_port is not None:
            self.destination_ports[int(destination_port)] += 1

        for observation in record["observations"]:
            category = observation.split(":", maxsplit=1)[0]
            self.observations[category] += 1


class PacketProcessor:
    def __init__(
        self,
        *,
        local_networks: list[Any],
        json_file: TextIO | None,
        pcap_writer: PcapWriter | None,
        quiet: bool,
        scan_threshold: int,
        scan_window: int,
    ) -> None:
        self.local_networks = local_networks
        self.json_file = json_file
        self.pcap_writer = pcap_writer
        self.quiet = quiet
        self.stats = CaptureStats()
        self.scan_tracker = ScanTracker(
            threshold=scan_threshold,
            window_seconds=scan_window,
        )

    def process(self, packet: Packet) -> None:
        try:
            record = self.analyse(packet)
            self.stats.update(record)

            if self.pcap_writer is not None:
                self.pcap_writer.write(packet)

            if self.json_file is not None:
                self.json_file.write(
                    json.dumps(record, ensure_ascii=False) + "\n"
                )
                self.json_file.flush()

            if not self.quiet:
                print(self.format_console_line(record))

        except Exception as error:
            print(
                f"[processor-error] Could not analyse one packet: {error}",
                file=sys.stderr,
            )

    def analyse(self, packet: Packet) -> dict[str, Any]:
        timestamp_epoch, timestamp_text = packet_timestamp(packet)
        protocols: list[str] = []
        observations: list[str] = []

        record: dict[str, Any] = {
            "packet_number": self.stats.total + 1,
            "timestamp": timestamp_text,
            "timestamp_epoch": timestamp_epoch,
            "length": len(packet),
            "protocols": protocols,
            "observations": observations,
        }

        if packet.haslayer(Ether):
            protocols.append("Ethernet")
            record["source_mac"] = packet[Ether].src
            record["destination_mac"] = packet[Ether].dst

        source_ip: str | None = None
        destination_ip: str | None = None

        if packet.haslayer(ARP):
            protocols.append("ARP")
            arp = packet[ARP]
            operation = {1: "request", 2: "reply"}.get(
                int(arp.op), str(int(arp.op))
            )
            record["arp"] = {
                "operation": operation,
                "sender_ip": arp.psrc,
                "target_ip": arp.pdst,
                "sender_mac": arp.hwsrc,
                "target_mac": arp.hwdst,
            }
            source_ip = arp.psrc
            destination_ip = arp.pdst
            if int(arp.op) == 2:
                observations.append("ARP_REPLY")

        elif packet.haslayer(IP):
            protocols.append("IPv4")
            ip_layer = packet[IP]
            source_ip = ip_layer.src
            destination_ip = ip_layer.dst
            record["ttl"] = int(ip_layer.ttl)
            record["ip_id"] = int(ip_layer.id)
            if int(ip_layer.frag) > 0 or "MF" in str(ip_layer.flags):
                observations.append("IP_FRAGMENT")

        elif packet.haslayer(IPv6):
            protocols.append("IPv6")
            ipv6_layer = packet[IPv6]
            source_ip = ipv6_layer.src
            destination_ip = ipv6_layer.dst
            record["hop_limit"] = int(ipv6_layer.hlim)

        record["source_ip"] = source_ip
        record["destination_ip"] = destination_ip
        record["direction"] = network_direction(
            source_ip, destination_ip, self.local_networks
        )

        if packet.haslayer(TCP):
            protocols.append("TCP")
            tcp = packet[TCP]
            source_port = int(tcp.sport)
            destination_port = int(tcp.dport)
            flags = str(tcp.flags)

            record["source_port"] = source_port
            record["destination_port"] = destination_port
            record["tcp_flags"] = flags
            record["sequence"] = int(tcp.seq)
            record["acknowledgement"] = int(tcp.ack)
            record["window"] = int(tcp.window)

            numeric_flags = int(tcp.flags)
            if numeric_flags == 0:
                observations.append("NULL_SCAN_PATTERN")
            if (
                numeric_flags & 0x01
                and numeric_flags & 0x08
                and numeric_flags & 0x20
            ):
                observations.append("XMAS_SCAN_PATTERN")
            if numeric_flags & 0x02 and not numeric_flags & 0x10:
                observations.append("TCP_SYN")
            if destination_port in CLEARTEXT_PORTS:
                observations.append(
                    f"CLEARTEXT_PORT:{CLEARTEXT_PORTS[destination_port]}"
                )

        elif packet.haslayer(UDP):
            protocols.append("UDP")
            udp = packet[UDP]
            record["source_port"] = int(udp.sport)
            record["destination_port"] = int(udp.dport)

        elif packet.haslayer(ICMP):
            protocols.append("ICMP")
            icmp = packet[ICMP]
            record["icmp_type"] = int(icmp.type)
            record["icmp_code"] = int(icmp.code)

        elif packet.haslayer(IPv6):
            payload = packet[IPv6].payload
            layer_name = payload.__class__.__name__
            if layer_name.startswith("ICMPv6"):
                protocols.append("ICMPv6")
                record["icmpv6_type"] = getattr(payload, "type", None)
                record["icmpv6_code"] = getattr(payload, "code", None)
                record["icmpv6_message"] = layer_name

        dns_details = get_dns_details(packet)
        if dns_details is not None:
            protocols.append("DNS")
            record["dns"] = dns_details
            if dns_details["kind"] == "response" and dns_details["rcode"] != 0:
                observations.append(
                    f"DNS_ERROR_RCODE:{dns_details['rcode']}"
                )

        dhcp_type = get_dhcp_message_type(packet)
        if dhcp_type is not None:
            protocols.append("DHCP")
            record["dhcp_message_type"] = dhcp_type

        observations.extend(
            self.scan_tracker.inspect(
                timestamp_epoch, source_ip, destination_ip, packet
            )
        )

        return record

    @staticmethod
    def format_console_line(record: dict[str, Any]) -> str:
        parts = [
            f"[{record['timestamp']}]",
            f"#{record['packet_number']:05d}",
            f"len={record['length']}",
        ]

        direction = record.get("direction")
        if direction:
            parts.append(direction)

        source_mac = record.get("source_mac")
        destination_mac = record.get("destination_mac")
        if source_mac and destination_mac:
            parts.append(f"MAC {source_mac} -> {destination_mac}")

        if "arp" in record:
            arp = record["arp"]
            parts.append(
                f"ARP {arp['operation']} "
                f"{arp['sender_ip']} -> {arp['target_ip']}"
            )
        else:
            source_ip = record.get("source_ip")
            destination_ip = record.get("destination_ip")
            if source_ip and destination_ip:
                ip_version = (
                    "IPv6" if "IPv6" in record["protocols"] else "IPv4"
                )
                parts.append(f"{ip_version} {source_ip} -> {destination_ip}")

        if "TCP" in record["protocols"]:
            parts.append(
                f"TCP {port_text(record['source_port'])} -> "
                f"{port_text(record['destination_port'])} "
                f"flags={record['tcp_flags']}"
            )
        elif "UDP" in record["protocols"]:
            parts.append(
                f"UDP {port_text(record['source_port'])} -> "
                f"{port_text(record['destination_port'])}"
            )
        elif "ICMP" in record["protocols"]:
            parts.append(
                f"ICMP type={record['icmp_type']} code={record['icmp_code']}"
            )
        elif "ICMPv6" in record["protocols"]:
            parts.append(
                f"{record.get('icmpv6_message', 'ICMPv6')} "
                f"type={record.get('icmpv6_type')} "
                f"code={record.get('icmpv6_code')}"
            )

        if "dns" in record:
            dns = record["dns"]
            dns_text = f"DNS {dns['kind']}"
            if dns.get("qname"):
                dns_text += f" {dns['qname']}"
            if dns["kind"] == "response":
                dns_text += f" answers={dns['answers']} rcode={dns['rcode']}"
            parts.append(dns_text)

        if record.get("dhcp_message_type"):
            parts.append(f"DHCP {record['dhcp_message_type']}")

        if record["observations"]:
            parts.append("OBS=" + ",".join(record["observations"]))

        return " | ".join(parts)


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Passive Scapy packet capture and PCAP triage for authorised use."
    )
    parser.add_argument(
        "--list-interfaces", action="store_true",
        help="List Scapy interfaces and exit."
    )
    parser.add_argument(
        "-i", "--interface",
        help="Live-capture interface. Default: Scapy's chosen interface."
    )
    parser.add_argument(
        "-r", "--read", type=Path,
        help="Read an existing PCAP/PCAPNG instead of live capture."
    )
    parser.add_argument(
        "-f", "--filter", default="",
        help='BPF filter, for example: "tcp or udp or icmp".'
    )
    parser.add_argument(
        "-c", "--count", type=int, default=0,
        help="Stop after this many packets. Zero means unlimited."
    )
    parser.add_argument(
        "-t", "--timeout", type=int, default=None,
        help="Stop after this many seconds."
    )
    parser.add_argument(
        "--local-network", action="append", default=[], metavar="CIDR",
        help="CIDR for IN/OUT/LAN labels. May be repeated."
    )
    parser.add_argument(
        "--pcap-out", type=Path,
        help="Save processed packets to a PCAP file."
    )
    parser.add_argument(
        "--jsonl-out", type=Path,
        help="Save one structured JSON record per packet."
    )
    parser.add_argument(
        "--scan-threshold", type=int, default=20,
        help="Unique TCP SYN targets required for a scan observation."
    )
    parser.add_argument(
        "--scan-window", type=int, default=10,
        help="Seconds used by the TCP SYN scan heuristic."
    )
    parser.add_argument(
        "-q", "--quiet", action="store_true",
        help="Suppress packet lines; still write files and final statistics."
    )
    return parser.parse_args()


def validate_arguments(args: argparse.Namespace) -> list[Any]:
    if args.count < 0:
        raise ValueError("--count cannot be negative.")
    if args.timeout is not None and args.timeout <= 0:
        raise ValueError("--timeout must be greater than zero.")
    if args.scan_threshold <= 0:
        raise ValueError("--scan-threshold must be greater than zero.")
    if args.scan_window <= 0:
        raise ValueError("--scan-window must be greater than zero.")
    if args.read is not None and not args.read.is_file():
        raise ValueError(f"Input capture not found: {args.read}")

    local_networks = []
    for value in args.local_network:
        try:
            local_networks.append(ip_network(value, strict=False))
        except ValueError as error:
            raise ValueError(
                f"Invalid --local-network value '{value}': {error}"
            ) from error
    return local_networks


def print_statistics(stats: CaptureStats) -> None:
    print("\n=== Capture Summary ===")
    print(f"Packets analysed: {stats.total}")

    if stats.protocols:
        protocol_text = ", ".join(
            f"{name}={count}" for name, count in stats.protocols.most_common()
        )
        print(f"Protocols: {protocol_text}")

    if stats.source_ips:
        print("Top source IPs:")
        for source, count in stats.source_ips.most_common(5):
            print(f"  {source:<39} {count}")

    if stats.destination_ports:
        print("Top destination ports:")
        for port, count in stats.destination_ports.most_common(10):
            print(f"  {port_text(port):<20} {count}")

    if stats.observations:
        print("Observations:")
        for name, count in stats.observations.most_common():
            print(f"  {name:<28} {count}")

    print("Note: observations are triage hints, not proof of malicious activity.")


def ensure_parent(path: Path | None) -> None:
    if path is not None:
        path.expanduser().resolve().parent.mkdir(parents=True, exist_ok=True)


def main() -> int:
    args = parse_arguments()

    if args.list_interfaces:
        show_interfaces()
        return 0

    try:
        local_networks = validate_arguments(args)
    except ValueError as error:
        print(f"Configuration error: {error}", file=sys.stderr)
        return 2

    ensure_parent(args.pcap_out)
    ensure_parent(args.jsonl_out)

    json_file: TextIO | None = None
    pcap_writer: PcapWriter | None = None
    processor: PacketProcessor | None = None

    try:
        if args.jsonl_out is not None:
            json_file = args.jsonl_out.open("w", encoding="utf-8", buffering=1)

        if args.pcap_out is not None:
            pcap_writer = PcapWriter(
                str(args.pcap_out), append=False, sync=True
            )

        processor = PacketProcessor(
            local_networks=local_networks,
            json_file=json_file,
            pcap_writer=pcap_writer,
            quiet=args.quiet,
            scan_threshold=args.scan_threshold,
            scan_window=args.scan_window,
        )

        source_description = (
            f"offline file {args.read}"
            if args.read is not None
            else f"interface {args.interface or conf.iface}"
        )
        print("Howlr Packet Sentinel")
        print(f"Source: {source_description}")
        print(f"BPF filter: {args.filter or '(none)'}")
        print(
            f"Packet limit: {args.count or 'unlimited'} | "
            f"Timeout: {args.timeout or 'none'}"
        )
        print("Press Ctrl+C to stop a live capture.\n")

        sniff_arguments: dict[str, Any] = {
            "prn": processor.process,
            "store": False,
            "count": args.count,
        }

        if args.filter:
            sniff_arguments["filter"] = args.filter
        if args.timeout is not None:
            sniff_arguments["timeout"] = args.timeout

        if args.read is not None:
            sniff_arguments["offline"] = str(args.read)
        elif args.interface:
            sniff_arguments["iface"] = args.interface

        sniff(**sniff_arguments)

    except KeyboardInterrupt:
        print("\nCapture stopped by user.")
    except PermissionError:
        print(
            "Permission denied. Run the terminal as Administrator/root.",
            file=sys.stderr,
        )
        return 1
    except (OSError, Scapy_Exception) as error:
        print(f"Capture failed: {error}", file=sys.stderr)
        print(
            "Check the interface, BPF filter, permissions, and Npcap/libpcap.",
            file=sys.stderr,
        )
        return 1
    except Exception as error:
        print(f"Unexpected failure: {error}", file=sys.stderr)
        return 1
    finally:
        if pcap_writer is not None:
            pcap_writer.close()
        if json_file is not None:
            json_file.close()

    if processor is not None:
        print_statistics(processor.stats)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
