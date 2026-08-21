#!/usr/bin/env python3
"""
Howlr Packet Sentinel by howlerlab / Rudy
=========================================

Version 0.2.0

Passive packet capture and PCAP triage for networking study, SOC work,
incident-response first look, and authorised penetration-test observation.

This tool does not transmit, modify, replay, or inject packets.
Capture only interfaces and networks you own or are authorised to monitor.
"""

from __future__ import annotations

import argparse
import csv
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
    Raw,
    PcapWriter,
    TCP,
    UDP,
    conf,
    show_interfaces,
    sniff,
)
from scapy.error import Scapy_Exception
from scapy.packet import Packet


VERSION = "0.2.0"

COMMON_PORTS = {
    20: "FTP-DATA",
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    67: "DHCP-SERVER",
    68: "DHCP-CLIENT",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    135: "MS-RPC",
    137: "NETBIOS-NS",
    138: "NETBIOS-DGM",
    139: "NETBIOS-SSN",
    143: "IMAP",
    161: "SNMP",
    162: "SNMP-TRAP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    514: "SYSLOG",
    636: "LDAPS",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "ORACLE",
    1900: "SSDP",
    2049: "NFS",
    3306: "MYSQL",
    3389: "RDP",
    5353: "MDNS",
    5355: "LLMNR",
    5432: "POSTGRESQL",
    5900: "VNC",
    5985: "WINRM-HTTP",
    5986: "WINRM-HTTPS",
    6379: "REDIS",
    7680: "DELIVERY-OPT",
    8080: "HTTP-ALT",
    8443: "HTTPS-ALT",
}

CLEARTEXT_PORTS = {
    21: "FTP",
    23: "TELNET",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    389: "LDAP",
    5900: "VNC",
}

DHCP_MESSAGE_TYPES = {
    1: "discover",
    2: "offer",
    3: "request",
    4: "decline",
    5: "ack",
    6: "nak",
    7: "release",
    8: "inform",
}

DNS_QTYPE_NAMES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    65: "HTTPS",
    255: "ANY",
}

DNS_RCODE_NAMES = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
}

ICMP_TYPE_NAMES = {
    0: "echo-reply",
    3: "destination-unreachable",
    4: "source-quench",
    5: "redirect",
    8: "echo-request",
    9: "router-advertisement",
    10: "router-solicitation",
    11: "time-exceeded",
    12: "parameter-problem",
    13: "timestamp-request",
    14: "timestamp-reply",
}

CSV_FIELDS = [
    "packet_number",
    "timestamp",
    "length",
    "severity",
    "direction",
    "protocols",
    "source_mac",
    "destination_mac",
    "source_ip",
    "destination_ip",
    "source_port",
    "destination_port",
    "service",
    "tcp_flags",
    "tcp_event",
    "icmp_type",
    "icmp_code",
    "dns_kind",
    "dns_qname",
    "dns_qtype",
    "dns_rcode",
    "http_method",
    "http_host",
    "http_uri",
    "observations",
]


def safe_text(value: Any) -> str:
    """Convert Scapy bytes and field values into readable text."""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace").rstrip(".")
    return str(value)


def packet_timestamp(packet: Packet) -> tuple[float, str]:
    """Return packet epoch and local ISO timestamp."""
    epoch = float(getattr(packet, "time", 0.0) or 0.0)
    if epoch <= 0:
        epoch = datetime.now().timestamp()

    readable = datetime.fromtimestamp(epoch).astimezone().isoformat(
        timespec="milliseconds"
    )
    return epoch, readable


def service_name(port: int | None) -> str:
    if port is None:
        return ""
    return COMMON_PORTS.get(int(port), "")


def port_text(port: int | None) -> str:
    if port is None:
        return "-"
    service = service_name(port)
    return f"{port}/{service}" if service else str(port)


def tcp_flags_text(flags: Any) -> str:
    """Convert a TCP flags value into readable names."""
    value = int(flags)
    names: list[str] = []

    mappings = (
        (0x100, "NS"),
        (0x080, "CWR"),
        (0x040, "ECE"),
        (0x020, "URG"),
        (0x010, "ACK"),
        (0x008, "PSH"),
        (0x004, "RST"),
        (0x002, "SYN"),
        (0x001, "FIN"),
    )

    for bit, name in mappings:
        if value & bit:
            names.append(name)

    return "+".join(names) if names else "NONE"


def tcp_event_name(flags: Any) -> str:
    """Classify common TCP flag combinations."""
    value = int(flags)

    syn = bool(value & 0x02)
    ack = bool(value & 0x10)
    rst = bool(value & 0x04)
    fin = bool(value & 0x01)
    psh = bool(value & 0x08)

    if syn and ack:
        return "SYN-ACK"
    if syn and not ack:
        return "SYN"
    if rst:
        return "RST"
    if fin:
        return "FIN"
    if psh and ack:
        return "PSH-ACK"
    if ack:
        return "ACK"

    return "OTHER"


def is_broadcast_ip(value: str) -> bool:
    try:
        address = ip_address(value)
    except ValueError:
        return False

    return str(address) == "255.255.255.255"


def network_direction(
    source: str | None,
    destination: str | None,
    local_networks: list[Any],
) -> str | None:
    """Classify traffic using local CIDRs plus multicast/broadcast awareness."""
    if not source or not destination:
        return None

    try:
        src_ip = ip_address(source)
        dst_ip = ip_address(destination)
    except ValueError:
        return None

    if dst_ip.is_multicast:
        return "MULTICAST"

    if is_broadcast_ip(destination):
        return "BROADCAST"

    if not local_networks:
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
    """Extract metadata-only DNS details."""
    if not packet.haslayer(DNS):
        return None

    dns = packet[DNS]
    rcode = int(dns.rcode)

    details: dict[str, Any] = {
        "kind": "response" if int(dns.qr) == 1 else "query",
        "id": int(dns.id),
        "rcode": rcode,
        "rcode_name": DNS_RCODE_NAMES.get(rcode, str(rcode)),
        "answers": int(dns.ancount or 0),
    }

    if packet.haslayer(DNSQR):
        qtype = int(packet[DNSQR].qtype)
        details["qname"] = safe_text(packet[DNSQR].qname)
        details["qtype"] = qtype
        details["qtype_name"] = DNS_QTYPE_NAMES.get(qtype, str(qtype))

    return details


def get_http_details(packet: Packet) -> dict[str, str] | None:
    """
    Extract a small amount of metadata from cleartext HTTP requests only.

    This does not decrypt HTTPS and intentionally avoids storing full payloads.
    """
    if not packet.haslayer(TCP) or not packet.haslayer(Raw):
        return None

    tcp = packet[TCP]
    if int(tcp.sport) not in (80, 8080) and int(tcp.dport) not in (80, 8080):
        return None

    payload = bytes(packet[Raw].load)
    try:
        text = payload.decode("iso-8859-1", errors="replace")
    except Exception:
        return None

    lines = text.splitlines()
    first_line = lines[0] if lines else ""
    parts = first_line.split()

    methods = {"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"}
    if len(parts) < 2 or parts[0] not in methods:
        return None

    host = ""
    for line in lines[1:]:
        if line.lower().startswith("host:"):
            host = line.split(":", 1)[1].strip()
            break

    return {
        "method": parts[0],
        "uri": parts[1],
        "host": host,
    }


def severity_for(observations: list[str]) -> str:
    """Return the highest triage severity for a packet record."""
    categories = {item.split(":", 1)[0] for item in observations}

    warning = {
        "ARP_MAC_CHANGE",
        "POSSIBLE_PORT_SCAN",
        "POSSIBLE_HOST_SCAN",
        "POSSIBLE_SYN_SCAN",
        "NULL_SCAN_PATTERN",
        "XMAS_SCAN_PATTERN",
    }

    notice = {
        "IP_FRAGMENT",
        "CLEARTEXT_SERVICE",
        "CLEARTEXT_HTTP",
        "DNS_ERROR_RCODE",
        "TCP_RST",
    }

    if categories & warning:
        return "WARNING"
    if categories & notice:
        return "NOTICE"
    if observations:
        return "INFO"

    return "NORMAL"


@dataclass
class ScanTracker:
    """Track SYN activity and classify simple scan-like patterns."""

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

        unique_pairs = {(dst, port) for _, dst, port in activity}
        unique_hosts = {dst for _, dst, _ in activity}
        unique_ports = {port for _, _, port in activity}

        if len(unique_pairs) < self.threshold:
            return []

        previous = self.last_alert.get(source_ip, 0.0)
        if timestamp - previous < self.window_seconds:
            return []

        self.last_alert[source_ip] = timestamp

        if len(unique_hosts) == 1 and len(unique_ports) >= self.threshold:
            return [
                f"POSSIBLE_PORT_SCAN:{source_ip}:"
                f"{len(unique_ports)}_ports_in_{self.window_seconds}s"
            ]

        if len(unique_hosts) >= self.threshold and len(unique_ports) <= 3:
            return [
                f"POSSIBLE_HOST_SCAN:{source_ip}:"
                f"{len(unique_hosts)}_hosts_in_{self.window_seconds}s"
            ]

        return [
            f"POSSIBLE_SYN_SCAN:{source_ip}:"
            f"{len(unique_pairs)}_targets_in_{self.window_seconds}s"
        ]


@dataclass
class ArpTracker:
    """Track observed IP-to-MAC mappings and flag changes."""

    mappings: dict[str, str] = field(default_factory=dict)

    def inspect(self, packet: Packet) -> list[str]:
        if not packet.haslayer(ARP):
            return []

        arp = packet[ARP]
        sender_ip = safe_text(arp.psrc)
        sender_mac = safe_text(arp.hwsrc).lower()

        if not sender_ip or sender_ip == "0.0.0.0":
            return []

        previous = self.mappings.get(sender_ip)
        self.mappings[sender_ip] = sender_mac

        if previous and previous != sender_mac:
            return [
                f"ARP_MAC_CHANGE:{sender_ip}:{previous}->{sender_mac}"
            ]

        return []


@dataclass
class CaptureStats:
    total: int = 0
    total_bytes: int = 0
    first_timestamp: float | None = None
    last_timestamp: float | None = None

    protocols: Counter[str] = field(default_factory=Counter)
    directions: Counter[str] = field(default_factory=Counter)
    source_ips: Counter[str] = field(default_factory=Counter)
    destination_ips: Counter[str] = field(default_factory=Counter)
    destination_ports: Counter[int] = field(default_factory=Counter)
    services: Counter[str] = field(default_factory=Counter)
    tcp_events: Counter[str] = field(default_factory=Counter)
    dns_queries: Counter[str] = field(default_factory=Counter)
    observations: Counter[str] = field(default_factory=Counter)

    def update(self, record: dict[str, Any]) -> None:
        self.total += 1
        self.total_bytes += int(record["length"])

        timestamp = float(record["timestamp_epoch"])
        if self.first_timestamp is None:
            self.first_timestamp = timestamp
        self.last_timestamp = timestamp

        for protocol in record["protocols"]:
            self.protocols[protocol] += 1

        direction = record.get("direction")
        if direction:
            self.directions[direction] += 1

        source_ip = record.get("source_ip")
        destination_ip = record.get("destination_ip")

        if source_ip:
            self.source_ips[source_ip] += 1
        if destination_ip:
            self.destination_ips[destination_ip] += 1

        destination_port = record.get("destination_port")
        if destination_port is not None:
            self.destination_ports[int(destination_port)] += 1
            service = service_name(int(destination_port))
            if service:
                self.services[service] += 1

        tcp_event = record.get("tcp_event")
        if tcp_event:
            self.tcp_events[tcp_event] += 1

        dns = record.get("dns")
        if dns and dns.get("kind") == "query" and dns.get("qname"):
            self.dns_queries[dns["qname"]] += 1

        for observation in record["observations"]:
            category = observation.split(":", maxsplit=1)[0]
            self.observations[category] += 1

    @property
    def duration(self) -> float:
        if self.first_timestamp is None or self.last_timestamp is None:
            return 0.0
        return max(0.0, self.last_timestamp - self.first_timestamp)

    @property
    def packet_rate(self) -> float:
        if self.duration <= 0:
            return 0.0
        return self.total / self.duration


class PacketProcessor:
    def __init__(
        self,
        *,
        local_networks: list[Any],
        json_file: TextIO | None,
        csv_writer: csv.DictWriter | None,
        csv_file: TextIO | None,
        pcap_writer: PcapWriter | None,
        quiet: bool,
        hunt: bool,
        scan_threshold: int,
        scan_window: int,
    ) -> None:
        self.local_networks = local_networks
        self.json_file = json_file
        self.csv_writer = csv_writer
        self.csv_file = csv_file
        self.pcap_writer = pcap_writer
        self.quiet = quiet
        self.hunt = hunt

        self.stats = CaptureStats()
        self.scan_tracker = ScanTracker(
            threshold=scan_threshold,
            window_seconds=scan_window,
        )
        self.arp_tracker = ArpTracker()

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

            if self.csv_writer is not None and self.csv_file is not None:
                self.csv_writer.writerow(self.csv_record(record))
                self.csv_file.flush()

            should_print = not self.quiet
            if self.hunt:
                should_print = should_print and bool(record["observations"])

            if should_print:
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

            operation = {
                1: "request",
                2: "reply",
            }.get(int(arp.op), str(int(arp.op)))

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

            observations.extend(self.arp_tracker.inspect(packet))

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
            source_ip,
            destination_ip,
            self.local_networks,
        )

        if packet.haslayer(TCP):
            protocols.append("TCP")
            tcp = packet[TCP]

            source_port = int(tcp.sport)
            destination_port = int(tcp.dport)
            numeric_flags = int(tcp.flags)

            record["source_port"] = source_port
            record["destination_port"] = destination_port
            record["service"] = service_name(destination_port)
            record["tcp_flags"] = tcp_flags_text(tcp.flags)
            record["tcp_event"] = tcp_event_name(tcp.flags)
            record["sequence"] = int(tcp.seq)
            record["acknowledgement"] = int(tcp.ack)
            record["window"] = int(tcp.window)

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

            if numeric_flags & 0x04:
                observations.append("TCP_RST")

            if destination_port in CLEARTEXT_PORTS:
                observations.append(
                    f"CLEARTEXT_SERVICE:{CLEARTEXT_PORTS[destination_port]}"
                )

        elif packet.haslayer(UDP):
            protocols.append("UDP")
            udp = packet[UDP]

            record["source_port"] = int(udp.sport)
            record["destination_port"] = int(udp.dport)
            record["service"] = service_name(int(udp.dport))

        elif packet.haslayer(ICMP):
            protocols.append("ICMP")
            icmp = packet[ICMP]

            icmp_type = int(icmp.type)
            record["icmp_type"] = icmp_type
            record["icmp_code"] = int(icmp.code)
            record["icmp_message"] = ICMP_TYPE_NAMES.get(
                icmp_type,
                str(icmp_type),
            )

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

            if (
                dns_details["kind"] == "response"
                and dns_details["rcode"] != 0
            ):
                observations.append(
                    f"DNS_ERROR_RCODE:{dns_details['rcode_name']}"
                )

        dhcp_type = get_dhcp_message_type(packet)
        if dhcp_type is not None:
            protocols.append("DHCP")
            record["dhcp_message_type"] = dhcp_type

        http_details = get_http_details(packet)
        if http_details is not None:
            protocols.append("HTTP")
            record["http"] = http_details
            observations.append("CLEARTEXT_HTTP")

        observations.extend(
            self.scan_tracker.inspect(
                timestamp_epoch,
                source_ip,
                destination_ip,
                packet,
            )
        )

        record["severity"] = severity_for(observations)
        return record

    @staticmethod
    def csv_record(record: dict[str, Any]) -> dict[str, Any]:
        dns = record.get("dns", {})
        http = record.get("http", {})

        return {
            "packet_number": record.get("packet_number", ""),
            "timestamp": record.get("timestamp", ""),
            "length": record.get("length", ""),
            "severity": record.get("severity", ""),
            "direction": record.get("direction", ""),
            "protocols": ",".join(record.get("protocols", [])),
            "source_mac": record.get("source_mac", ""),
            "destination_mac": record.get("destination_mac", ""),
            "source_ip": record.get("source_ip", ""),
            "destination_ip": record.get("destination_ip", ""),
            "source_port": record.get("source_port", ""),
            "destination_port": record.get("destination_port", ""),
            "service": record.get("service", ""),
            "tcp_flags": record.get("tcp_flags", ""),
            "tcp_event": record.get("tcp_event", ""),
            "icmp_type": record.get("icmp_type", ""),
            "icmp_code": record.get("icmp_code", ""),
            "dns_kind": dns.get("kind", ""),
            "dns_qname": dns.get("qname", ""),
            "dns_qtype": dns.get("qtype_name", ""),
            "dns_rcode": dns.get("rcode_name", ""),
            "http_method": http.get("method", ""),
            "http_host": http.get("host", ""),
            "http_uri": http.get("uri", ""),
            "observations": ",".join(record.get("observations", [])),
        }

    @staticmethod
    def format_console_line(record: dict[str, Any]) -> str:
        parts = [
            f"[{record['timestamp']}]",
            f"#{record['packet_number']:05d}",
            record.get("severity", "NORMAL"),
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
                    "IPv6"
                    if "IPv6" in record["protocols"]
                    else "IPv4"
                )
                parts.append(
                    f"{ip_version} {source_ip} -> {destination_ip}"
                )

        if "TCP" in record["protocols"]:
            parts.append(
                f"TCP {port_text(record.get('source_port'))} -> "
                f"{port_text(record.get('destination_port'))} "
                f"flags={record.get('tcp_flags', '')} "
                f"event={record.get('tcp_event', '')}"
            )

        elif "UDP" in record["protocols"]:
            parts.append(
                f"UDP {port_text(record.get('source_port'))} -> "
                f"{port_text(record.get('destination_port'))}"
            )

        elif "ICMP" in record["protocols"]:
            parts.append(
                f"ICMP {record.get('icmp_message', '')} "
                f"type={record.get('icmp_type')} "
                f"code={record.get('icmp_code')}"
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

            if dns.get("qtype_name"):
                dns_text += f" type={dns['qtype_name']}"

            if dns["kind"] == "response":
                dns_text += (
                    f" answers={dns['answers']} "
                    f"rcode={dns['rcode_name']}"
                )

            parts.append(dns_text)

        if record.get("dhcp_message_type"):
            parts.append(
                f"DHCP {record['dhcp_message_type']}"
            )

        if "http" in record:
            http = record["http"]
            parts.append(
                f"HTTP {http['method']} "
                f"host={http.get('host') or '-'} "
                f"uri={http.get('uri') or '-'}"
            )

        if record["observations"]:
            parts.append(
                "OBS=" + ",".join(record["observations"])
            )

        return " | ".join(parts)


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Passive Scapy packet capture and PCAP triage for authorised use."
        )
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {VERSION}",
    )

    parser.add_argument(
        "--list-interfaces",
        action="store_true",
        help="List Scapy interfaces and exit.",
    )

    parser.add_argument(
        "-i",
        "--interface",
        help="Live-capture interface. Default: Scapy's chosen interface.",
    )

    parser.add_argument(
        "-r",
        "--read",
        type=Path,
        help="Read an existing PCAP/PCAPNG instead of live capture.",
    )

    parser.add_argument(
        "-f",
        "--filter",
        default="",
        help='BPF filter, for example: "tcp or udp or icmp".',
    )

    parser.add_argument(
        "-c",
        "--count",
        type=int,
        default=0,
        help="Stop after this many packets. Zero means unlimited.",
    )

    parser.add_argument(
        "-t",
        "--timeout",
        type=int,
        default=None,
        help="Stop after this many seconds.",
    )

    parser.add_argument(
        "--local-network",
        action="append",
        default=[],
        metavar="CIDR",
        help="CIDR for IN/OUT/LAN labels. May be repeated.",
    )

    parser.add_argument(
        "--pcap-out",
        type=Path,
        help="Save processed packets to a PCAP file.",
    )

    parser.add_argument(
        "--jsonl-out",
        type=Path,
        help="Save one structured JSON record per packet.",
    )

    parser.add_argument(
        "--csv-out",
        type=Path,
        help="Save structured packet metadata to CSV.",
    )

    parser.add_argument(
        "--session",
        metavar="NAME",
        help=(
            "Create timestamped PCAP, JSONL, and CSV files automatically "
            "using NAME."
        ),
    )

    parser.add_argument(
        "--hunt",
        action="store_true",
        help=(
            "Analyse all packets but only print packets containing "
            "triage observations."
        ),
    )

    parser.add_argument(
        "--scan-threshold",
        type=int,
        default=20,
        help="Unique TCP SYN targets required for a scan observation.",
    )

    parser.add_argument(
        "--scan-window",
        type=int,
        default=10,
        help="Seconds used by the TCP SYN scan heuristic.",
    )

    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Suppress packet lines; still write files and final statistics.",
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

    if args.read is not None and args.interface:
        raise ValueError(
            "--read and --interface cannot be used together."
        )

    local_networks = []

    for value in args.local_network:
        try:
            local_networks.append(
                ip_network(value, strict=False)
            )
        except ValueError as error:
            raise ValueError(
                f"Invalid --local-network value '{value}': {error}"
            ) from error

    return local_networks


def ensure_parent(path: Path | None) -> None:
    if path is not None:
        path.expanduser().resolve().parent.mkdir(
            parents=True,
            exist_ok=True,
        )


def configure_session_outputs(
    args: argparse.Namespace,
) -> None:
    if not args.session:
        return

    safe_name = "".join(
        character
        if character.isalnum() or character in ("-", "_")
        else "_"
        for character in args.session
    ).strip("_")

    if not safe_name:
        safe_name = "session"

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    if args.pcap_out is None:
        args.pcap_out = Path(
            "captures",
            f"{safe_name}_{timestamp}.pcap",
        )

    if args.jsonl_out is None:
        args.jsonl_out = Path(
            "output",
            f"{safe_name}_{timestamp}.jsonl",
        )

    if args.csv_out is None:
        args.csv_out = Path(
            "output",
            f"{safe_name}_{timestamp}.csv",
        )


def print_counter(
    title: str,
    counter: Counter[Any],
    *,
    limit: int = 10,
    formatter=lambda value: str(value),
) -> None:
    if not counter:
        return

    print(title)

    for value, count in counter.most_common(limit):
        print(f"  {formatter(value):<42} {count}")


def print_statistics(stats: CaptureStats) -> None:
    print("\n" + "=" * 62)
    print("HOWLR PACKET SENTINEL - CAPTURE SUMMARY")
    print("=" * 62)

    print(f"Packets analysed : {stats.total}")
    print(f"Bytes analysed   : {stats.total_bytes}")

    if stats.duration > 0:
        print(f"Duration         : {stats.duration:.2f} seconds")
        print(f"Packet rate      : {stats.packet_rate:.2f} packets/sec")

    print_counter(
        "\nProtocols:",
        stats.protocols,
    )

    print_counter(
        "\nDirections:",
        stats.directions,
    )

    print_counter(
        "\nTop source IPs:",
        stats.source_ips,
        limit=10,
    )

    print_counter(
        "\nTop destination IPs:",
        stats.destination_ips,
        limit=10,
    )

    print_counter(
        "\nTop destination ports:",
        stats.destination_ports,
        limit=10,
        formatter=lambda port: port_text(int(port)),
    )

    print_counter(
        "\nTop services:",
        stats.services,
        limit=10,
    )

    print_counter(
        "\nTCP events:",
        stats.tcp_events,
        limit=10,
    )

    print_counter(
        "\nTop DNS queries:",
        stats.dns_queries,
        limit=10,
    )

    print_counter(
        "\nObservations:",
        stats.observations,
        limit=20,
    )

    print(
        "\nNote: observations are triage hints, "
        "not proof of malicious activity."
    )
    print("=" * 62)


def main() -> int:
    args = parse_arguments()

    if args.list_interfaces:
        show_interfaces()
        return 0

    configure_session_outputs(args)

    try:
        local_networks = validate_arguments(args)
    except ValueError as error:
        print(
            f"Configuration error: {error}",
            file=sys.stderr,
        )
        return 2

    ensure_parent(args.pcap_out)
    ensure_parent(args.jsonl_out)
    ensure_parent(args.csv_out)

    json_file: TextIO | None = None
    csv_file: TextIO | None = None
    csv_writer: csv.DictWriter | None = None
    pcap_writer: PcapWriter | None = None
    processor: PacketProcessor | None = None

    try:
        if args.jsonl_out is not None:
            json_file = args.jsonl_out.open(
                "w",
                encoding="utf-8",
                buffering=1,
            )

        if args.csv_out is not None:
            csv_file = args.csv_out.open(
                "w",
                encoding="utf-8",
                newline="",
                buffering=1,
            )
            csv_writer = csv.DictWriter(
                csv_file,
                fieldnames=CSV_FIELDS,
                extrasaction="ignore",
            )
            csv_writer.writeheader()

        if args.pcap_out is not None:
            pcap_writer = PcapWriter(
                str(args.pcap_out),
                append=False,
                sync=True,
            )

        processor = PacketProcessor(
            local_networks=local_networks,
            json_file=json_file,
            csv_writer=csv_writer,
            csv_file=csv_file,
            pcap_writer=pcap_writer,
            quiet=args.quiet,
            hunt=args.hunt,
            scan_threshold=args.scan_threshold,
            scan_window=args.scan_window,
        )

        source_description = (
            f"offline file {args.read}"
            if args.read is not None
            else f"interface {args.interface or conf.iface}"
        )

        print(f"Howlr Packet Sentinel v{VERSION}")
        print(f"Source: {source_description}")
        print(f"BPF filter: {args.filter or '(none)'}")
        print(
            f"Packet limit: {args.count or 'unlimited'} | "
            f"Timeout: {args.timeout or 'none'}"
        )

        if local_networks:
            print(
                "Local networks: "
                + ", ".join(str(network) for network in local_networks)
            )

        if args.hunt:
            print(
                "Mode: HUNT "
                "(only packets with observations are printed)"
            )

        if args.pcap_out:
            print(f"PCAP output: {args.pcap_out}")

        if args.jsonl_out:
            print(f"JSONL output: {args.jsonl_out}")

        if args.csv_out:
            print(f"CSV output: {args.csv_out}")

        if args.read is None:
            print("Press Ctrl+C to stop a live capture.\n")
        else:
            print()

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
        print(
            f"Capture failed: {error}",
            file=sys.stderr,
        )
        print(
            "Check the interface, BPF filter, permissions, "
            "and Npcap/libpcap.",
            file=sys.stderr,
        )
        return 1

    except Exception as error:
        print(
            f"Unexpected failure: {error}",
            file=sys.stderr,
        )
        return 1

    finally:
        if pcap_writer is not None:
            pcap_writer.close()

        if json_file is not None:
            json_file.close()

        if csv_file is not None:
            csv_file.close()

    if processor is not None:
        print_statistics(processor.stats)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
