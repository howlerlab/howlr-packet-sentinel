# Changelog

All notable changes to Howlr Packet Sentinel are documented here.

---

## [Unreleased] - v0.2.0 Development

### Added

- `--version`.
- CSV export with `--csv-out`.
- Automatic timestamped PCAP, JSONL and CSV output with `--session`.
- Hunt mode with `--hunt`.
- Direction labels for `LAN`, `IN`, `OUT`, `TRANSIT`, `MULTICAST` and `BROADCAST`.
- Readable TCP flag names.
- TCP event labels including `SYN`, `SYN-ACK`, `ACK`, `PSH-ACK`, `RST` and `FIN`.
- Basic SYN scan heuristics:
  - `POSSIBLE_PORT_SCAN`
  - `POSSIBLE_HOST_SCAN`
  - `POSSIBLE_SYN_SCAN`
- ARP IP-to-MAC mapping tracking.
- `ARP_MAC_CHANGE` observation.
- DNS query-type names.
- DNS response-code names such as `NOERROR` and `NXDOMAIN`.
- Readable ICMP type names.
- Cleartext HTTP request metadata parsing for supported HTTP traffic.
- Packet severity labels: `NORMAL`, `INFO`, `NOTICE`, `WARNING`.
- Expanded statistics for bytes, duration, packet rate, directions, destinations, services, TCP events and DNS queries.

### Changed

- Improved console packet formatting.
- TCP flags are displayed as readable names instead of only compact Scapy flag letters.
- Multicast traffic is classified separately from ordinary outbound traffic.
- Capture summaries provide more triage context.
- Runtime output directories are created automatically when required.
- Generated `captures/` and `output/` content remains excluded from Git.
- `--read` and `--interface` are mutually exclusive.
- Documentation updated for v0.2.0 installation, operation and troubleshooting.

### Validated

Manual testing has confirmed:

- `--version`
- CLI help
- interface listing
- Windows live capture
- IPv4 and IPv6 parsing
- TCP and UDP parsing
- ARP parsing
- DNS parsing
- service labels
- TCP event labels
- `LAN`, `IN`, `OUT` and `MULTICAST` classification
- PCAP export
- JSONL export
- CSV export
- `--session`
- offline PCAP re-analysis
- quiet summary mode
- enhanced statistics

### Still to Validate Before Release

- deliberate `--hunt` workflow testing
- controlled port-scan heuristic detection
- controlled host-scan heuristic detection
- ARP MAC-change observation
- cleartext HTTP request metadata
- Kali/Linux live-capture regression testing for v0.2.0

---

## [0.1.0] - Initial Release

### Added

- Initial Scapy-based passive packet-capture tool.
- Live packet capture.
- Offline PCAP and PCAPNG analysis.
- Ethernet and ARP summaries.
- IPv4 and IPv6 summaries.
- TCP, UDP, ICMP and ICMPv6 summaries.
- DNS metadata parsing.
- DHCP message-type parsing.
- Common service-name labels.
- Basic TCP SYN observation.
- NULL and XMAS scan-pattern observations.
- IP-fragment observation.
- DNS error-code observation.
- Cleartext service-port observation.
- Configurable packet count and timeout.
- BPF capture filters.
- Local CIDR direction classification.
- PCAP export.
- JSONL export.
- Protocol and endpoint statistics.
- Quiet summary mode.
- Windows and Kali/Linux support.
- MIT License.
- GitHub repository and project documentation.
