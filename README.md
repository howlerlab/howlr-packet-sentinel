# Howlr Packet Sentinel

**Howlr Packet Sentinel** is a lightweight command-line packet capture and network triage tool written in Python using Scapy.

It supports live packet capture, offline PCAP analysis, protocol and service identification, traffic direction classification, structured exports, and basic security-focused observations.

> Designed for authorised security labs, troubleshooting, learning, and defensive network analysis.

## Current Version

**v0.2.0**

## Features

### Packet Capture

- Live packet capture from a selected network interface
- Offline PCAP/PCAPNG analysis
- BPF capture filters
- Packet-count limits
- Capture timeouts
- Interface discovery

### Protocol Analysis

Howlr Packet Sentinel can identify and summarise:

- Ethernet
- ARP
- IPv4
- IPv6
- TCP
- UDP
- ICMP
- ICMPv6
- DNS
- mDNS
- HTTP

### Service Identification

Common services are labelled automatically where possible, including:

- HTTP
- HTTPS
- DNS
- mDNS
- SSDP
- SSH
- FTP
- Telnet
- SMB
- RDP

Service identification is based primarily on known TCP/UDP ports and should be treated as a triage aid rather than proof of the actual application protocol.

### Traffic Direction

Specify one or more local networks using `--local-network` to classify traffic as:

- `IN`
- `OUT`
- `LAN`
- `MULTICAST`
- `BROADCAST`
- `TRANSIT`

Example:

```text
--local-network 192.168.1.0/24
```

### TCP Events

TCP flags are converted into readable events such as:

- `SYN`
- `SYN-ACK`
- `ACK`
- `PSH-ACK`
- `FIN`
- `RST`

### DNS Analysis

DNS traffic can include:

- query name
- query type
- response count
- response code

DNS error response codes may generate observations.

### HTTP Triage

Unencrypted HTTP traffic may expose metadata such as:

- HTTP method
- Host header
- URI

Example:

```text
HTTP GET host=example.com uri=/
```

### Security Observations

Howlr Packet Sentinel includes lightweight triage observations such as:

- `TCP_SYN`
- `TCP_RST`
- `ARP_REPLY`
- `ARP_MAC_CHANGE`
- `DNS_ERROR_RCODE`
- `CLEARTEXT_SERVICE`
- `CLEARTEXT_HTTP`
- `POSSIBLE_PORT_SCAN`

These observations are intended to highlight traffic worth investigating.

**They are not proof of malicious activity.**

### Hunt Mode

`--hunt` analyses all captured packets but only prints packets containing observations.

This is useful when normal packet output is too noisy.

### Structured Output

Captured data can be exported as:

- PCAP
- JSONL
- CSV

Session mode can automatically create timestamped versions of all three.

---

# Requirements

- Python 3
- Scapy
- Npcap on Windows
- Administrator/root privileges may be required for live packet capture

Install Python dependencies:

```text
pip install -r requirements.txt
```

## Windows

Install Npcap before performing live capture.

Npcap should normally be installed with WinPcap API compatibility enabled.

## Linux / Kali

Live packet capture generally requires root privileges, so commands may need to be run using `sudo`.

---

# Getting Started

## 1. List Network Interfaces

Do this first instead of guessing the interface name.

### Windows / PowerShell

```powershell
python .\howlr_packet_sentinel.py --list-interfaces
```

### Linux / Kali

```bash
python3 howlr_packet_sentinel.py --list-interfaces
```

Example:

```text
Source  Index  Name     MAC                IPv4
sys     1      lo       00:00:00:00:00:00  127.0.0.1
sys     2      eth0     00:0c:29:12:34:56  192.168.1.50
```

Use the interface **name** shown by Howlr Packet Sentinel.

For example:

```text
eth0
```

or:

```text
Realtek PCIe GbE Family Controller
```

> Numeric interface indexes displayed by `--list-interfaces` are informational and are not currently accepted by `-i` in v0.2.0.

---

# Basic Usage

## Windows

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" -c 20
```

Example:

```powershell
python .\howlr_packet_sentinel.py -i "Realtek PCIe GbE Family Controller" -c 20
```

## Linux / Kali

When using the project's virtual environment:

```bash
sudo .venv/bin/python howlr_packet_sentinel.py -i eth0 -c 20
```

Or, if Scapy is installed for the system Python:

```bash
sudo python3 howlr_packet_sentinel.py -i eth0 -c 20
```

---

# Practical Examples

## Capture 50 Packets

### Windows

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" -c 50
```

### Linux

```bash
sudo .venv/bin/python howlr_packet_sentinel.py -i eth0 -c 50
```

## Capture for 30 Seconds

### Windows

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" -t 30
```

### Linux

```bash
sudo .venv/bin/python howlr_packet_sentinel.py -i eth0 -t 30
```

## Classify Traffic Direction

Replace the example network with your actual local subnet.

### Windows

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" --local-network 192.168.1.0/24 -c 50
```

### Linux

```bash
sudo .venv/bin/python howlr_packet_sentinel.py -i eth0 --local-network 192.168.1.0/24 -c 50
```

This enables labels such as:

```text
IN
OUT
LAN
MULTICAST
BROADCAST
TRANSIT
```

## Hunt Mode

Only print packets containing triage observations.

### Windows

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" --local-network 192.168.1.0/24 --hunt -t 30
```

### Linux

```bash
sudo .venv/bin/python howlr_packet_sentinel.py -i eth0 --local-network 192.168.1.0/24 --hunt -t 30
```

Example output:

```text
NOTICE | OUT | IPv4 192.168.1.50 -> 93.184.216.34 | TCP 50000 -> 80/HTTP | OBS=CLEARTEXT_SERVICE:HTTP
```

## Capture Only TCP Traffic

```text
-f "tcp"
```

Windows:

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" -f "tcp" -c 50
```

Linux:

```bash
sudo .venv/bin/python howlr_packet_sentinel.py -i eth0 -f "tcp" -c 50
```

## Capture TCP, UDP and ICMP

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" -f "tcp or udp or icmp" -c 100
```

Linux:

```bash
sudo .venv/bin/python howlr_packet_sentinel.py -i eth0 -f "tcp or udp or icmp" -c 100
```

## Capture DNS Traffic

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" -f "port 53" -c 50
```

Linux:

```bash
sudo .venv/bin/python howlr_packet_sentinel.py -i eth0 -f "port 53" -c 50
```

## Capture HTTP Traffic

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" -f "tcp port 80" --hunt -t 30
```

Linux:

```bash
sudo .venv/bin/python howlr_packet_sentinel.py -i eth0 -f "tcp port 80" --hunt -t 30
```

Unencrypted HTTP may produce output such as:

```text
HTTP GET host=example.com uri=/ | OBS=CLEARTEXT_SERVICE:HTTP,CLEARTEXT_HTTP
```

HTTPS payloads are encrypted, so Howlr Packet Sentinel cannot extract HTTP methods, hosts or URIs from ordinary TLS-encrypted HTTPS traffic.

---

# Session Capture

Session mode automatically creates timestamped PCAP, JSONL and CSV files.

Example:

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" --local-network 192.168.1.0/24 --session office-test -c 100
```

Linux:

```bash
sudo .venv/bin/python howlr_packet_sentinel.py -i eth0 --local-network 192.168.1.0/24 --session kali-test -c 100
```

Example generated files:

```text
captures/office-test_YYYYMMDD_HHMMSS.pcap
output/office-test_YYYYMMDD_HHMMSS.jsonl
output/office-test_YYYYMMDD_HHMMSS.csv
```

The `captures/` and `output/` directories are generated automatically when required and are excluded from Git by the supplied `.gitignore`.

---

# Individual Output Files

## Save PCAP

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" -c 100 --pcap-out capture.pcap
```

## Save JSONL

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" -c 100 --jsonl-out packets.jsonl
```

## Save CSV

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" -c 100 --csv-out packets.csv
```

Multiple output options can be used together.

---

# Offline PCAP Analysis

Existing packet captures can be analysed without performing a live capture.

```powershell
python .\howlr_packet_sentinel.py -r .\captures\capture.pcap
```

Linux:

```bash
python3 howlr_packet_sentinel.py -r ./captures/capture.pcap
```

Add a local network to enable direction classification:

```powershell
python .\howlr_packet_sentinel.py -r .\captures\capture.pcap --local-network 192.168.1.0/24
```

Quiet mode is useful when only the final statistics are required:

```powershell
python .\howlr_packet_sentinel.py -r .\captures\capture.pcap --local-network 192.168.1.0/24 -q
```

---

# Port-Scan Triage

Howlr Packet Sentinel maintains a lightweight TCP SYN heuristic.

The default behaviour looks for a source contacting multiple unique TCP destinations within a configured time window.

Options:

```text
--scan-threshold
--scan-window
```

Example:

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" --local-network 192.168.1.0/24 --hunt --scan-threshold 10 --scan-window 5 -t 60
```

Possible observation:

```text
POSSIBLE_PORT_SCAN
```

This is a heuristic only. Legitimate software can create traffic patterns that resemble scanning.

---

# ARP Change Detection

Howlr Packet Sentinel tracks observed ARP IP-to-MAC mappings during a capture.

If the same IP address is subsequently observed using a different MAC address, it can generate:

```text
ARP_MAC_CHANGE
```

Example:

```text
OBS=ARP_REPLY,ARP_MAC_CHANGE:192.168.1.50:02:00:00:00:00:01->02:00:00:00:00:02
```

This can be useful during ARP-spoofing investigations, but an address change is not automatically malicious. DHCP changes, failover systems, virtualisation and legitimate network changes can also affect mappings.

---

# Quiet Mode

Use `-q` or `--quiet` to suppress individual packet lines while still generating the final summary and requested output files.

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" --local-network 192.168.1.0/24 -t 30 -q
```

This is particularly useful for longer captures.

---

# Capture Summary

At the end of a capture, Howlr Packet Sentinel can report:

- packets analysed
- bytes analysed
- capture duration
- packet rate
- protocol counts
- traffic directions
- top source IP addresses
- top destination IP addresses
- top destination ports
- top services
- TCP events
- DNS queries
- observation counts

Example:

```text
==============================================================
HOWLR PACKET SENTINEL - CAPTURE SUMMARY
==============================================================
Packets analysed : 50

Protocols:
  Ethernet
  IPv4
  TCP
  UDP

Directions:
  IN
  OUT
  LAN

Top services:
  HTTPS
  DNS

Observations:
  TCP_SYN
  CLEARTEXT_HTTP

Note: observations are triage hints, not proof of malicious activity.
==============================================================
```

---

# Command Reference

```text
-h, --help
--version
--list-interfaces

-i, --interface INTERFACE
-r, --read FILE
-f, --filter FILTER
-c, --count COUNT
-t, --timeout SECONDS

--local-network CIDR

--pcap-out FILE
--jsonl-out FILE
--csv-out FILE
--session NAME

--hunt

--scan-threshold NUMBER
--scan-window SECONDS

-q, --quiet
```

View the current command reference directly:

```powershell
python .\howlr_packet_sentinel.py --help
```

Linux:

```bash
python3 howlr_packet_sentinel.py --help
```

---

# Troubleshooting

## Interface Not Found

Run:

```text
--list-interfaces
```

and copy the interface **name** exactly.

For example:

```powershell
python .\howlr_packet_sentinel.py -i "Realtek PCIe GbE Family Controller" -c 20
```

In v0.2.0, do not substitute the displayed numeric interface index for the interface name.

## No Packets Captured

Confirm:

1. the selected interface is active;
2. traffic is actually passing through that interface;
3. the capture filter is not too restrictive;
4. the process has sufficient privileges.

Generate ordinary network traffic while testing, for example by opening a website.

## Linux Permission Error

Try running the capture with `sudo`:

```bash
sudo .venv/bin/python howlr_packet_sentinel.py -i eth0 -c 20
```

## Windows Capture Problems

Confirm that Npcap is installed and that PowerShell or the terminal has sufficient privileges.

## Hunt Mode Prints Nothing

`--hunt` suppresses packets that do not contain observations.

A completely quiet hunt-mode screen can therefore be normal.

Check the final summary to see whether packets were analysed.

---

# Tested Platforms

v0.2.0 has been manually validated on:

- Windows
- Kali Linux

Validation included:

- interface discovery
- live packet capture
- offline PCAP replay
- IPv4 and IPv6 processing
- TCP and UDP parsing
- ARP processing
- DNS/mDNS parsing
- traffic direction classification
- service identification
- TCP event classification
- hunt mode
- cleartext HTTP detection
- HTTP method, Host and URI extraction
- ARP MAC-change detection
- TCP SYN scan heuristic
- PCAP export
- JSONL export
- CSV export
- session capture
- quiet mode
- capture summaries

---

# Project Status

Howlr Packet Sentinel is an educational and defensive security project under active development.

v0.2.0 focuses on improving packet triage, structured output, traffic classification and practical command-line usability.

Future releases may improve:

- automatic active-interface selection
- automatic local-network detection
- simplified command-line installation
- shorter executable command such as `howlr`
- additional protocol analysis
- improved detection heuristics
- richer session reporting

---

# Authorised Use

Use Howlr Packet Sentinel only on systems and networks that you own or have explicit permission to monitor.

Packet capture may expose sensitive information belonging to other users.

The security observations generated by this tool are **triage hints, not proof of malicious activity**.

---

# Licence

See `LICENSE`.