# Howlr Packet Sentinel — Usage Guide

This is the detailed command and workflow guide for **Howlr Packet Sentinel v0.2.0**.

For installation, see **[INSTALL.md](INSTALL.md)**.  
For observation meanings, directions and severities, see **[docs/OBSERVATIONS.md](docs/OBSERVATIONS.md)**.  
For capture problems, see **[docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md)**.

---

# General Syntax

## Live Capture — Windows

```text
python .\howlr_packet_sentinel.py -i "<INTERFACE>" [OPTIONS]
```

## Live Capture — Kali / Linux

```text
sudo .venv/bin/python howlr_packet_sentinel.py -i <INTERFACE> [OPTIONS]
```

## Offline Analysis — Windows

```text
python .\howlr_packet_sentinel.py -r <PCAP_FILE> [OPTIONS]
```

## Offline Analysis — Linux

```text
.venv/bin/python howlr_packet_sentinel.py -r <PCAP_FILE> [OPTIONS]
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

Always check the program itself for the current CLI:

### Windows

```powershell
python .\howlr_packet_sentinel.py --help
```

### Linux

```bash
.venv/bin/python howlr_packet_sentinel.py --help
```

---

# Version

```powershell
python .\howlr_packet_sentinel.py --version
```

Expected:

```text
howlr_packet_sentinel.py 0.2.0
```

---

# Interface Discovery

### Windows

```powershell
python .\howlr_packet_sentinel.py --list-interfaces
```

### Linux

```bash
.venv/bin/python howlr_packet_sentinel.py --list-interfaces
```

Use the exact interface name.

Examples:

```text
Realtek PCIe GbE Family Controller
eth0
```

v0.2.0 does not accept the displayed numeric index in place of the interface name.

---

# Basic Live Capture

## Capture 20 Packets

### Windows

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" -c 20
```

### Linux

```bash
sudo .venv/bin/python howlr_packet_sentinel.py -i eth0 -c 20
```

---

# Packet Count

Capture 50 packets:

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" -c 50
```

Capture 500 packets:

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" -c 500
```

---

# Timeout

Capture for 30 seconds:

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" -t 30
```

Capture for one minute:

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" -t 60
```

Capture for five minutes:

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" -t 300
```

---

# Count and Timeout Together

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" -c 500 -t 60
```

This is useful when you want a safety ceiling on both time and traffic volume.

---

# Local-Network Classification

Add:

```text
--local-network 192.168.1.0/24
```

Example:

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" --local-network 192.168.1.0/24 -c 50
```

Linux:

```bash
sudo .venv/bin/python howlr_packet_sentinel.py -i eth0 --local-network 192.168.1.0/24 -c 50
```

This enables:

```text
IN
OUT
LAN
MULTICAST
BROADCAST
TRANSIT
```

See **[docs/OBSERVATIONS.md](docs/OBSERVATIONS.md)** for detailed interpretation.

---

# Reading a Packet Line

Example:

```text
[2026-08-21T21:56:36.218+08:00] | #00015 | NOTICE | len=129 | OUT | MAC 00:0c:29:20:e5:73 -> 00:50:56:e3:47:2d | IPv4 192.168.42.130 -> 104.20.23.154 | TCP 50836 -> 80/HTTP flags=ACK+PSH event=PSH-ACK | HTTP GET host=example.com uri=/ | OBS=CLEARTEXT_SERVICE:HTTP,CLEARTEXT_HTTP
```

Breakdown:

```text
timestamp       2026-08-21T21:56:36.218+08:00
packet number   #00015
severity        NOTICE
length          len=129
direction       OUT
Ethernet        source MAC -> destination MAC
IPv4            source IP -> destination IP
TCP             source port -> destination port/service
flags           ACK+PSH
event           PSH-ACK
HTTP            GET / on example.com
observations    CLEARTEXT_SERVICE + CLEARTEXT_HTTP
```

---

# BPF Filters

Howlr accepts BPF filters through `-f` / `--filter`.

A BPF filter limits packets before Howlr analyses them.

## TCP Only

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" -f "tcp" -c 100
```

## UDP Only

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" -f "udp" -c 100
```

## ICMP Only

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" -f "icmp" -c 100
```

## TCP, UDP and ICMP

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" -f "tcp or udp or icmp" -c 100
```

## DNS

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" -f "port 53" -t 60
```

## HTTP

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" -f "tcp port 80" -t 60
```

## HTTPS

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" -f "tcp port 443" -t 60
```

## One Host

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" -f "host 192.168.1.50" -t 60
```

## Source Host

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" -f "src host 192.168.1.50" -t 60
```

## Destination Host

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" -f "dst host 192.168.1.50" -t 60
```

## One Port

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" -f "port 22" -t 60
```

## Host and Port

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" -f "host 192.168.1.20 and tcp port 22" -t 60
```

## Exclude a Port

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" -f "not port 22" -t 60
```

If a filter captures nothing, remove the filter and confirm that normal capture works first.

---

# Hunt Mode

Enable with:

```text
--hunt
```

### Windows

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" --local-network 192.168.1.0/24 --hunt -t 60
```

### Linux

```bash
sudo .venv/bin/python howlr_packet_sentinel.py -i eth0 --local-network 192.168.1.0/24 --hunt -t 60
```

Hunt Mode:

```text
captures all matching packets
        ↓
analyses them
        ↓
updates statistics
        ↓
prints only packets carrying observations
```

A quiet Hunt Mode screen does not mean no packets are being analysed.

---

# Service Identification

Howlr recognises common service ports such as:

```text
20/FTP-DATA
21/FTP
22/SSH
23/TELNET
25/SMTP
53/DNS
80/HTTP
110/POP3
123/NTP
143/IMAP
389/LDAP
443/HTTPS
445/SMB
3389/RDP
5353/MDNS
5900/VNC
8080/HTTP-ALT
```

Example outbound HTTP:

```text
TCP 50836 -> 80/HTTP
```

Example inbound HTTPS:

```text
TCP 443/HTTPS -> 49286
```

v0.2.0 service statistics recognise known service ports on either side of a flow. This is important for inbound traffic, where the well-known service port is commonly the source port.

Port-based identification is triage metadata, not deep protocol proof.

---

# TCP Events

Howlr translates common flag combinations.

## SYN

```text
flags=SYN event=SYN
```

Usually begins a TCP connection attempt.

## SYN-ACK

```text
flags=SYN+ACK event=SYN-ACK
```

Usually responds positively to a SYN.

## ACK

```text
flags=ACK event=ACK
```

Acknowledges TCP data.

## PSH-ACK

```text
flags=ACK+PSH event=PSH-ACK
```

Often appears during application data transfer.

## FIN

```text
flags=ACK+FIN event=FIN
```

Usually participates in orderly connection shutdown.

## RST

```text
flags=RST event=RST
```

Resets a TCP connection.

Repeated RST traffic can be useful in troubleshooting or scan investigation.

---

# DNS Analysis

Capture DNS:

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" -f "port 53" -t 60
```

Howlr can display query names and response metadata.

Summary example:

```text
Top DNS queries:
  example.com
  api.example.net
  _spotify-connect._tcp.local
```

Useful questions:

```text
Which domains is this host resolving?
Which names appear repeatedly?
Are lookups failing?
Are unfamiliar domains present?
```

---

# DNS Errors

A failed DNS response may trigger:

```text
DNS_ERROR_RCODE
```

Example:

```text
DNS response telemetry.example.com type=A answers=0 rcode=REFUSED | OBS=DNS_ERROR_RCODE:REFUSED
```

Possible causes include:

- resolver policy
- nonexistent names
- application errors
- temporary DNS problems
- blocked queries

Investigate context before drawing conclusions.

---

# mDNS and Multicast

mDNS commonly uses:

```text
224.0.0.251
ff02::fb
UDP 5353
```

Possible output:

```text
MULTICAST | UDP 5353/MDNS -> 5353/MDNS
```

This is common service-discovery traffic.

---

# HTTP Analysis

Howlr can extract basic metadata from readable, unencrypted HTTP requests.

Example:

```text
HTTP GET host=example.com uri=/
```

Possible packet:

```text
NOTICE | OUT | TCP 50836 -> 80/HTTP flags=ACK+PSH event=PSH-ACK | HTTP GET host=example.com uri=/ | OBS=CLEARTEXT_SERVICE:HTTP,CLEARTEXT_HTTP
```

Metadata can include:

- method
- Host
- URI

## Generate Test HTTP Traffic

### Windows

```powershell
curl http://example.com -UseBasicParsing
```

### Linux

```bash
curl http://example.com
```

Run a Hunt at the same time:

```bash
sudo .venv/bin/python howlr_packet_sentinel.py -i eth0 --local-network 192.168.1.0/24 --hunt -t 30
```

Possible observations:

```text
TCP_SYN
CLEARTEXT_SERVICE:HTTP
CLEARTEXT_HTTP
```

---

# HTTPS Limitation

Howlr does not decrypt TLS.

It can recognise:

```text
443/HTTPS
```

but cannot normally extract:

```text
GET
POST
Host
URI
```

from encrypted HTTPS payloads.

---

# Port-Scan Triage

Howlr uses a lightweight TCP SYN heuristic.

Options:

```text
--scan-threshold
--scan-window
```

Example:

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" --local-network 192.168.1.0/24 --hunt --scan-threshold 5 --scan-window 10 -t 60
```

Possible observation:

```text
POSSIBLE_PORT_SCAN:192.168.1.20:5_ports_in_10s
```

Interpretation:

```text
source host:   192.168.1.20
unique ports:  5
window:        10 seconds
```

Possible causes:

- Nmap
- vulnerability scanner
- asset inventory
- administrator testing
- service discovery
- reconnaissance
- unusual application behaviour

It is a heuristic, not an attack verdict.

---

# Tuning Scan Detection

Lower threshold:

```text
--scan-threshold 5
```

is more sensitive.

Higher threshold:

```text
--scan-threshold 20
```

requires more unique ports.

Short window:

```text
--scan-window 5
```

focuses on bursts.

Longer window:

```text
--scan-window 30
```

includes slower behaviour.

---

# ARP Analysis

ARP replies may trigger:

```text
ARP_REPLY
```

Howlr also tracks IP-to-MAC mappings during the current analysis.

If:

```text
192.168.1.50 -> 02:00:00:00:00:01
```

later becomes:

```text
192.168.1.50 -> 02:00:00:00:00:02
```

Howlr may report:

```text
ARP_MAC_CHANGE:192.168.1.50:02:00:00:00:00:01->02:00:00:00:00:02
```

Possible causes include:

- ARP spoofing
- duplicate IP
- device replacement
- VM movement
- failover
- legitimate network reconfiguration

---

# Output Files

Howlr can produce:

```text
PCAP
JSONL
CSV
```

## PCAP

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" -c 100 --pcap-out capture.pcap
```

Best for:

- Wireshark
- replay
- packet-level evidence
- deeper protocol inspection

## JSONL

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" -c 100 --jsonl-out packets.jsonl
```

Best for:

- scripts
- automation
- structured processing
- SIEM-style experiments

## CSV

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" -c 100 --csv-out packets.csv
```

Best for:

- spreadsheets
- sorting
- filtering
- simple reporting

## All Three Explicitly

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" -c 100 --pcap-out capture.pcap --jsonl-out packets.jsonl --csv-out packets.csv
```

---

# Session Mode

Use:

```text
--session NAME
```

Example:

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" --local-network 192.168.1.0/24 --session investigation -t 300
```

Typical output:

```text
captures/investigation_YYYYMMDD_HHMMSS.pcap
output/investigation_YYYYMMDD_HHMMSS.jsonl
output/investigation_YYYYMMDD_HHMMSS.csv
```

Useful names:

```text
baseline
http-test
dns-test
possible-scan
workstation-triage
incident-01
```

---

# Offline Analysis

### Windows

```powershell
python .\howlr_packet_sentinel.py -r .\capture.pcap
```

### Linux

```bash
.venv/bin/python howlr_packet_sentinel.py -r ./capture.pcap
```

With local network:

```powershell
python .\howlr_packet_sentinel.py -r .\capture.pcap --local-network 192.168.1.0/24
```

Summary only:

```powershell
python .\howlr_packet_sentinel.py -r .\capture.pcap --local-network 192.168.1.0/24 -q
```

---

# Quiet Mode

Use:

```text
-q
```

or:

```text
--quiet
```

Example:

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" --local-network 192.168.1.0/24 -t 60 -q
```

Quiet Mode suppresses normal packet lines while retaining processing and the final summary.

---

# Reading the Summary

## Packets and Bytes

```text
Packets analysed
Bytes analysed
```

Question:

```text
How much traffic did Howlr process?
```

## Duration and Packet Rate

Question:

```text
How busy was the capture?
```

## Protocols

Question:

```text
What types of traffic were present?
```

## Directions

Question:

```text
Where was traffic flowing?
```

## Top Source IPs

Question:

```text
Which systems generated the most observed packets?
```

## Top Destination IPs

Question:

```text
Which destinations received the most traffic?
```

## Top Destination Ports

Question:

```text
Which ports were most active?
```

## Top Services

Question:

```text
Which recognised services dominated?
```

## TCP Events

Question:

```text
What TCP behaviour occurred?
```

## DNS Queries

Question:

```text
Which names were resolved most often?
```

## Observations

Question:

```text
Which packets triggered Howlr's triage logic?
```

---

# Use Case 1 — What Is This Machine Talking To?

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" --local-network 192.168.1.0/24 -t 60
```

Review:

```text
Directions
Top destination IPs
Top destination ports
Top services
Top DNS queries
Observations
```

---

# Use Case 2 — Quick SOC-Style First Look

1. List interface:

```powershell
python .\howlr_packet_sentinel.py --list-interfaces
```

2. Normal capture:

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" --local-network 192.168.1.0/24 -t 30
```

3. Hunt:

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" --local-network 192.168.1.0/24 --hunt -t 60
```

4. Save evidence if needed:

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" --local-network 192.168.1.0/24 --session investigation -t 300
```

---

# Use Case 3 — Unexpected Outbound Traffic

Look for:

```text
OUT
Top destination IPs
Top services
Top DNS queries
```

Questions:

```text
Why is this machine contacting this IP?
Which service?
Was there a DNS lookup?
Is this application expected?
```

---

# Use Case 4 — Internal/LAN Communication

Look for:

```text
LAN
```

Examples:

```text
SMB
SSH
RDP
internal HTTP
DNS
NAS traffic
```

Question:

```text
Why are these two internal hosts communicating?
```

---

# Use Case 5 — Possible Port Scan

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" --local-network 192.168.1.0/24 --hunt --scan-threshold 5 --scan-window 10 -t 60
```

Look for:

```text
POSSIBLE_PORT_SCAN
```

Then investigate source, target, ports and whether the source is an authorised scanner.

---

# Use Case 6 — Cleartext HTTP

Start:

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" -f "tcp port 80" --hunt -t 30
```

Generate:

```powershell
curl http://example.com -UseBasicParsing
```

Look for:

```text
CLEARTEXT_SERVICE:HTTP
CLEARTEXT_HTTP
HTTP GET host=example.com uri=/
```

---

# Use Case 7 — DNS Investigation

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" -f "port 53" -t 60
```

Review:

```text
Top DNS queries
DNS_ERROR_RCODE
```

---

# Use Case 8 — ARP Investigation

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" --local-network 192.168.1.0/24 --hunt -t 300
```

Watch for:

```text
ARP_REPLY
ARP_MAC_CHANGE
```

---

# Use Case 9 — Build a Baseline

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" --local-network 192.168.1.0/24 --session baseline -t 300
```

Later:

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" --local-network 192.168.1.0/24 --session later-check -t 300
```

Compare:

```text
protocols
directions
services
destinations
DNS
observations
```

---

# Use Case 10 — Application Troubleshooting

Filter a host:

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" -f "host 192.168.1.20" -t 60
```

Ask:

```text
Does the app connect?
Which port?
Does it reset?
Are DNS requests failing?
Does traffic leave the machine?
```

---

# Use Case 11 — Learn TCP Handshake Behaviour

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" -f "tcp" -c 100
```

Look for:

```text
SYN
SYN-ACK
ACK
PSH-ACK
FIN
RST
```

---

# Use Case 12 — Learn Discovery Traffic

Run a normal LAN capture and observe:

```text
ARP
MDNS
SSDP
MULTICAST
BROADCAST
```

This shows why a LAN can remain active even when nobody is actively browsing.

---

# Use Case 13 — Triage a PCAP Before Wireshark

```powershell
python .\howlr_packet_sentinel.py -r .\capture.pcap --local-network 192.168.1.0/24 -q
```

Use the summary to decide whether deeper manual packet inspection is worthwhile.

---

# Use Case 14 — Preserve Evidence

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" --local-network 192.168.1.0/24 --session suspicious-traffic -t 300
```

You get:

```text
raw packet evidence
structured JSONL
CSV
summary
```

---

# Recommended Analyst Workflow

```text
1. Discover interface
        ↓
2. Identify local subnet
        ↓
3. Run a short normal capture
        ↓
4. Review protocols, directions and services
        ↓
5. Run Hunt Mode
        ↓
6. Investigate observations
        ↓
7. Save a longer session if required
        ↓
8. Open the PCAP in Wireshark
```

---

# Minimal First-Look Workflow

```powershell
python .\howlr_packet_sentinel.py --list-interfaces
```

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" --local-network 192.168.1.0/24 -t 30
```

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" --local-network 192.168.1.0/24 --hunt -t 60
```

---

# Important Interpretation Rule

Use this mental model:

```text
Observation
     ↓
Question
     ↓
Context
     ↓
Evidence
     ↓
Conclusion
```

Do not jump directly from an observation to an attack conclusion.

For detailed observation meanings, see **[docs/OBSERVATIONS.md](docs/OBSERVATIONS.md)**.
