# Howlr Packet Sentinel

**Howlr Packet Sentinel** is a lightweight command-line packet capture and network triage tool written in Python using Scapy.

It is designed for fast first-look analysis of network traffic. Howlr can capture traffic, identify common protocols and services, classify traffic direction, surface lightweight security observations, save structured output, and produce a concise capture summary before you move to deeper tools such as Wireshark.

> **Current stable release: v0.2.0**

## Documentation

The documentation is split so this README can stay useful as the project landing page.

| Guide | Purpose |
|---|---|
| **[INSTALL.md](INSTALL.md)** | Full Windows and Kali/Linux installation, Npcap, virtual environments and first-run verification |
| **[USAGE.md](USAGE.md)** | Full syntax, command reference, filters, examples, outputs and analyst workflows |
| **[Observations Guide](docs/OBSERVATIONS.md)** | `IN`, `OUT`, `LAN`, severity levels and every v0.2 observation |
| **[Troubleshooting Guide](docs/TROUBLESHOOTING.md)** | Interface, Npcap, privileges, BPF, routing, VPN, VM and output problems |
| **[CHANGELOG.md](CHANGELOG.md)** | Release history |

---

# What Howlr Does

Howlr Packet Sentinel v0.2.0 can:

- capture live packets from a selected interface
- analyse PCAP/PCAPNG files offline
- apply BPF capture filters
- stop by packet count or timeout
- identify Ethernet, ARP, IPv4, IPv6, TCP, UDP, ICMP, ICMPv6, DNS, mDNS and basic HTTP metadata
- identify common services from known TCP/UDP ports
- classify traffic as `IN`, `OUT`, `LAN`, `MULTICAST`, `BROADCAST` or `TRANSIT`
- translate TCP flags into readable events such as `SYN`, `SYN-ACK`, `ACK`, `PSH-ACK`, `FIN` and `RST`
- display DNS names and response information
- identify selected cleartext-service ports
- extract method, Host and URI from readable unencrypted HTTP requests
- track ARP IP-to-MAC mappings during an analysis session
- flag ARP mapping changes
- apply a lightweight TCP SYN-based port-scan heuristic
- run in Hunt Mode to print only packets containing observations
- write PCAP, JSONL and CSV
- create timestamped session output
- produce useful end-of-capture statistics

The intended workflow is:

```text
Capture
   ↓
Understand
   ↓
Summarise
   ↓
Highlight
   ↓
Investigate deeper
```

Howlr is intentionally not a replacement for a full IDS, EDR, NDR, SIEM, Zeek, Suricata, Snort or Wireshark. Its role is to help answer:

```text
What is happening on this interface?
Which systems are talking?
Where is traffic going?
Which services are being used?
What DNS names appear?
Is traffic local or external?
Did anything trigger a triage observation?
What should I inspect next?
```

---

# Quick Start

If Howlr is not installed yet, start with **[INSTALL.md](INSTALL.md)**.

## Check Version

### Windows

```powershell
python .\howlr_packet_sentinel.py --version
```

### Kali / Linux

```bash
python3 howlr_packet_sentinel.py --version
```

Expected:

```text
howlr_packet_sentinel.py 0.2.0
```

## List Interfaces

### Windows

```powershell
python .\howlr_packet_sentinel.py --list-interfaces
```

### Kali / Linux

```bash
python3 howlr_packet_sentinel.py --list-interfaces
```

Use the exact interface **name**. In v0.2.0 the displayed numeric interface index is informational and is not accepted directly by `-i`.

Examples:

```text
Windows: Realtek PCIe GbE Family Controller
Linux:   eth0
```

## Capture 20 Packets

### Windows

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" -c 20
```

### Kali / Linux

```bash
sudo .venv/bin/python howlr_packet_sentinel.py -i eth0 -c 20
```

## Add Local-Network Classification

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" --local-network 192.168.1.0/24 -t 60
```

Linux:

```bash
sudo .venv/bin/python howlr_packet_sentinel.py -i eth0 --local-network 192.168.1.0/24 -t 60
```

This enables direction labels:

```text
IN
OUT
LAN
MULTICAST
BROADCAST
TRANSIT
```

## Hunt Mode

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" --local-network 192.168.1.0/24 --hunt -t 60
```

Linux:

```bash
sudo .venv/bin/python howlr_packet_sentinel.py -i eth0 --local-network 192.168.1.0/24 --hunt -t 60
```

Hunt Mode still analyses all packets but only prints packets carrying observations.

## Save an Investigation Session

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" --local-network 192.168.1.0/24 --session investigation -t 300
```

Typical files:

```text
captures/investigation_YYYYMMDD_HHMMSS.pcap
output/investigation_YYYYMMDD_HHMMSS.jsonl
output/investigation_YYYYMMDD_HHMMSS.csv
```

---

# Example Output

Normal HTTPS response traffic can look like:

```text
NORMAL | IN | IPv4 104.18.41.158 -> 192.168.1.50 | TCP 443/HTTPS -> 49286 flags=ACK event=ACK
```

Readable HTTP can look like:

```text
NOTICE | OUT | IPv4 192.168.1.50 -> 104.20.23.154 | TCP 50836 -> 80/HTTP flags=ACK+PSH event=PSH-ACK | HTTP GET host=example.com uri=/ | OBS=CLEARTEXT_SERVICE:HTTP,CLEARTEXT_HTTP
```

A scan heuristic can look like:

```text
WARNING | LAN | IPv4 192.168.1.20 -> 192.168.1.50 | TCP -> 24 flags=SYN event=SYN | OBS=TCP_SYN,POSSIBLE_PORT_SCAN:192.168.1.20:5_ports_in_10s
```

---

# Capture Summary

At the end of a capture Howlr can report:

- packets and bytes analysed
- duration and packet rate
- protocols
- directions
- top source IPs
- top destination IPs
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
Bytes analysed   : 24611
Duration         : 0.24 seconds
Packet rate      : 206.29 packets/sec

Protocols:
  Ethernet                                   50
  IPv4                                       50
  TCP                                        29
  UDP                                        21

Directions:
  IN                                         36
  OUT                                        14

Top services:
  HTTPS                                      29

TCP events:
  ACK                                        22
  PSH-ACK                                     7

Note: observations are triage hints, not proof of malicious activity.
==============================================================
```

---

# Common Commands

Help:

```powershell
python .\howlr_packet_sentinel.py --help
```

Capture 50 packets:

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" -c 50
```

Capture for 30 seconds:

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" -t 30
```

TCP only:

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" -f "tcp" -c 100
```

DNS only:

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" -f "port 53" -t 60
```

HTTP Hunt:

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" -f "tcp port 80" --hunt -t 30
```

Offline summary:

```powershell
python .\howlr_packet_sentinel.py -r .\capture.pcap --local-network 192.168.1.0/24 -q
```

For detailed syntax and examples, see **[USAGE.md](USAGE.md)**.

---

# Main Use Cases

## 1. What Is This Machine Talking To?

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" --local-network 192.168.1.0/24 -t 60
```

Review:

```text
Directions
Top destination IPs
Top ports
Top services
Top DNS queries
Observations
```

## 2. Quick SOC-Style First Look

Run a short normal capture, then Hunt Mode, then save a session if something deserves deeper investigation.

```text
Normal capture
    ↓
Review traffic profile
    ↓
Hunt Mode
    ↓
Interesting?
   /       \
 No        Yes
            ↓
        Save session
            ↓
         Wireshark
```

## 3. Learn TCP

Capture TCP:

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" -f "tcp" -c 100
```

Watch:

```text
SYN → SYN-ACK → ACK → PSH-ACK → FIN
```

## 4. Find Cleartext HTTP

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" -f "tcp port 80" --hunt -t 30
```

Generate:

```powershell
curl http://example.com -UseBasicParsing
```

Possible observation:

```text
HTTP GET host=example.com uri=/
OBS=CLEARTEXT_SERVICE:HTTP,CLEARTEXT_HTTP
```

## 5. Preserve Evidence

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" --local-network 192.168.1.0/24 --session suspicious-traffic -t 300
```

Use Howlr to triage and the saved PCAP for deeper analysis.

---

# Tested Platforms

v0.2.0 has been manually validated on:

- Windows
- Kali Linux

Testing included:

- version/help
- interface discovery
- live capture
- offline replay
- IPv4/IPv6
- TCP/UDP
- ARP
- DNS/mDNS
- traffic directions
- service identification
- inbound service counting
- TCP events
- Hunt Mode
- cleartext service detection
- cleartext HTTP metadata
- ARP mapping changes
- TCP SYN scan heuristic
- PCAP/JSONL/CSV output
- session capture
- quiet mode
- summaries

---

# Project Structure

```text
howlr-packet-sentinel/
│
├── howlr_packet_sentinel.py
├── requirements.txt
├── README.md
├── INSTALL.md
├── USAGE.md
├── CHANGELOG.md
├── LICENSE
├── .gitignore
│
├── docs/
│   ├── OBSERVATIONS.md
│   └── TROUBLESHOOTING.md
│
├── captures/
└── output/
```

`captures/` and `output/` are runtime directories and may be created automatically.

---

# Project Scope

Howlr is best thought of as:

```text
Capture
   ↓
Summarise
   ↓
Highlight
   ↓
Decide what deserves deeper investigation
```

It complements tools such as:

- Wireshark
- tcpdump
- Zeek
- Suricata
- Snort

---

# Future Ideas

Possible future improvements include:

- automatic active-interface detection
- automatic local-network detection
- installable CLI
- shorter `howlr` command
- numeric interface selection
- richer protocol parsing
- more service mappings
- additional observations
- improved scan heuristics
- baseline comparison
- richer reporting

These are ideas, not guarantees for a specific release.

---

# Authorised Use

Use Howlr Packet Sentinel only on systems and networks that you own or have explicit permission to monitor.

Packet capture may expose IP addresses, DNS names, service metadata and unencrypted application data.

> **Observations are triage hints, not proof of malicious activity.**

---

# Licence

See **[LICENSE](LICENSE)**.

```text
HOWLR PACKET SENTINEL
Capture. Understand. Summarise. Highlight. Investigate.
```
