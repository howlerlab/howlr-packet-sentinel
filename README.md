# Howlr Packet Sentinel

**Howlr Packet Sentinel** is a lightweight command-line packet capture and network triage tool written in Python using Scapy.

It is designed to provide a fast first look at network traffic without requiring an analyst to immediately inspect every individual packet manually.

Howlr Packet Sentinel can:

- capture live network traffic
- analyse existing PCAP and PCAPNG files
- identify common network protocols
- identify common TCP and UDP services
- classify network traffic direction
- interpret common TCP flags and events
- inspect DNS activity
- identify cleartext services
- extract basic unencrypted HTTP metadata
- track ARP IP-to-MAC mappings
- detect ARP mapping changes
- detect simple TCP SYN-based scanning behaviour
- reduce packet noise using Hunt Mode
- export packet information to PCAP, JSONL and CSV
- generate capture statistics and summaries
- preserve traffic for deeper Wireshark investigation

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
Investigate Deeper
```

Howlr Packet Sentinel is intended for:

- cybersecurity labs
- networking education
- packet-analysis practice
- SOC-style network triage
- defensive security analysis
- troubleshooting
- authorised incident-response exercises
- learning TCP/IP behaviour
- PCAP first-pass analysis

It is **not** designed to replace Wireshark, Zeek, Suricata, Snort, EDR, NDR or SIEM platforms.

Instead, Howlr tries to quickly answer questions such as:

```text
What is happening on this network interface?

Which systems are communicating?

Where is the traffic going?

Is traffic staying inside the LAN or leaving it?

Which protocols are being used?

Which services are being used?

Which domains are being queried?

Are any cleartext services present?

Is one host probing multiple TCP ports?

Did an IP-to-MAC mapping suddenly change?

Is anything worth investigating further?
```

> Howlr Packet Sentinel is intended for systems and networks that you own or have explicit permission to monitor.

---

# Current Stable Version

```text
v0.2.0
```

Check the installed version:

## Windows / PowerShell

```powershell
python .\howlr_packet_sentinel.py --version
```

## Linux / Kali

```bash
python3 howlr_packet_sentinel.py --version
```

Expected output:

```text
howlr_packet_sentinel.py 0.2.0
```

The stable release is maintained on:

```text
main
```

Development may continue separately on development branches.

---

# Table of Contents

1. Overview
2. Requirements
3. Installation
4. Windows Installation
5. Kali / Linux Installation
6. Virtual Environment Setup
7. Interface Discovery
8. Finding Your Local Network
9. Command Syntax
10. Command Reference
11. Basic Usage
12. Packet Count and Timeout
13. Traffic Direction Classification
14. BPF Capture Filters
15. Protocol Analysis
16. Service Identification
17. TCP Event Analysis
18. DNS Analysis
19. HTTP Analysis
20. Security Observations
21. Severity Levels
22. Hunt Mode
23. Port Scan Triage
24. ARP Change Detection
25. Session Capture
26. PCAP Output
27. JSONL Output
28. CSV Output
29. Offline PCAP Analysis
30. Quiet Mode
31. Capture Summary
32. Understanding Traffic Directions
33. Use Cases
34. Recommended Analyst Workflow
35. Troubleshooting
36. Tested Platforms
37. Validated v0.2.0 Features
38. Project Structure
39. Project Scope
40. Future Ideas
41. Authorised Use
42. Licence

---

# Requirements

Howlr Packet Sentinel requires:

- Python 3
- Scapy
- Git if cloning the repository
- Npcap for live capture on Windows
- appropriate privileges for raw packet capture

The Python dependency is defined in:

```text
requirements.txt
```

Current dependency:

```text
scapy>=2.7.0
```

---

# Installation

Howlr Packet Sentinel runs directly from its Python source.

A typical installation consists of:

```text
Install Python
      ↓
Install Git
      ↓
Clone repository
      ↓
Create virtual environment
      ↓
Install requirements
      ↓
Install Npcap if using Windows
      ↓
List interfaces
      ↓
Run Howlr
```

---

# Clone the Repository

Open PowerShell, Terminal or a shell and run:

```bash
git clone https://github.com/howlerlab/howlr-packet-sentinel.git
```

Move into the project:

```bash
cd howlr-packet-sentinel
```

The project should contain files similar to:

```text
howlr-packet-sentinel/
│
├── howlr_packet_sentinel.py
├── requirements.txt
├── README.md
├── CHANGELOG.md
├── LICENSE
└── .gitignore
```

Runtime directories such as:

```text
captures/
output/
```

are created when required.

---

# Windows Installation

## 1. Install Python

Install Python 3.

Verify the installation:

```powershell
python --version
```

Example:

```text
Python 3.x.x
```

You can also verify pip:

```powershell
python -m pip --version
```

---

# 2. Install Git

Verify Git:

```powershell
git --version
```

Then clone Howlr:

```powershell
git clone https://github.com/howlerlab/howlr-packet-sentinel.git
```

Move into the repository:

```powershell
cd .\howlr-packet-sentinel
```

---

# 3. Create a Python Virtual Environment

Creating a virtual environment is recommended so that Howlr's Python packages remain separate from the system Python installation.

Create the environment:

```powershell
python -m venv .venv
```

Activate it:

```powershell
.\.venv\Scripts\Activate.ps1
```

When activated, PowerShell normally shows:

```text
(.venv) PS C:\...\howlr-packet-sentinel>
```

---

## PowerShell Execution Policy Error

If PowerShell blocks virtual environment activation, you can temporarily allow scripts for the current PowerShell session:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

Then retry:

```powershell
.\.venv\Scripts\Activate.ps1
```

The change applies only to the current PowerShell process.

---

# 4. Install Python Requirements

With the virtual environment active:

```powershell
python -m pip install -r requirements.txt
```

Verify Scapy:

```powershell
python -c "import scapy; print(scapy.__version__)"
```

---

# 5. Install Npcap

Windows live packet capture requires **Npcap**.

Npcap provides the packet-capture driver used by tools such as Scapy and Wireshark.

During installation, enabling:

```text
WinPcap API-compatible Mode
```

is generally recommended for compatibility.

After installation, restart the terminal before testing Howlr.

---

# 6. Verify Howlr

Run:

```powershell
python .\howlr_packet_sentinel.py --version
```

Then:

```powershell
python .\howlr_packet_sentinel.py --help
```

Then:

```powershell
python .\howlr_packet_sentinel.py --list-interfaces
```

If all three commands work, the installation is ready for testing.

---

# Windows Without Activating the Virtual Environment

Activating `.venv` is optional.

You can call the virtual environment Python directly:

```powershell
.\.venv\Scripts\python.exe .\howlr_packet_sentinel.py --version
```

Example live capture:

```powershell
.\.venv\Scripts\python.exe .\howlr_packet_sentinel.py -i "<INTERFACE>" -c 20
```

This can be useful if you prefer not to activate the virtual environment.

---

# Kali / Linux Installation

## 1. Update Package Information

On Kali or Debian-based systems:

```bash
sudo apt update
```

---

# 2. Install Python, Git and Virtual Environment Support

```bash
sudo apt install -y python3 python3-venv python3-pip git
```

Verify:

```bash
python3 --version
```

and:

```bash
git --version
```

---

# 3. Clone Howlr Packet Sentinel

```bash
git clone https://github.com/howlerlab/howlr-packet-sentinel.git
```

Move into the repository:

```bash
cd howlr-packet-sentinel
```

---

# 4. Create the Virtual Environment

```bash
python3 -m venv .venv
```

Install dependencies directly into it:

```bash
.venv/bin/pip install -r requirements.txt
```

Verify Scapy:

```bash
.venv/bin/python -c "import scapy; print(scapy.__version__)"
```

---

# 5. Test Howlr

```bash
.venv/bin/python howlr_packet_sentinel.py --version
```

Then:

```bash
.venv/bin/python howlr_packet_sentinel.py --help
```

Then:

```bash
.venv/bin/python howlr_packet_sentinel.py --list-interfaces
```

---

# Linux Capture Privileges

Live packet capture generally requires elevated privileges.

Therefore:

```bash
sudo .venv/bin/python howlr_packet_sentinel.py -i eth0 -c 20
```

is normally required.

Offline PCAP analysis generally does not require `sudo`:

```bash
.venv/bin/python howlr_packet_sentinel.py -r capture.pcap
```

---

# Optional Linux Packet-Capture Packages

If BPF filtering or capture support is missing, ensure common packet-capture packages are installed.

For Kali/Debian:

```bash
sudo apt install -y tcpdump libpcap-dev
```

These may already be installed on Kali.

---

# Interface Discovery

Before running a live capture, identify the correct interface.

Do **not** guess the interface name.

## Windows

```powershell
python .\howlr_packet_sentinel.py --list-interfaces
```

## Linux / Kali

```bash
python3 howlr_packet_sentinel.py --list-interfaces
```

or when using the project environment:

```bash
.venv/bin/python howlr_packet_sentinel.py --list-interfaces
```

Example output:

```text
Source  Index  Name                           MAC                IPv4
sys     1      lo                             00:00:00:00:00:00  127.0.0.1
sys     2      eth0                           00:0c:29:12:34:56  192.168.1.50
```

Possible Windows interface:

```text
Realtek PCIe GbE Family Controller
```

Possible Linux interface:

```text
eth0
```

---

# Important v0.2.0 Interface Limitation

The numeric interface index shown by `--list-interfaces` is informational in v0.2.0.

For example:

```text
Index: 12
Name: Realtek PCIe GbE Family Controller
```

Use:

```powershell
python .\howlr_packet_sentinel.py -i "Realtek PCIe GbE Family Controller" -c 20
```

Do **not** use:

```powershell
python .\howlr_packet_sentinel.py -i 12 -c 20
```

v0.2.0 expects the interface name.

---

# Finding Your Local Network

Traffic direction classification becomes significantly more useful when Howlr knows which network should be treated as local.

This is supplied using:

```text
--local-network
```

---

# Windows

Run:

```powershell
ipconfig
```

Look for the active adapter.

Example:

```text
IPv4 Address. . . . . . . . . . . : 192.168.1.50
Subnet Mask . . . . . . . . . . . : 255.255.255.0
```

This corresponds to:

```text
192.168.1.0/24
```

Use:

```powershell
--local-network 192.168.1.0/24
```

Example:

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" --local-network 192.168.1.0/24 -c 50
```

---

# Linux / Kali

Check the interface:

```bash
ip addr
```

or:

```bash
ip -br addr
```

Example:

```text
eth0    UP    192.168.42.130/24
```

The local network is:

```text
192.168.42.0/24
```

You can also check routes:

```bash
ip route
```

Example:

```text
192.168.42.0/24 dev eth0
```

Use:

```bash
--local-network 192.168.42.0/24
```

---

# What Does `/24` Mean?

CIDR notation specifies the network prefix.

For example:

```text
192.168.1.0/24
```

usually represents addresses from:

```text
192.168.1.0
```

through:

```text
192.168.1.255
```

with usable host addresses typically within that subnet depending on network configuration.

Do not simply copy the example network.

Use the network belonging to your actual capture interface.

---

# Command Syntax

## General Live Capture Syntax

```text
python howlr_packet_sentinel.py -i <INTERFACE> [OPTIONS]
```

Windows:

```text
python .\howlr_packet_sentinel.py -i "<INTERFACE>" [OPTIONS]
```

Linux/Kali:

```text
sudo .venv/bin/python howlr_packet_sentinel.py -i <INTERFACE> [OPTIONS]
```

---

# Offline Analysis Syntax

```text
python howlr_packet_sentinel.py -r <PCAP_FILE> [OPTIONS]
```

Windows example:

```powershell
python .\howlr_packet_sentinel.py -r .\capture.pcap
```

Linux example:

```bash
python3 howlr_packet_sentinel.py -r ./capture.pcap
```

---

# Command Reference

```text
-h, --help
    Show command-line help.

--version
    Display the current Howlr Packet Sentinel version.

--list-interfaces
    List available capture interfaces.

-i, --interface INTERFACE
    Capture live packets from the selected interface.

-r, --read FILE
    Analyse an existing PCAP or PCAPNG file.

-f, --filter FILTER
    Apply a BPF capture filter.

-c, --count COUNT
    Stop after processing the specified number of packets.

-t, --timeout SECONDS
    Stop live capture after the specified number of seconds.

--local-network CIDR
    Define a local network for traffic-direction classification.

--pcap-out FILE
    Save captured packets to a PCAP file.

--jsonl-out FILE
    Save parsed packet information as JSON Lines.

--csv-out FILE
    Save parsed packet information as CSV.

--session NAME
    Automatically create timestamped PCAP, JSONL and CSV files.

--hunt
    Analyse all packets but print only packets containing observations.

--scan-threshold NUMBER
    Configure the number of unique ports used by the scan heuristic.

--scan-window SECONDS
    Configure the scan-detection time window.

-q, --quiet
    Suppress normal packet output while retaining processing and the summary.
```

Always check the current CLI directly:

## Windows

```powershell
python .\howlr_packet_sentinel.py --help
```

## Linux

```bash
python3 howlr_packet_sentinel.py --help
```

---

# Basic Usage

## Windows — Capture 20 Packets

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" -c 20
```

Real interface example:

```powershell
python .\howlr_packet_sentinel.py -i "Realtek PCIe GbE Family Controller" -c 20
```

---

# Linux / Kali — Capture 20 Packets

```bash
sudo .venv/bin/python howlr_packet_sentinel.py -i eth0 -c 20
```

---

# Capture 50 Packets

## Windows

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" -c 50
```

## Linux

```bash
sudo .venv/bin/python howlr_packet_sentinel.py -i eth0 -c 50
```

---

# Timed Capture

Capture for 30 seconds.

## Windows

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" -t 30
```

## Linux

```bash
sudo .venv/bin/python howlr_packet_sentinel.py -i eth0 -t 30
```

---

# Capture for 60 Seconds

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" -t 60
```

---

# Capture for Five Minutes

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" -t 300
```

---

# Packet Count and Timeout Together

You can use packet count and timeout together.

Example:

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" -c 100 -t 60
```

The capture ends when the applicable stop condition is reached.

---

# Direction-Aware Capture

Add your local network:

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" --local-network 192.168.1.0/24 -c 50
```

Linux:

```bash
sudo .venv/bin/python howlr_packet_sentinel.py -i eth0 --local-network 192.168.1.0/24 -c 50
```

Howlr can now classify traffic as:

```text
IN
OUT
LAN
MULTICAST
BROADCAST
TRANSIT
```

---

# BPF Capture Filters

Howlr supports BPF capture filters using:

```text
-f
```

or:

```text
--filter
```

A BPF filter reduces which packets are passed to Howlr for processing.

---

# Capture TCP Only

## Windows

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" -f "tcp" -c 100
```

## Linux

```bash
sudo .venv/bin/python howlr_packet_sentinel.py -i eth0 -f "tcp" -c 100
```

---

# Capture UDP Only

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" -f "udp" -c 100
```

---

# Capture ICMP Only

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" -f "icmp" -c 100
```

---

# Capture TCP, UDP and ICMP

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" -f "tcp or udp or icmp" -c 100
```

Linux:

```bash
sudo .venv/bin/python howlr_packet_sentinel.py -i eth0 -f "tcp or udp or icmp" -c 100
```

---

# Capture DNS

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" -f "port 53" -t 60
```

Linux:

```bash
sudo .venv/bin/python howlr_packet_sentinel.py -i eth0 -f "port 53" -t 60
```

---

# Capture HTTP

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" -f "tcp port 80" -t 60
```

---

# Capture HTTP in Hunt Mode

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" -f "tcp port 80" --hunt -t 60
```

Linux:

```bash
sudo .venv/bin/python howlr_packet_sentinel.py -i eth0 -f "tcp port 80" --hunt -t 60
```

---

# Capture Traffic for One Host

Example:

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" -f "host 192.168.1.50" -t 60
```

---

# Capture Traffic Going to a Host

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" -f "dst host 192.168.1.50" -t 60
```

---

# Capture Traffic Coming From a Host

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" -f "src host 192.168.1.50" -t 60
```

---

# Capture HTTPS

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" -f "tcp port 443" -t 60
```

Howlr can identify HTTPS service traffic but does not decrypt TLS payloads.

---

# Protocol Analysis

Howlr can identify and summarise:

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

Example:

```text
Protocols:
  Ethernet                                   150
  IPv4                                       122
  TCP                                         81
  UDP                                         41
  DNS                                         18
  IPv6                                        28
```

This provides a fast protocol profile of the capture.

---

# Service Identification

Howlr identifies common TCP and UDP services using recognised ports.

Examples include:

| Port | Service |
|---:|---|
| 20 | FTP-DATA |
| 21 | FTP |
| 22 | SSH |
| 23 | TELNET |
| 25 | SMTP |
| 53 | DNS |
| 80 | HTTP |
| 110 | POP3 |
| 123 | NTP |
| 137-139 | NetBIOS |
| 143 | IMAP |
| 389 | LDAP |
| 443 | HTTPS |
| 445 | SMB |
| 3389 | RDP |
| 5353 | MDNS |
| 5900 | VNC |
| 8080 | HTTP-ALT |

Example:

```text
TCP 50836 -> 80/HTTP
```

Inbound HTTPS example:

```text
TCP 443/HTTPS -> 57336
```

Howlr checks recognised service ports on either side of the TCP or UDP conversation.

This means inbound traffic such as:

```text
443 -> 57336
```

can still be counted as HTTPS.

> Service labels are based primarily on known ports and should be treated as triage information rather than absolute protocol identification.

---

# TCP Event Analysis

TCP flags are translated into easier-to-read events.

Examples:

```text
SYN
SYN-ACK
ACK
PSH-ACK
FIN
RST
```

---

# SYN

Example:

```text
flags=SYN event=SYN
```

Usually represents the beginning of a TCP connection attempt.

---

# SYN-ACK

```text
flags=SYN+ACK event=SYN-ACK
```

Usually indicates that the receiving system is responding to a connection attempt.

---

# ACK

```text
flags=ACK event=ACK
```

Acknowledges TCP traffic.

---

# PSH-ACK

```text
flags=ACK+PSH event=PSH-ACK
```

Often indicates application data being transferred.

---

# FIN

```text
flags=ACK+FIN event=FIN
```

Usually indicates a normal TCP connection shutdown.

---

# RST

```text
flags=RST event=RST
```

Indicates that a TCP connection was reset.

Repeated resets can sometimes be useful during troubleshooting or investigation.

---

# DNS Analysis

Howlr can inspect DNS information including:

- DNS query name
- query type
- response code
- answer count

Example:

```text
example.com
```

Capture summary:

```text
Top DNS queries:
  example.com                                5
  api.example.net                            3
  _spotify-connect._tcp.local                2
```

DNS analysis can answer:

```text
Which domains is this machine requesting?

Which domains are requested most frequently?

Are requests repeatedly failing?

Is an application contacting unfamiliar domains?
```

---

# DNS Error Observations

DNS error responses may generate:

```text
DNS_ERROR_RCODE
```

Possible causes include:

- nonexistent domains
- DNS configuration errors
- application mistakes
- temporary DNS failures
- repeated invalid lookups

This is an observation, not proof of malicious activity.

---

# HTTP Analysis

Howlr can inspect **unencrypted HTTP** metadata.

Information may include:

- HTTP method
- Host header
- URI

Example:

```text
HTTP GET host=example.com uri=/
```

Full example:

```text
NOTICE | OUT | IPv4 192.168.1.50 -> 104.20.23.154 | TCP 50836 -> 80/HTTP flags=ACK+PSH event=PSH-ACK | HTTP GET host=example.com uri=/ | OBS=CLEARTEXT_SERVICE:HTTP,CLEARTEXT_HTTP
```

From this packet the analyst can immediately see:

```text
Source:
192.168.1.50

Destination:
104.20.23.154

Protocol:
HTTP

Method:
GET

Host:
example.com

URI:
/
```

---

# Generate Test HTTP Traffic

## Windows

```powershell
curl http://example.com -UseBasicParsing
```

## Linux / Kali

```bash
curl http://example.com
```

Run Howlr at the same time:

```bash
sudo .venv/bin/python howlr_packet_sentinel.py -i eth0 --local-network 192.168.1.0/24 --hunt -t 30
```

Possible result:

```text
HTTP GET host=example.com uri=/
OBS=CLEARTEXT_SERVICE:HTTP,CLEARTEXT_HTTP
```

---

# HTTPS

HTTPS uses TLS encryption.

Howlr can identify traffic associated with:

```text
443/HTTPS
```

but it does **not decrypt TLS**.

Therefore ordinary HTTPS traffic does not expose HTTP information such as:

```text
GET
POST
Host
URI
```

to Howlr.

---

# Cleartext Service Detection

Howlr can flag traffic using ports commonly associated with unencrypted services.

Examples can include:

```text
FTP
TELNET
HTTP
POP3
IMAP
LDAP
VNC
```

Possible observation:

```text
CLEARTEXT_SERVICE:HTTP
```

or:

```text
CLEARTEXT_SERVICE:TELNET
```

The observation means that a recognised cleartext service port was observed.

It does not prove sensitive information was actually transmitted.

---

# Security Observations

Howlr v0.2.0 contains lightweight triage observations including:

```text
TCP_SYN
TCP_RST
ARP_REPLY
ARP_MAC_CHANGE
DNS_ERROR_RCODE
CLEARTEXT_SERVICE
CLEARTEXT_HTTP
POSSIBLE_PORT_SCAN
```

Observations are intended to answer:

```text
Which packets might deserve further attention?
```

They do **not** answer:

```text
Has a confirmed attack occurred?
```

> Howlr observations are triage hints, not proof of malicious activity.

---

# Severity Levels

Packet output may contain severity labels such as:

```text
NORMAL
INFO
NOTICE
WARNING
```

Example:

```text
NOTICE | OUT | ... | OBS=CLEARTEXT_HTTP
```

A stronger heuristic may appear as:

```text
WARNING | LAN | ... | OBS=POSSIBLE_PORT_SCAN
```

Severity labels help prioritise output.

They are not formal risk scores.

---

# Hunt Mode

Hunt Mode is enabled using:

```text
--hunt
```

Howlr still analyses all captured packets, but only packets containing observations are printed.

---

# Normal Capture

Normal capture might look conceptually like:

```text
packet
packet
packet
packet
packet
interesting packet
packet
packet
packet
packet
```

---

# Hunt Mode

Hunt Mode reduces that to:

```text
interesting packet
```

---

# Windows Hunt Example

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" --local-network 192.168.1.0/24 --hunt -t 60
```

---

# Linux Hunt Example

```bash
sudo .venv/bin/python howlr_packet_sentinel.py -i eth0 --local-network 192.168.1.0/24 --hunt -t 60
```

Hunt Mode can be useful for:

- SOC-style first look
- scan detection
- cleartext service discovery
- HTTP inspection
- ARP mapping changes
- TCP resets
- DNS errors

---

# Port Scan Triage

Howlr contains a lightweight TCP SYN-based scan heuristic.

Relevant settings are:

```text
--scan-threshold
--scan-window
```

Example:

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" --local-network 192.168.1.0/24 --hunt --scan-threshold 5 --scan-window 10 -t 60
```

This example uses:

```text
Threshold: 5 unique TCP ports
Window:    10 seconds
```

Possible output:

```text
WARNING | LAN | IPv4 192.168.1.20 -> 192.168.1.50 | TCP -> 24 flags=SYN event=SYN | OBS=TCP_SYN,POSSIBLE_PORT_SCAN:192.168.1.20:5_ports_in_10s
```

Possible causes include:

- Nmap
- vulnerability scanning
- administrative scanning
- asset discovery
- monitoring software
- unusual application behaviour
- reconnaissance

> `POSSIBLE_PORT_SCAN` is a heuristic. Legitimate applications can sometimes generate similar patterns.

---

# ARP Analysis

Howlr can inspect ARP traffic.

ARP replies may generate:

```text
ARP_REPLY
```

Howlr also tracks observed IP-to-MAC mappings during a capture.

---

# ARP MAC Change Detection

Suppose Howlr initially sees:

```text
192.168.1.50 -> 02:00:00:00:00:01
```

Later it sees:

```text
192.168.1.50 -> 02:00:00:00:00:02
```

Howlr may generate:

```text
ARP_MAC_CHANGE:192.168.1.50:02:00:00:00:00:01->02:00:00:00:00:02
```

Possible explanations include:

- ARP spoofing
- duplicate IP addresses
- device replacement
- virtualisation
- failover systems
- legitimate network reconfiguration

An ARP mapping change is worth investigating but is **not automatically malicious**.

---

# Session Capture

One of the most convenient v0.2.0 features is:

```text
--session
```

Session mode automatically creates timestamped:

```text
PCAP
JSONL
CSV
```

---

# Windows Session Example

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" --local-network 192.168.1.0/24 --session investigation -t 60
```

---

# Linux Session Example

```bash
sudo .venv/bin/python howlr_packet_sentinel.py -i eth0 --local-network 192.168.1.0/24 --session investigation -t 60
```

Possible generated files:

```text
captures/investigation_20260821_210000.pcap
output/investigation_20260821_210000.jsonl
output/investigation_20260821_210000.csv
```

The directories are created automatically when required.

Generated runtime captures and output are excluded from Git by `.gitignore`.

---

# Why Session Mode Is Useful

Without session mode, you may have to specify each output manually.

With session mode:

```text
one command
    ↓
   PCAP
   JSONL
   CSV
```

This is useful during investigations because you simultaneously preserve:

```text
raw packets
structured packet data
spreadsheet-friendly data
```

---

# PCAP Output

PCAP preserves the original packet data.

Create one manually:

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" -c 100 --pcap-out capture.pcap
```

PCAP is useful for:

- Wireshark
- deeper packet inspection
- replay through Howlr
- sharing authorised lab captures
- evidence preservation

---

# JSONL Output

Create JSON Lines output:

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" -c 100 --jsonl-out packets.jsonl
```

JSONL is useful for:

- Python scripting
- automation
- log analysis
- SIEM-style ingestion
- machine-readable processing

Each line represents an individual structured record.

---

# CSV Output

Create CSV output:

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" -c 100 --csv-out packets.csv
```

CSV is useful for:

- Excel
- spreadsheets
- filtering
- sorting
- reporting
- basic tabular analysis

---

# Create All Individual Outputs

You can also specify all output files yourself:

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" -c 100 --pcap-out capture.pcap --jsonl-out packets.jsonl --csv-out packets.csv
```

---

# Offline PCAP Analysis

Howlr can analyse existing captures.

## Windows

```powershell
python .\howlr_packet_sentinel.py -r .\captures\capture.pcap
```

## Linux

```bash
python3 howlr_packet_sentinel.py -r ./captures/capture.pcap
```

Offline analysis does not require selecting a live interface.

---

# Offline Analysis With Direction Classification

## Windows

```powershell
python .\howlr_packet_sentinel.py -r .\captures\capture.pcap --local-network 192.168.1.0/24
```

## Linux

```bash
python3 howlr_packet_sentinel.py -r ./captures/capture.pcap --local-network 192.168.1.0/24
```

This allows saved packets to be classified as:

```text
IN
OUT
LAN
MULTICAST
BROADCAST
TRANSIT
```

---

# Offline Summary Only

```powershell
python .\howlr_packet_sentinel.py -r .\captures\capture.pcap --local-network 192.168.1.0/24 -q
```

This is useful when you want a quick overview without printing every packet.

---

# Quiet Mode

Enable using:

```text
-q
```

or:

```text
--quiet
```

Quiet Mode suppresses normal packet lines but continues:

- packet processing
- protocol counting
- service counting
- TCP event counting
- DNS analysis
- observation processing
- output-file generation
- final summary generation

Example:

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" --local-network 192.168.1.0/24 -t 60 -q
```

Quiet Mode is useful for:

- larger captures
- PCAP summaries
- baseline analysis
- protocol profiling
- service profiling

---

# Capture Summary

At the end of the capture, Howlr displays a summary.

Example:

```text
==============================================================
HOWLR PACKET SENTINEL - CAPTURE SUMMARY
==============================================================

Packets analysed : 150
Bytes analysed   : 46219
Duration         : 30.03 seconds
Packet rate      : 5.00 packets/sec
```

---

# Protocol Summary

Example:

```text
Protocols:
  Ethernet                                   150
  IPv4                                       124
  TCP                                         87
  UDP                                         37
  DNS                                         12
  IPv6                                        26
```

This tells you which protocols dominate the capture.

---

# Direction Summary

Example:

```text
Directions:
  OUT                                         65
  IN                                          55
  LAN                                         18
  MULTICAST                                   12
```

This quickly shows where traffic is flowing.

---

# Top Source IPs

Example:

```text
Top source IPs:
  192.168.1.50                               70
  104.20.23.154                              30
  192.168.1.1                                20
```

This helps identify active traffic sources.

---

# Top Destination IPs

Example:

```text
Top destination IPs:
  192.168.1.50                               55
  104.20.23.154                              40
  8.8.8.8                                    10
```

This helps answer:

```text
Where is the traffic going?
```

---

# Top Destination Ports

Example:

```text
Top destination ports:
  443/HTTPS                                  45
  53/DNS                                     20
  5353/MDNS                                  10
  80/HTTP                                     8
```

---

# Top Services

Example:

```text
Top services:
  HTTPS                                      55
  DNS                                        20
  MDNS                                       10
  HTTP                                        8
```

This provides a basic service profile.

---

# TCP Events

Example:

```text
TCP events:
  ACK                                        50
  PSH-ACK                                    20
  SYN                                        10
  SYN-ACK                                     8
  FIN                                         7
  RST                                         2
```

This helps describe the overall TCP behaviour of the capture.

---

# Top DNS Queries

Example:

```text
Top DNS queries:
  example.com                                 5
  api.example.net                             3
  _spotify-connect._tcp.local                 2
```

---

# Observations

Example:

```text
Observations:
  CLEARTEXT_SERVICE                           6
  TCP_SYN                                     4
  CLEARTEXT_HTTP                              1
  ARP_REPLY                                   1
```

This can be one of the most useful sections during Hunt Mode analysis.

---

# Understanding Traffic Directions

Assume:

```text
Local network: 192.168.1.0/24
Local host:    192.168.1.50
```

Howlr can classify traffic into the following categories.

---

# IN — Inbound

Traffic coming from outside your configured local network into it.

Example:

```text
104.20.23.154 -> 192.168.1.50
```

Howlr:

```text
IN | IPv4 104.20.23.154 -> 192.168.1.50
```

Examples include:

- website responses
- remote application responses
- Internet server traffic
- cloud service responses

Useful question:

```text
Which external systems are sending traffic to my network?
```

---

# OUT — Outbound

Traffic leaving your configured local network.

Example:

```text
192.168.1.50 -> 104.20.23.154
```

Howlr:

```text
OUT | IPv4 192.168.1.50 -> 104.20.23.154
```

Examples include:

- web browsing
- cloud applications
- software updates
- external APIs
- DNS queries
- outbound applications

Useful question:

```text
Which external systems is this host contacting?
```

---

# LAN — Local Network

Both source and destination belong to your configured local network.

Example:

```text
192.168.1.20 -> 192.168.1.50
```

Howlr:

```text
LAN | IPv4 192.168.1.20 -> 192.168.1.50
```

Examples include:

- SMB
- SSH
- RDP
- NAS traffic
- internal web applications
- workstation-to-workstation traffic

Useful question:

```text
Which machines inside my network are communicating?
```

---

# MULTICAST

Traffic sent to a multicast group instead of one single destination.

Example:

```text
192.168.1.1 -> 224.0.0.251
```

`224.0.0.251` is commonly used by mDNS.

Possible output:

```text
MULTICAST | UDP 5353/MDNS -> 5353/MDNS
```

IPv6 example:

```text
ff02::fb
```

Typical multicast traffic:

- mDNS
- device discovery
- printer discovery
- service discovery
- media-device discovery

Multicast traffic is normal on many networks.

---

# BROADCAST

Traffic intended for all devices within the broadcast domain.

Example destination:

```text
255.255.255.255
```

Typical examples include:

- DHCP
- discovery protocols
- network bootstrapping
- local service discovery

Broadcast traffic is not automatically suspicious.

---

# TRANSIT

Traffic that does not match the configured local network relationship.

Possible causes:

- incorrect `--local-network`
- another subnet visible to the interface
- routing
- forwarding
- multiple networks on the capture interface
- IPv6 traffic while only an IPv4 local network is configured

`TRANSIT` does not mean malicious traffic.

---

# Use Case 1 — What Is This Machine Talking To?

Suppose a workstation appears to have unexpected network activity.

You want to know:

```text
Which systems is it talking to?

Which external IP addresses are contacted?

Which local machines are involved?

Which services are being used?

Which DNS names appear?
```

Run:

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" --local-network 192.168.1.0/24 -t 60
```

Review:

```text
Directions
Top source IPs
Top destination IPs
Top destination ports
Top services
Top DNS queries
Observations
```

Example:

```text
Top destination IPs:
  104.20.23.154
  8.8.8.8
  192.168.1.20

Top services:
  HTTPS
  DNS
  HTTP
```

This gives you a quick network profile of the system.

---

# Use Case 2 — Quick SOC-Style First Look

## Step 1 — Find the Interface

```powershell
python .\howlr_packet_sentinel.py --list-interfaces
```

## Step 2 — Identify Your Local Network

Example:

```text
192.168.1.0/24
```

## Step 3 — Capture Normal Traffic

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" --local-network 192.168.1.0/24 -t 30
```

## Step 4 — Run Hunt Mode

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" --local-network 192.168.1.0/24 --hunt -t 60
```

## Step 5 — Ask Questions

```text
Is the machine contacting unexpected Internet addresses?

Is there unexpected LAN communication?

Are cleartext protocols being used?

Are repeated TCP resets present?

Is one host probing many ports?

Did an ARP mapping change?

Are DNS lookups repeatedly failing?

Which services dominate the capture?
```

## Step 6 — Preserve Evidence

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" --local-network 192.168.1.0/24 --session investigation -t 300
```

Then open the PCAP with Wireshark if deeper investigation is required.

---

# Use Case 3 — Find Unexpected Outbound Traffic

Run:

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" --local-network 192.168.1.0/24 -t 60
```

Look for:

```text
OUT
```

and:

```text
Top destination IPs
```

Example:

```text
OUT | IPv4 192.168.1.50 -> 104.20.23.154
```

Useful question:

```text
Why is this machine contacting this Internet address?
```

This can help with:

- malware-analysis labs
- application troubleshooting
- software inventory
- incident triage
- unknown application traffic

Outbound traffic is not inherently malicious.

---

# Use Case 4 — Examine Local Network Communication

Look for:

```text
LAN
```

Example:

```text
LAN | IPv4 192.168.1.20 -> 192.168.1.50 | TCP 50123 -> 445/SMB
```

This helps identify:

- SMB traffic
- SSH
- RDP
- local servers
- NAS traffic
- internal applications

Useful question:

```text
Why are these two internal machines communicating?
```

---

# Use Case 5 — Detect Possible Port Scanning

Run:

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" --local-network 192.168.1.0/24 --hunt --scan-threshold 5 --scan-window 10 -t 60
```

Possible result:

```text
POSSIBLE_PORT_SCAN
```

Possible explanations:

```text
Nmap
vulnerability scanner
administrator testing
asset discovery
monitoring software
reconnaissance
```

This is a triage signal rather than a confirmed attack.

---

# Use Case 6 — Find Cleartext HTTP

Run:

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" -f "tcp port 80" --hunt -t 30
```

Generate:

```powershell
curl http://example.com -UseBasicParsing
```

Possible result:

```text
HTTP GET host=example.com uri=/
OBS=CLEARTEXT_SERVICE:HTTP,CLEARTEXT_HTTP
```

This demonstrates why HTTP traffic can reveal useful metadata to a passive observer.

---

# Use Case 7 — Identify Cleartext Services

Hunt Mode may identify services such as:

```text
FTP
TELNET
HTTP
POP3
IMAP
LDAP
VNC
```

Example:

```text
OBS=CLEARTEXT_SERVICE:TELNET
```

This helps identify legacy services that may deserve review.

---

# Use Case 8 — Investigate ARP Changes

Possible observation:

```text
ARP_MAC_CHANGE
```

Questions to ask:

```text
Was this IP reassigned?

Did the device change?

Is there a duplicate IP?

Did a VM migrate?

Is this a failover system?

Could ARP spoofing be occurring?
```

Howlr identifies the change; deeper investigation determines why it occurred.

---

# Use Case 9 — Investigate DNS Behaviour

Capture:

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" -f "port 53" -t 60
```

Review:

```text
Top DNS queries
DNS_ERROR_RCODE
```

Questions:

```text
Which domains is the machine resolving?

Are there unfamiliar domains?

Are queries repeatedly failing?

Is DNS traffic going to an unexpected resolver?
```

---

# Use Case 10 — Preserve Evidence for Wireshark

Run:

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" --local-network 192.168.1.0/24 --session suspicious-traffic -t 300
```

Workflow:

```text
Howlr
   ↓
Interesting traffic identified
   ↓
PCAP preserved
   ↓
Wireshark
   ↓
Deep packet inspection
```

This is one of Howlr's primary intended workflows.

---

# Use Case 11 — Triage a PCAP Before Opening Wireshark

Instead of manually opening a large capture immediately:

```powershell
python .\howlr_packet_sentinel.py -r .\capture.pcap --local-network 192.168.1.0/24 -q
```

Howlr can quickly show:

```text
protocol distribution
traffic directions
top source IPs
top destination IPs
top ports
top services
TCP events
DNS queries
observations
```

You can then decide which traffic deserves manual inspection.

---

# Use Case 12 — Create a Network Baseline

Create a normal baseline:

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" --local-network 192.168.1.0/24 --session baseline -t 60
```

Later capture another period:

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" --local-network 192.168.1.0/24 --session investigation -t 60
```

Compare:

```text
protocol counts
direction counts
destination IPs
services
DNS queries
TCP events
observations
```

This can help reveal behavioural differences.

---

# Use Case 13 — Learn TCP Behaviour

Capture only TCP:

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" -f "tcp" -c 100
```

Watch:

```text
SYN
SYN-ACK
ACK
PSH-ACK
FIN
RST
```

This makes Howlr useful when learning how a TCP connection is established, used and terminated.

---

# Use Case 14 — Learn Network Discovery Traffic

Run a normal capture and observe:

```text
MDNS
MULTICAST
ARP
SSDP
```

This can help students understand why a quiet LAN still generates traffic even when nobody is actively browsing the Internet.

---

# Use Case 15 — Troubleshoot an Application

Suppose an application is not working correctly.

Howlr can help answer:

```text
Is it attempting a TCP connection?

Which destination IP is used?

Which destination port is used?

Does the connection reset?

Are DNS queries failing?

Is traffic leaving the machine at all?
```

A short capture can therefore provide useful context before moving to deeper tools.

---

# Recommended Analyst Workflow

A practical workflow is:

```text
1. Discover interface
        ↓
2. Identify local subnet
        ↓
3. Run short normal capture
        ↓
4. Review protocols, directions and services
        ↓
5. Run Hunt Mode
        ↓
6. Investigate observations
        ↓
7. Save a session
        ↓
8. Open interesting PCAP traffic in Wireshark
```

Diagram:

```text
                  HOWLR PACKET SENTINEL
                           │
            ┌──────────────┼──────────────┐
            │              │              │
        Protocols       Services      Directions
            │              │              │
            └──────────────┼──────────────┘
                           │
                     Observations
                           │
                    Interesting?
                      /        \
                    No          Yes
                    │            │
                 Finish      Save Session
                                 │
                                 ▼
                             PCAP File
                                 │
                                 ▼
                             Wireshark
```

---

# Troubleshooting

# Interface Not Found

Run:

```powershell
python .\howlr_packet_sentinel.py --list-interfaces
```

Copy the exact interface name.

Example:

```powershell
python .\howlr_packet_sentinel.py -i "Realtek PCIe GbE Family Controller" -c 20
```

Do not use a numeric interface index with `-i` in v0.2.0.

---

# No Packets Captured

Check:

1. the correct interface was selected;
2. the interface is active;
3. traffic is actually passing through it;
4. the capture filter is not too restrictive;
5. the process has sufficient privileges.

Generate normal traffic during testing.

Windows:

```powershell
curl http://example.com -UseBasicParsing
```

Linux:

```bash
curl http://example.com
```

---

# Hunt Mode Prints Nothing

This may be completely normal.

Hunt Mode prints only packets containing observations.

For example:

```text
Packets analysed : 500
Observations      : none
```

means packets were processed but none matched the current observation rules.

---

# Wrong Traffic Direction

Verify:

```text
--local-network
```

If your address is:

```text
192.168.0.111
```

with a `/24` network, the corresponding network is normally:

```text
192.168.0.0/24
```

Using the wrong CIDR can cause confusing direction labels.

---

# Linux Permission Error

Use:

```bash
sudo .venv/bin/python howlr_packet_sentinel.py -i eth0 -c 20
```

---

# Windows Capture Error

Check:

- Npcap is installed
- the selected interface exists
- the interface is active
- PowerShell has appropriate privileges

Try opening PowerShell as Administrator for troubleshooting.

---

# BPF Filter Error

If a filter fails:

1. check the filter syntax;
2. test without `-f`;
3. verify packet-capture support is installed.

Linux users can ensure libpcap/tcpdump support exists:

```bash
sudo apt install tcpdump libpcap-dev
```

---

# HTTPS Does Not Show URI

This is expected.

HTTPS is encrypted with TLS.

Howlr can identify:

```text
443/HTTPS
```

but cannot passively read the encrypted HTTP request content.

---

# VPN or Tailscale Traffic Appears on the Wrong Interface

VPNs and overlay networks can modify routing.

Examples include:

- Tailscale
- commercial VPN clients
- corporate VPN software

Run:

```text
--list-interfaces
```

and determine which interface is actually carrying the traffic.

---

# Virtual Machine Traffic Is Missing

Virtual machines may use:

- NAT
- bridged networking
- host-only networking
- virtual adapters

Make sure Howlr is capturing the interface where the desired traffic actually passes.

---

# Tested Platforms

Howlr Packet Sentinel v0.2.0 has been manually validated on:

```text
Windows
Kali Linux
```

---

# Validated v0.2.0 Features

Testing included:

- `--version`
- `--help`
- interface discovery
- live Windows capture
- live Kali/Linux capture
- offline PCAP replay
- packet-count limits
- capture timeout
- IPv4
- IPv6
- TCP
- UDP
- ARP
- DNS
- mDNS
- HTTP
- traffic direction classification
- `IN`
- `OUT`
- `LAN`
- `MULTICAST`
- service identification
- inbound service identification
- TCP flag formatting
- TCP event classification
- Hunt Mode
- cleartext service observations
- cleartext HTTP observations
- HTTP method extraction
- HTTP Host extraction
- HTTP URI extraction
- ARP reply observations
- ARP MAC-change detection
- TCP SYN observations
- controlled port-scan heuristic testing
- PCAP export
- JSONL export
- CSV export
- session capture
- quiet mode
- capture statistics
- capture summaries

---

# Example Validated Kali Hunt

Command:

```bash
sudo .venv/bin/python howlr_packet_sentinel.py -i eth0 --local-network 192.168.42.0/24 --hunt -t 20
```

Test traffic:

```bash
curl http://example.com
```

Howlr identified:

```text
TCP_SYN
CLEARTEXT_SERVICE:HTTP
CLEARTEXT_HTTP
```

and extracted:

```text
HTTP GET host=example.com uri=/
```

Example workflow:

```text
curl request
    ↓
DNS lookup
    ↓
TCP connection
    ↓
HTTP request
    ↓
Howlr captures packet
    ↓
HTTP service recognised
    ↓
HTTP metadata parsed
    ↓
CLEARTEXT_HTTP observation
    ↓
Capture summary
```

---

# Example Port Scan Validation

Howlr v0.2.0 was also validated using controlled TCP connection attempts against multiple ports.

The scan heuristic successfully generated:

```text
POSSIBLE_PORT_SCAN
```

when the configured threshold was reached.

Example observation:

```text
POSSIBLE_PORT_SCAN:192.168.1.20:5_ports_in_10s
```

---

# Example ARP Validation

A controlled PCAP containing:

```text
192.168.1.50 -> MAC A
```

followed by:

```text
192.168.1.50 -> MAC B
```

successfully produced:

```text
ARP_MAC_CHANGE
```

demonstrating that ARP mappings are tracked during analysis.

---

# Project Structure

Typical repository:

```text
howlr-packet-sentinel/
│
├── howlr_packet_sentinel.py
│   Main Howlr Packet Sentinel program
│
├── requirements.txt
│   Python dependencies
│
├── README.md
│   Installation, usage and documentation
│
├── CHANGELOG.md
│   Release history
│
├── LICENSE
│   Project licence
│
├── .gitignore
│   Git exclusions
│
├── captures/
│   Runtime PCAP captures
│   Created when required
│
└── output/
    Runtime JSONL and CSV output
    Created when required
```

Runtime directories are ignored by Git.

---

# What Howlr Packet Sentinel Is Good At

v0.2.0 is particularly useful for:

- networking education
- TCP/IP learning
- packet-analysis practice
- SOC fundamentals
- cybersecurity labs
- first-pass network triage
- service identification
- direction classification
- DNS triage
- TCP event analysis
- cleartext service discovery
- cleartext HTTP detection
- simple scan detection
- ARP mapping investigation
- PCAP evidence collection
- offline PCAP summaries
- network troubleshooting

---

# What Howlr Packet Sentinel Is Not

Howlr Packet Sentinel is not:

- a full IDS
- a full IPS
- EDR
- NDR
- SIEM
- antivirus
- malware detection software
- a vulnerability scanner
- a replacement for Wireshark
- a replacement for Zeek
- a replacement for Suricata
- a replacement for Snort

Its scope is intentionally narrower:

```text
Quickly understand network traffic
and identify what deserves deeper investigation.
```

---

# Howlr vs Wireshark

Howlr Packet Sentinel and Wireshark serve different purposes.

Howlr:

```text
Capture
↓
Summarise
↓
Highlight
↓
Identify what deserves attention
```

Wireshark:

```text
Inspect individual packets
↓
Follow streams
↓
Decode protocols deeply
↓
Perform detailed packet investigation
```

A useful workflow is:

```text
Howlr
  ↓
Find something interesting
  ↓
PCAP
  ↓
Wireshark
```

---

# Project Status

Howlr Packet Sentinel is an educational and defensive security project under active development.

Current stable release:

```text
v0.2.0
```

v0.2.0 focuses on:

- packet capture
- protocol visibility
- traffic direction
- service identification
- TCP event analysis
- DNS analysis
- cleartext observations
- ARP mapping changes
- scan triage
- structured output
- practical CLI usage
- analyst-oriented summaries

---

# Future Ideas

Possible future improvements include:

- automatic active-interface detection
- automatic local-network detection
- simplified installation
- installable CLI
- shorter executable command such as:

```text
howlr
```

Possible future syntax:

```text
howlr --hunt
```

Other ideas include:

- numeric interface selection
- improved interface selection
- richer protocol parsing
- richer HTTP analysis
- additional DNS analysis
- expanded service identification
- improved scan heuristics
- additional network observations
- richer session reporting
- improved analyst summaries
- cleaner CLI output
- configuration files
- baseline comparison
- improved reporting

These are development ideas and are not guarantees for a particular release.

---

# Authorised Use

Use Howlr Packet Sentinel only on systems and networks that you:

- own; or
- have explicit permission to monitor.

Packet capture can expose:

- network addresses
- hostnames
- DNS requests
- application metadata
- unencrypted communications
- information belonging to other users

Always comply with:

- applicable law
- organisational policy
- privacy requirements
- rules of engagement
- authorisation boundaries

Security observations generated by Howlr Packet Sentinel are:

> **triage hints, not proof of malicious activity.**

---

# Licence

Howlr Packet Sentinel is distributed under the terms contained in:

```text
LICENSE
```

---

# Howlr Packet Sentinel

```text
Capture.
Understand.
Summarise.
Highlight.
Investigate.
```