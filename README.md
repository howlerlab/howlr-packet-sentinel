# Howlr Packet Sentinel

**Author:** Rudy (@howlerlab)  
**Current development version:** `0.2.0`

Howlr Packet Sentinel is a passive packet-capture and network-triage tool built with Python and Scapy.

It is intended for:

- networking study
- SOC packet triage
- incident-response first look
- authorised penetration-testing observation
- offline PCAP analysis

> **Authorised use only**
>
> Capture only interfaces, systems, and networks that you own or are explicitly authorised to monitor.

---

## Main Features

Howlr Packet Sentinel v0.2.0 includes:

- live packet capture
- offline PCAP and PCAPNG analysis
- Ethernet, ARP, IPv4, IPv6, TCP, UDP, ICMP and ICMPv6 summaries
- DNS and DHCP metadata summaries
- common service-name labels
- readable TCP flags and TCP event classification
- network direction labels:
  - `LAN`
  - `IN`
  - `OUT`
  - `TRANSIT`
  - `MULTICAST`
  - `BROADCAST`
- packet severity labels:
  - `NORMAL`
  - `INFO`
  - `NOTICE`
  - `WARNING`
- PCAP export
- JSONL export
- CSV export
- automatic timestamped session output
- quiet summary mode
- hunt mode for triage-focused output
- protocol, endpoint, service, TCP-event and DNS statistics
- basic ARP mapping-change observation
- basic TCP SYN scan heuristics
- cleartext HTTP request metadata for supported HTTP traffic

Possible observations include:

- `TCP_SYN`
- `TCP_RST`
- `POSSIBLE_PORT_SCAN`
- `POSSIBLE_HOST_SCAN`
- `POSSIBLE_SYN_SCAN`
- `NULL_SCAN_PATTERN`
- `XMAS_SCAN_PATTERN`
- `ARP_MAC_CHANGE`
- `IP_FRAGMENT`
- `DNS_ERROR_RCODE`
- `CLEARTEXT_SERVICE`
- `CLEARTEXT_HTTP`

> Observations are triage hints only. They are **not proof of malicious activity**.

---

## Project Structure

```text
howlr-packet-sentinel/
├── .gitignore
├── CHANGELOG.md
├── LICENSE
├── README.md
├── howlr_packet_sentinel.py
└── requirements.txt
```

Runtime folders such as `captures/` and `output/` are created automatically when required and are ignored by Git.

---

# Requirements

## General

- Python 3.13 or newer
- Scapy
- Git, if cloning from GitHub

## Windows Live Capture

- Npcap
- Administrator privileges

## Linux Live Capture

- root or suitable packet-capture permissions

The current Python dependency is:

```text
scapy>=2.7.0
```

---

# Clone the Repository

```bash
git clone https://github.com/howlerlab/howlr-packet-sentinel.git
cd howlr-packet-sentinel
```

The stable version is normally available from `main`.

To test the current v0.2 development branch:

```bash
git switch develop-v0.2
```

---

# Windows Installation

## 1. Create a Virtual Environment

From inside the project directory:

```powershell
python -m venv .venv
```

Creating `.venv` does **not** install Scapy.

It creates an isolated Python environment for the project.

---

## 2. Activate the Virtual Environment

```powershell
.\.venv\Scripts\Activate.ps1
```

The prompt should begin with:

```text
(.venv)
```

### PowerShell Script Execution Is Disabled

If PowerShell reports:

```text
running scripts is disabled on this system
```

you can allow locally created scripts for your user account:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

Alternatively, activation is not required.

You can run the virtual-environment Python directly:

```powershell
.\.venv\Scripts\python.exe .\howlr_packet_sentinel.py --help
```

---

## 3. Upgrade pip

```powershell
python -m pip install --upgrade pip
```

---

## 4. Install Dependencies

```powershell
python -m pip install -r requirements.txt
```

This installs Scapy into the active virtual environment.

---

## 5. Verify Scapy

```powershell
python -c "import scapy; print(scapy.__version__)"
```

Example:

```text
2.7.0
```

---

## 6. Verify Howlr Packet Sentinel

```powershell
python .\howlr_packet_sentinel.py --version
```

Expected:

```text
howlr_packet_sentinel.py 0.2.0
```

For live packet capture, ensure Npcap is installed and run PowerShell or PyCharm with the required Administrator privileges.

---

# Kali Linux / Linux Installation

## 1. Create a Virtual Environment

```bash
python3 -m venv .venv
```

If the `venv` module is unavailable:

```bash
sudo apt update
sudo apt install python3-venv
```

---

## 2. Activate the Virtual Environment

```bash
source .venv/bin/activate
```

---

## 3. Upgrade pip

```bash
python3 -m pip install --upgrade pip
```

---

## 4. Install Dependencies

```bash
python3 -m pip install -r requirements.txt
```

---

## 5. Verify Scapy

```bash
python3 -c "import scapy; print(scapy.__version__)"
```

---

## 6. Verify Howlr Packet Sentinel

```bash
python3 howlr_packet_sentinel.py --version
```

For live capture using the virtual environment:

```bash
sudo .venv/bin/python howlr_packet_sentinel.py -i "<INTERFACE>" -c 20
```

Offline PCAP analysis normally does not require root privileges.

---

# Using PyCharm

1. Open the entire `howlr-packet-sentinel` directory in PyCharm.
2. Select or create the project's `.venv` interpreter.
3. Open the PyCharm terminal.
4. Install the dependencies:

```powershell
python -m pip install -r requirements.txt
```

Verify Scapy:

```powershell
python -c "import scapy; print(scapy.__version__)"
```

Then verify Sentinel:

```powershell
python .\howlr_packet_sentinel.py --version
```

If PyCharm reports:

```text
ModuleNotFoundError: No module named 'scapy'
```

Scapy is not installed in the Python interpreter currently selected by PyCharm.

Make sure PyCharm is using the project's `.venv`, then run:

```powershell
python -m pip install -r requirements.txt
```

---

# Choosing a Network Interface

Before performing a live capture, first identify the network interface that you want Howlr Packet Sentinel to monitor.

Do **not** assume that your interface will be named `Wi-Fi`, `Ethernet`, `eth0`, or `wlan0`.

Interface names vary between operating systems and computers.

## Windows

```powershell
python .\howlr_packet_sentinel.py --list-interfaces
```

## Linux / Kali

```bash
python3 howlr_packet_sentinel.py --list-interfaces
```

The command displays the interfaces detected by Scapy.

Possible interface names might include:

```text
Wi-Fi
Ethernet
eth0
wlan0
ens33
enp0s3
```

Choose the interface that you want to monitor and provide its name using:

```text
-i "<INTERFACE>"
```

or:

```text
--interface "<INTERFACE>"
```

For example:

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" -c 100
```

Replace `<INTERFACE>` with the actual interface reported by `--list-interfaces`.

---

# Basic Usage

## Show Version

Windows:

```powershell
python .\howlr_packet_sentinel.py --version
```

Linux:

```bash
python3 howlr_packet_sentinel.py --version
```

---

## Show Help

Windows:

```powershell
python .\howlr_packet_sentinel.py --help
```

Linux:

```bash
python3 howlr_packet_sentinel.py --help
```

---

## List Interfaces

Windows:

```powershell
python .\howlr_packet_sentinel.py --list-interfaces
```

Linux:

```bash
python3 howlr_packet_sentinel.py --list-interfaces
```

---

## Capture 100 Packets

Windows:

```powershell
python .\howlr_packet_sentinel.py `
  -i "<INTERFACE>" `
  -c 100
```

Linux:

```bash
sudo .venv/bin/python howlr_packet_sentinel.py \
  -i "<INTERFACE>" \
  -c 100
```

---

## Capture for 60 Seconds

Windows:

```powershell
python .\howlr_packet_sentinel.py `
  -i "<INTERFACE>" `
  -t 60
```

Linux:

```bash
sudo .venv/bin/python howlr_packet_sentinel.py \
  -i "<INTERFACE>" \
  -t 60
```

Press `Ctrl+C` to stop a live capture early.

---

# Defining the Local Network

Use `--local-network` to tell Howlr Packet Sentinel which network should be considered local.

For example:

```text
192.168.1.0/24
```

Windows:

```powershell
python .\howlr_packet_sentinel.py `
  -i "<INTERFACE>" `
  --local-network 192.168.1.0/24 `
  -c 100
```

Linux:

```bash
sudo .venv/bin/python howlr_packet_sentinel.py \
  -i "<INTERFACE>" \
  --local-network 192.168.1.0/24 \
  -c 100
```

Replace:

```text
192.168.1.0/24
```

with the CIDR for the network you are actually monitoring.

---

# Network Direction Labels

When `--local-network` is supplied, Sentinel can classify traffic direction.

| Label | Meaning |
|---|---|
| `LAN` | Source and destination are inside a supplied local network |
| `OUT` | Local source to non-local destination |
| `IN` | Non-local source to local destination |
| `TRANSIT` | Neither endpoint belongs to a supplied local network |
| `MULTICAST` | Destination is an IP multicast address |
| `BROADCAST` | Destination is the limited IPv4 broadcast address |

Multiple local networks may be supplied.

Example:

```powershell
python .\howlr_packet_sentinel.py `
  -i "<INTERFACE>" `
  --local-network 192.168.1.0/24 `
  --local-network 192.168.10.0/24 `
  -c 100
```

---

# Capture Filters

The `-f` or `--filter` option accepts Berkeley Packet Filter (BPF) syntax.

## ICMP

```powershell
python .\howlr_packet_sentinel.py `
  -i "<INTERFACE>" `
  -f "icmp" `
  -c 20
```

## DNS

```powershell
python .\howlr_packet_sentinel.py `
  -i "<INTERFACE>" `
  -f "port 53" `
  -c 50
```

## TCP

```powershell
python .\howlr_packet_sentinel.py `
  -i "<INTERFACE>" `
  -f "tcp" `
  -c 100
```

## UDP

```powershell
python .\howlr_packet_sentinel.py `
  -i "<INTERFACE>" `
  -f "udp" `
  -c 100
```

## HTTPS

```powershell
python .\howlr_packet_sentinel.py `
  -i "<INTERFACE>" `
  -f "tcp port 443" `
  -c 100
```

---

# Session Mode

`--session` automatically creates timestamped:

- PCAP
- JSONL
- CSV

files for a capture session.

Example:

```powershell
python .\howlr_packet_sentinel.py `
  -i "<INTERFACE>" `
  --local-network 192.168.1.0/24 `
  --session my-capture `
  -c 100
```

Example generated structure:

```text
captures/
└── my-capture_20260821_171350.pcap

output/
├── my-capture_20260821_171350.jsonl
└── my-capture_20260821_171350.csv
```

The directories are created automatically if they do not already exist.

Because packet captures may contain sensitive network metadata, `captures/` and `output/` are excluded from Git by default.

---

# Manual Export

Outputs can also be selected individually.

## PCAP

```powershell
python .\howlr_packet_sentinel.py `
  -i "<INTERFACE>" `
  -c 100 `
  --pcap-out captures\capture.pcap
```

## JSONL

```powershell
python .\howlr_packet_sentinel.py `
  -i "<INTERFACE>" `
  -c 100 `
  --jsonl-out output\capture.jsonl
```

## CSV

```powershell
python .\howlr_packet_sentinel.py `
  -i "<INTERFACE>" `
  -c 100 `
  --csv-out output\capture.csv
```

### PCAP

Preserves the captured packets for later analysis with Howlr Packet Sentinel, Wireshark, and other compatible tools.

### JSONL

Stores one structured JSON object per packet and preserves richer nested metadata.

### CSV

Stores selected packet metadata in a tabular format suitable for spreadsheets and other analysis tools.

---

# Offline PCAP Analysis

Howlr Packet Sentinel can analyse an existing PCAP or PCAPNG file instead of capturing live traffic.

Example:

```powershell
python .\howlr_packet_sentinel.py `
  -r .\captures\capture.pcap `
  --local-network 192.168.1.0/24
```

No interface needs to be selected when analysing an offline capture.

---

## Quiet Offline Analysis

Use `-q` or `--quiet` to suppress individual packet lines while still producing the final statistics.

```powershell
python .\howlr_packet_sentinel.py `
  -r .\captures\capture.pcap `
  --local-network 192.168.1.0/24 `
  -q
```

This can be useful when analysing larger capture files.

---

# Hunt Mode

Hunt mode analyses all packets but only prints packets containing triage observations.

```powershell
python .\howlr_packet_sentinel.py `
  -i "<INTERFACE>" `
  --local-network 192.168.1.0/24 `
  --hunt
```

Hunt mode can reduce normal packet noise while looking for traffic that matches Sentinel's observation rules.

It is intended as a first-look triage aid.

It is **not** a replacement for:

- Wireshark
- Zeek
- Suricata
- an IDS/IPS
- NDR
- EDR
- a SIEM

---

# Scan Heuristics

Howlr Packet Sentinel tracks TCP SYN activity over a configurable time window.

The default settings are:

```text
--scan-threshold 20
--scan-window 10
```

Example:

```powershell
python .\howlr_packet_sentinel.py `
  -i "<INTERFACE>" `
  --local-network 192.168.1.0/24 `
  --hunt `
  --scan-threshold 20 `
  --scan-window 10
```

Possible observations include:

```text
POSSIBLE_PORT_SCAN
POSSIBLE_HOST_SCAN
POSSIBLE_SYN_SCAN
```

These are heuristics.

Legitimate applications, administration tools, vulnerability scanners, monitoring systems, and other network activity may produce similar traffic patterns.

---

# ARP Monitoring

Howlr Packet Sentinel tracks observed sender IP-to-MAC mappings during a capture.

If the same sender IP later appears associated with a different MAC address, Sentinel may generate:

```text
ARP_MAC_CHANGE
```

This can be useful during first-look ARP analysis.

However, an IP-to-MAC mapping change is **not automatically evidence of ARP spoofing**.

Legitimate causes may include:

- DHCP changes
- virtual machines
- high-availability systems
- interface changes
- network failover
- legitimate device replacement

Always investigate the surrounding network context.

---

# Cleartext HTTP Metadata

For supported unencrypted HTTP traffic on ports such as `80` or `8080`, Sentinel can extract request metadata including:

- HTTP method
- host
- URI

Example metadata might resemble:

```text
GET
example.local
/index.html
```

Howlr Packet Sentinel does **not** decrypt HTTPS.

Traffic protected by TLS normally prevents the HTTP request contents from being visible to a passive packet analyser.

---

# TCP Event Labels

Sentinel converts common TCP flag combinations into more readable event names.

Examples include:

```text
SYN
SYN-ACK
ACK
PSH-ACK
RST
FIN
```

For example:

```text
flags=ACK+PSH event=PSH-ACK
```

This is intended to make packet output easier to interpret during networking study and first-look analysis.

---

# Service Labels

Common destination ports are displayed with service names when known.

Examples:

```text
22/SSH
53/DNS
80/HTTP
443/HTTPS
445/SMB
3389/RDP
5353/MDNS
```

Port-based service names are hints only.

Applications can operate on non-standard ports, and a port number alone does not prove which application generated the traffic.

---

# Capture Summary

At the end of a capture or offline analysis, Sentinel produces a summary.

Depending on the traffic observed, this may include:

- packets analysed
- bytes analysed
- capture duration
- packet rate
- protocol counts
- direction counts
- top source IPs
- top destination IPs
- top destination ports
- top services
- TCP events
- top DNS queries
- observation counts

Example structure:

```text
==============================================================
HOWLR PACKET SENTINEL - CAPTURE SUMMARY
==============================================================
Packets analysed : 50
Bytes analysed   : 25440
Duration         : 2.70 seconds
Packet rate      : 18.53 packets/sec

Protocols:
  Ethernet
  IPv4
  TCP
  UDP
  ARP

Directions:
  OUT
  IN
  LAN
  MULTICAST

Top destination ports:
  443/HTTPS
  5353/MDNS

TCP events:
  ACK
  PSH-ACK

Note: observations are triage hints, not proof of malicious activity.
==============================================================
```

Protocol counts overlap because one packet may contain several protocol layers.

For example:

```text
Ethernet
└── IPv4
    └── UDP
        └── DNS
```

One DNS packet can therefore contribute to the Ethernet, IPv4, UDP, and DNS counters.

---

# Command Options

The current v0.2 command-line options include:

```text
--version
--list-interfaces
-i, --interface
-r, --read
-f, --filter
-c, --count
-t, --timeout
--local-network
--pcap-out
--jsonl-out
--csv-out
--session
--hunt
--scan-threshold
--scan-window
-q, --quiet
```

Always use:

```powershell
python .\howlr_packet_sentinel.py --help
```

for the authoritative option list provided by the installed version.

---

# Validated v0.2.0 Functionality

The current v0.2 development build has been manually validated for:

- startup
- `--version`
- CLI help
- interface enumeration
- Windows live capture
- IPv4 parsing
- IPv6 parsing
- TCP parsing
- UDP parsing
- ARP parsing
- DNS parsing
- service-name labelling
- readable TCP event labelling
- `LAN` classification
- `IN` classification
- `OUT` classification
- `MULTICAST` classification
- enhanced capture statistics
- automatic `--session` output
- PCAP export
- JSONL export
- CSV export
- offline PCAP re-analysis
- quiet summary mode

The remaining triage heuristics should be treated as development features until deliberately exercised and validated.

---

# Current Limitations

Howlr Packet Sentinel does not:

- decrypt HTTPS
- identify the operating-system process responsible for every connection
- reassemble complete TCP streams
- extract transferred files
- conclusively detect malware
- replace Wireshark
- replace Zeek
- replace Suricata
- replace NDR or EDR tooling
- display every packet from every device on a switched or managed network
- guarantee that every heuristic observation is malicious
- transmit packets
- modify packets
- replay packets
- inject packets

Howlr Packet Sentinel is designed as a lightweight packet-visibility, networking-education, and first-look triage tool.

---

# Troubleshooting

## `ModuleNotFoundError: No module named 'scapy'`

Scapy is not installed in the Python environment being used to run Sentinel.

With the virtual environment activated:

```powershell
python -m pip install -r requirements.txt
```

Verify:

```powershell
python -c "import scapy; print(scapy.__version__)"
```

If you are not activating the Windows virtual environment:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

Then:

```powershell
.\.venv\Scripts\python.exe -c "import scapy; print(scapy.__version__)"
```

---

## PowerShell Cannot Activate `.venv`

If PowerShell reports:

```text
running scripts is disabled on this system
```

you can use:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

Alternatively, activation is optional:

```powershell
.\.venv\Scripts\python.exe .\howlr_packet_sentinel.py --help
```

---

## Permission Denied During Live Capture

### Windows

Check that:

- Npcap is installed
- the terminal has the required Administrator privileges

### Linux

Use root or suitable packet-capture permissions.

For example:

```bash
sudo .venv/bin/python howlr_packet_sentinel.py -i "<INTERFACE>" -c 20
```

---

## Cannot Find the Correct Interface

Run:

```powershell
python .\howlr_packet_sentinel.py --list-interfaces
```

Then use one of the interface names reported by Sentinel:

```powershell
python .\howlr_packet_sentinel.py `
  -i "<INTERFACE>" `
  -c 20
```

---

## BPF Filter Fails

Check:

- BPF syntax
- selected interface
- Npcap or libpcap availability
- capture permissions

Start with an unfiltered capture to confirm that packet capture itself works:

```powershell
python .\howlr_packet_sentinel.py `
  -i "<INTERFACE>" `
  -c 10
```

Then add the filter.

---

# Security and Privacy

Packet captures can contain sensitive information, including:

- IP addresses
- MAC addresses
- hostnames
- DNS queries
- unencrypted application metadata
- internal network structure
- potentially unencrypted content

Do not commit packet captures or generated analysis files to a public Git repository unless you have reviewed and intentionally sanitised them.

The project's `.gitignore` excludes:

```text
captures/
output/
```

by default.

---

# Licence

Howlr Packet Sentinel is licensed under the MIT License.

See:

```text
LICENSE
```

for the full licence terms.

---

# Authorised Use

Capture only interfaces, systems, and networks that you own or are explicitly authorised to monitor.

Users are responsible for ensuring that their use of Howlr Packet Sentinel complies with:

- applicable laws
- organisational policies
- privacy requirements
- rules of engagement
- network-owner authorisation

Howlr Packet Sentinel is a passive analysis tool. It does not transmit, modify, replay, or inject packets.