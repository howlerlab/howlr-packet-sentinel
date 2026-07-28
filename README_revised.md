# Howlr Packet Sentinel

**Author:** Rudy (@howlerlab)

A passive packet-capture and network-triage tool built with Scapy.

It is intended for:

-   Networking study
-   SOC packet triage
-   Incident response first look
-   Authorised penetration-testing observation
-   Offline PCAP analysis

> **Disclaimer**
>
> Use this tool only on systems and networks you own or are explicitly
> authorised to monitor.

------------------------------------------------------------------------

# Project Structure

``` text
howlr-packet-sentinel/
│
├── captures/
├── docs/
│   ├── architecture.md
│   ├── protocol_notes.md
│   └── roadmap.md
│
├── examples/
│   ├── analyse_pcap.md
│   ├── capture_dns.md
│   ├── capture_http.md
│   └── capture_icmp.md
│
├── output/
│
├── .gitignore
├── CHANGELOG.md
├── LICENSE
├── README.md
├── howlr_packet_sentinel.py
└── requirements.txt
```

------------------------------------------------------------------------

# Project Files

  File                         Description
  ---------------------------- -----------------------------------
  `howlr_packet_sentinel.py`   Main application
  `requirements.txt`           Python dependencies
  `README.md`                  Documentation and usage
  `CHANGELOG.md`               Project version history
  `LICENSE`                    MIT License
  `.gitignore`                 Git ignore rules
  `captures/`                  Generated PCAP files
  `output/`                    JSONL and report output
  `docs/`                      Design notes and documentation
  `examples/`                  Example commands and walkthroughs

------------------------------------------------------------------------

# Main Features

-   Live packet capture
-   Offline PCAP and PCAPNG analysis
-   Ethernet, ARP, IPv4 and IPv6 support
-   TCP, UDP, ICMP and ICMPv6 summaries
-   DNS and DHCP summaries
-   TCP flag display
-   Common service-name labels
-   Incoming, outgoing and LAN direction labels
-   PCAP export
-   JSONL export
-   Protocol statistics
-   Endpoint statistics
-   Basic SOC triage observations

Possible observations include:

-   TCP SYN activity
-   Possible SYN scanning
-   NULL scan patterns
-   XMAS scan patterns
-   IP fragmentation
-   ARP replies
-   DNS errors
-   Cleartext service ports

These observations are investigation hints only and are **not proof of
malicious activity**.

------------------------------------------------------------------------

# Requirements

Before using Howlr Packet Sentinel, ensure you have:

-   Python 3.13 or newer
-   Git (optional, for cloning the repository)
-   Scapy
-   Npcap (Windows only, required for live packet capture)
-   Administrator (Windows) or root (Linux) privileges for live capture

------------------------------------------------------------------------

# Installation

## Clone the Repository

``` bash
git clone https://github.com/howlerlab/howlr-packet-sentinel.git
cd howlr-packet-sentinel
```

------------------------------------------------------------------------

# Windows Installation (Recommended)

## Create a Virtual Environment

``` powershell
python -m venv .venv
```

Activate it:

``` powershell
.\.venv\Scripts\activate
```

Upgrade pip:

``` powershell
python -m pip install --upgrade pip
```

Install dependencies:

``` powershell
python -m pip install -r requirements.txt
```

Verify Scapy:

``` powershell
python -c "import scapy; print(scapy.__version__)"
```

For live packet capture:

-   Install **Npcap**
-   Run PowerShell or PyCharm as **Administrator**

------------------------------------------------------------------------

# Kali Linux Installation

Create a virtual environment:

``` bash
python3 -m venv .venv
```

Activate it:

``` bash
source .venv/bin/activate
```

Upgrade pip:

``` bash
python3 -m pip install --upgrade pip
```

Install dependencies:

``` bash
python3 -m pip install -r requirements.txt
```

Verify installation:

``` bash
python3 -c "import scapy; print(scapy.__version__)"
```

For live capture:

``` bash
sudo python3 howlr_packet_sentinel.py
```

or configure Linux packet-capture capabilities as appropriate.

------------------------------------------------------------------------

# Install Scapy Without a Virtual Environment

Although using a virtual environment is recommended, Scapy can also be
installed globally.

Windows:

``` powershell
python -m pip install scapy
```

Linux:

``` bash
python3 -m pip install scapy
```

------------------------------------------------------------------------

# Why Use a Virtual Environment?

Each Python project should have its own isolated environment.

``` text
ASTP Python
└── .venv

Howlr Packet Sentinel
└── .venv

Another Project
└── .venv
```

Benefits include:

-   Prevents dependency conflicts
-   Easier upgrades
-   Cleaner development environment
-   Reproducible installations
-   Professional Python development practice

------------------------------------------------------------------------

# List Network Interfaces

Windows:

``` powershell
python howlr_packet_sentinel.py --list-interfaces
```

Linux:

``` bash
python3 howlr_packet_sentinel.py --list-interfaces
```

Typical Linux interfaces:

``` text
eth0
wlan0
lo
```

------------------------------------------------------------------------

# Basic Usage

## Capture 100 Packets

Windows:

``` powershell
python howlr_packet_sentinel.py -c 100
```

Linux:

``` bash
sudo python3 howlr_packet_sentinel.py -c 100
```

------------------------------------------------------------------------

## Capture for 60 Seconds

Windows:

``` powershell
python howlr_packet_sentinel.py -t 60
```

Linux:

``` bash
sudo python3 howlr_packet_sentinel.py -t 60
```

------------------------------------------------------------------------

## Stop a Capture

Press:

``` text
Ctrl + C
```

If running inside PyCharm, click the red **Stop** button.

------------------------------------------------------------------------

# Select a Network Interface

Windows:

``` powershell
python howlr_packet_sentinel.py -i "Wi-Fi" -c 100
```

Linux:

``` bash
sudo python3 howlr_packet_sentinel.py -i eth0 -c 100
```

Always run:

``` powershell
python howlr_packet_sentinel.py --list-interfaces
```

first to determine the correct interface name.

------------------------------------------------------------------------

# Local Network Direction Labels

Use:

``` text
--local-network
```

to classify packets as:

-   LAN
-   OUT
-   IN
-   TRANSIT

Example:

``` powershell
python howlr_packet_sentinel.py `
-c 100 `
-t 60 `
--local-network 10.1.102.0/24
```

Linux:

``` bash
sudo python3 howlr_packet_sentinel.py \
-c 100 \
-t 60 \
--local-network 192.168.0.0/24
```

Replace the CIDR with your local network.

------------------------------------------------------------------------

# Capture Filters

The `-f` or `--filter` option accepts Berkeley Packet Filter (BPF)
syntax.

## ARP or ICMP

``` powershell
python howlr_packet_sentinel.py -f "arp or icmp" -c 50
```

## DNS

``` powershell
python howlr_packet_sentinel.py -f "port 53" -c 50
```

## TCP

``` powershell
python howlr_packet_sentinel.py -f "tcp" -c 100
```

## UDP

``` powershell
python howlr_packet_sentinel.py -f "udp" -c 100
```

## HTTPS

``` powershell
python howlr_packet_sentinel.py -f "tcp port 443" -c 100
```

------------------------------------------------------------------------

# Save Captured Packets

``` powershell
python howlr_packet_sentinel.py `
-c 100 `
--pcap-out captures\capture.pcap
```

Supported analysis tools include:

-   Wireshark
-   Scapy
-   Zeek
-   Suricata

------------------------------------------------------------------------

# Save Structured JSONL Output

``` powershell
python howlr_packet_sentinel.py `
-c 100 `
--jsonl-out output\capture.jsonl
```

JSONL stores one JSON object per line.

Useful for:

-   Searching
-   Automation
-   Reporting
-   Importing into other tools

------------------------------------------------------------------------

# Save Both PCAP and JSONL

``` powershell
python howlr_packet_sentinel.py `
-c 100 `
-t 60 `
--local-network 10.1.102.0/24 `
--pcap-out captures\astp_capture.pcap `
--jsonl-out output\astp_capture.jsonl
```

------------------------------------------------------------------------

# Analyse an Existing PCAP

Windows:

``` powershell
python howlr_packet_sentinel.py -r evidence.pcap
```

Linux:

``` bash
python3 howlr_packet_sentinel.py -r evidence.pcap
```

Offline analysis generally does **not** require Administrator or root
privileges.

------------------------------------------------------------------------

# Quiet Mode

Display only the final summary:

``` powershell
python howlr_packet_sentinel.py -r evidence.pcap -q
```

------------------------------------------------------------------------

# Command Options

``` text
--list-interfaces
-i, --interface
-r, --read
-f, --filter
-c, --count
-t, --timeout
--local-network
--pcap-out
--jsonl-out
--scan-threshold
--scan-window
-q, --quiet
```

Display built-in help:

``` powershell
python howlr_packet_sentinel.py --help
```

------------------------------------------------------------------------

# Example Output

``` text
[2026-07-28T10:30:15.123+08:00]
#00001
OUT
IPv4 10.1.102.84 -> 8.8.8.8
ICMP type=8 code=0
```

TCP example:

``` text
IPv4 10.1.102.84 -> 172.64.155.209
TCP 56866 -> 443/HTTPS
flags=S
OBS=TCP_SYN
```

DNS example:

``` text
IPv4 10.1.102.84 -> 1.1.1.1
UDP 53024 -> 53/DNS
DNS query example.com
```

------------------------------------------------------------------------

# Capture Summary

The program displays:

-   Total packets analysed
-   Protocol counts
-   Top source IPs
-   Top destination ports
-   Observation counts

Example:

``` text
=== Capture Summary ===

Packets analysed: 2136

Protocols:
Ethernet=2136
IPv4=1844
TCP=1359

Top source:
10.1.102.84

Top destination port:
443/HTTPS

Observations:
TCP_SYN=21
```

Protocol counts overlap because a packet can contain multiple protocol
layers.

Example:

``` text
Ethernet
└── IPv4
    └── UDP
        └── DNS
```

------------------------------------------------------------------------

# Using PyCharm

PyCharm is the recommended IDE for developing and testing Howlr Packet
Sentinel.

## Open the Project

1.  Open PyCharm.
2.  Select **Open**.
3.  Choose the `howlr-packet-sentinel` project folder.

## Configure the Python Interpreter

If PyCharm reports **No Python interpreter configured**:

1.  Open **Settings → Project → Python Interpreter**.
2.  Create or select a virtual environment (`.venv`).
3.  Ensure the interpreter points to:

``` text
howlr-packet-sentinel/.venv/Scripts/python.exe
```

on Windows, or:

``` text
howlr-packet-sentinel/.venv/bin/python
```

on Linux.

## Important

Creating a virtual environment does **not** install the project's
dependencies.

After activating the environment, always install the required packages:

``` powershell
python -m pip install -r requirements.txt
```

Without this step you may encounter:

``` text
ModuleNotFoundError: No module named 'scapy'
```

Verify the installation:

``` powershell
python -c "import scapy; print(scapy.__version__)"
```

If a version number is displayed, Scapy has been installed successfully.

------------------------------------------------------------------------

# Troubleshooting

## ModuleNotFoundError: No module named 'scapy'

Cause:

-   Scapy has not been installed into the active Python environment.

Solution:

``` powershell
python -m pip install -r requirements.txt
```

or

``` powershell
python -m pip install scapy
```

Then verify:

``` powershell
python -c "import scapy; print(scapy.__version__)"
```

## Permission Denied During Live Capture

Live packet capture requires elevated privileges.

Windows:

-   Run PowerShell or PyCharm as **Administrator**.
-   Ensure Npcap is installed.

Linux:

``` bash
sudo python3 howlr_packet_sentinel.py
```

## No Interfaces Found

Run:

``` powershell
python howlr_packet_sentinel.py --list-interfaces
```

Confirm:

-   Your network adapter is enabled.
-   Npcap is installed (Windows).
-   The correct interface name is being used.

------------------------------------------------------------------------

# Current Limitations

This tool does **not**:

-   Decrypt HTTPS
-   Identify Windows processes
-   Reassemble complete TCP streams
-   Extract transferred files
-   Detect malware conclusively
-   Replace Wireshark, Zeek, Suricata or an EDR
-   Display every packet on a switched network
-   Inject, replay or modify packets

Its primary purpose is packet triage and networking education.

------------------------------------------------------------------------

# Recommended Learning Workflow

1.  Capture a small number of packets.
2.  Read the packet summaries.
3.  Identify the protocol layers.
4.  Observe the source and destination addresses.
5.  Examine ports and TCP flags.
6.  Save the capture as a PCAP.
7.  Open the same PCAP in Wireshark.
8.  Compare the outputs.
9.  Investigate any interesting observations.

------------------------------------------------------------------------

# Roadmap

## Version 0.1.0

-   Live capture
-   Offline PCAP analysis
-   DNS support
-   DHCP support
-   JSONL export
-   PCAP export

## Planned

-   HTTP parsing
-   TLS SNI extraction
-   ARP spoof detection
-   Port scan heuristics
-   CSV export
-   HTML reports
-   Configuration file support

------------------------------------------------------------------------

# Authorised Use

Capture only interfaces, systems and networks that you own or are
explicitly authorised to monitor.

Packet captures may contain sensitive information. Store them securely
and comply with applicable laws, organisational policies and rules of
engagement.
