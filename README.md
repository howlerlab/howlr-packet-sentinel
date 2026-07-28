# Howlr Packet Sentinel
**Author:** howlerlab

A passive packet-capture and network-triage tool built with Scapy.

It is intended for:

- networking study
- SOC packet triage
- incident-response first look
- authorised penetration-testing observation
- offline PCAP analysis

> Use this tool only on systems and networks you own or are authorised to monitor.

---

## Project Files

```text
howlr-packet-sentinel/
├── howlr_packet_sentinel.py
├── requirements.txt
└── README.md
```

- `howlr_packet_sentinel.py` — the main program
- `requirements.txt` — required Python package
- `README.md` — setup and usage instructions

---

## Main Features

- Live packet capture
- Offline PCAP and PCAPNG analysis
- Ethernet, ARP, IPv4 and IPv6 support
- TCP, UDP, ICMP and ICMPv6 summaries
- DNS and DHCP summaries
- TCP flag display
- Common service-name labels
- Incoming, outgoing and LAN direction labels
- PCAP output
- JSONL output
- Protocol and endpoint statistics
- Basic SOC triage observations

Possible observations include:

- TCP SYN activity
- possible SYN scanning
- NULL scan patterns
- XMAS scan patterns
- IP fragmentation
- ARP replies
- DNS errors
- cleartext service ports

These are investigation hints, not proof of malicious activity.

---

## Requirements

- Python 3
- Scapy
- Npcap on Windows for live capture
- Administrator or root privileges for live capture

---

## Installation

### Windows

Open PowerShell or Command Prompt in the project folder:

```powershell
python -m pip install -r requirements.txt
```

For live capture, run PowerShell or PyCharm as Administrator.

### Kali Linux

Create a virtual environment:

```bash
python3 -m venv .venv
```

Activate it:

```bash
source .venv/bin/activate
```

Install the requirement:

```bash
python3 -m pip install -r requirements.txt
```

For live capture, use `sudo` or appropriate packet-capture permissions.

---

## List Network Interfaces

### Windows

```powershell
python howlr_packet_sentinel.py --list-interfaces
```

### Kali Linux

```bash
python3 howlr_packet_sentinel.py --list-interfaces
```

Typical Kali interfaces may include:

```text
eth0
wlan0
lo
```

---

## Basic Usage

### Capture 100 Packets

Windows:

```powershell
python howlr_packet_sentinel.py -c 100
```

Kali:

```bash
sudo python3 howlr_packet_sentinel.py -c 100
```

### Capture for 60 Seconds

Windows:

```powershell
python howlr_packet_sentinel.py -t 60
```

Kali:

```bash
sudo python3 howlr_packet_sentinel.py -t 60
```

### Stop a Capture

Press:

```text
Ctrl + C
```

In PyCharm, you may also click the red Stop button.

---

## Select an Interface

Windows:

```powershell
python howlr_packet_sentinel.py -i "Wi-Fi" -c 100
```

Kali:

```bash
sudo python3 howlr_packet_sentinel.py -i eth0 -c 100
```

Use `--list-interfaces` first to find the correct name.

---

## Local-Network Direction Labels

Use `--local-network` to classify packets as:

- `LAN` — local to local
- `OUT` — local to external
- `IN` — external to local
- `TRANSIT` — neither endpoint belongs to the supplied local network

Example for the ASTP network:

```powershell
python howlr_packet_sentinel.py `
  -c 100 `
  -t 60 `
  --local-network 10.1.102.0/24
```

Kali example:

```bash
sudo python3 howlr_packet_sentinel.py \
  -c 100 \
  -t 60 \
  --local-network 192.168.0.0/24
```

Replace the network with the actual CIDR used by the machine.

---

## Capture Filters

The `-f` or `--filter` option accepts a BPF capture filter.

### ARP or ICMP

```powershell
python howlr_packet_sentinel.py -f "arp or icmp" -c 50
```

### DNS

```powershell
python howlr_packet_sentinel.py -f "port 53" -c 50
```

### TCP

```powershell
python howlr_packet_sentinel.py -f "tcp" -c 100
```

### UDP

```powershell
python howlr_packet_sentinel.py -f "udp" -c 100
```

### HTTPS

```powershell
python howlr_packet_sentinel.py -f "tcp port 443" -c 100
```

---

## Save Captured Packets

Save packets to a PCAP file:

```powershell
python howlr_packet_sentinel.py `
  -c 100 `
  --pcap-out captures\capture.pcap
```

The PCAP can later be opened in:

- Wireshark
- Scapy
- Zeek
- Suricata
- other packet-analysis tools

---

## Save Structured JSONL Output

```powershell
python howlr_packet_sentinel.py `
  -c 100 `
  --jsonl-out captures\capture.jsonl
```

JSONL stores one JSON record per line.

This is useful for:

- searching
- scripting
- importing into other tools
- preserving packet metadata
- creating later reports

---

## Save Both PCAP and JSONL

```powershell
python howlr_packet_sentinel.py `
  -c 100 `
  -t 60 `
  --local-network 10.1.102.0/24 `
  --pcap-out captures\astp_capture.pcap `
  --jsonl-out captures\astp_capture.jsonl
```

---

## Analyse an Existing PCAP

Windows:

```powershell
python howlr_packet_sentinel.py -r evidence.pcap
```

Kali:

```bash
python3 howlr_packet_sentinel.py -r evidence.pcap
```

Offline analysis usually does not require Administrator or root privileges.

---

## Quiet Mode

Use quiet mode to suppress individual packet lines and display only the final summary:

```powershell
python howlr_packet_sentinel.py -r evidence.pcap -q
```

---

## Command Options

```text
--list-interfaces
    List available Scapy interfaces and exit.

-i, --interface
    Select the live-capture interface.

-r, --read
    Read an existing PCAP or PCAPNG file.

-f, --filter
    Apply a BPF capture filter.

-c, --count
    Stop after a specified number of packets.
    Zero means unlimited.

-t, --timeout
    Stop after a specified number of seconds.

--local-network
    Define a local CIDR for direction labels.
    This option may be repeated.

--pcap-out
    Save processed packets to a PCAP file.

--jsonl-out
    Save structured packet records to JSONL.

--scan-threshold
    Set the number of unique SYN targets needed
    for a possible scan observation.

--scan-window
    Set the time window used by the SYN-scan heuristic.

-q, --quiet
    Suppress individual packet output.
```

Display the built-in help:

```powershell
python howlr_packet_sentinel.py --help
```

---

## Example Packet Output

```text
[2026-07-28T10:30:15.123+08:00] |
#00001 |
len=74 |
OUT |
MAC e4:1f:d5:27:bb:54 -> ae:8b:a9:10:c1:52 |
IPv4 10.1.102.84 -> 8.8.8.8 |
ICMP type=8 code=0
```

TCP example:

```text
IPv4 10.1.102.84 -> 172.64.155.209 |
TCP 56866 -> 443/HTTPS flags=S |
OBS=TCP_SYN
```

DNS example:

```text
IPv4 10.1.102.84 -> 1.1.1.1 |
UDP 53024 -> 53/DNS |
DNS query example.com
```

---

## Capture Summary

At the end of a run, the script displays:

- total packets analysed
- protocol counts
- top source IP addresses
- top destination ports
- observation counts

Example:

```text
=== Capture Summary ===
Packets analysed: 2136
Protocols: Ethernet=2136, IPv4=1844, TCP=1359
Top source IPs:
  10.1.102.84  805
Top destination ports:
  443/HTTPS    727
Observations:
  TCP_SYN      21
```

Protocol counts overlap because one packet can contain several layers.

For example:

```text
Ethernet
└── IPv4
    └── UDP
        └── DNS
```

That one packet is counted under Ethernet, IPv4, UDP and DNS.

---

## Important Limitations

This tool does not:

- decrypt HTTPS
- identify the Windows process responsible for each connection
- reassemble complete TCP conversations
- extract or analyse transferred files
- detect malware conclusively
- replace Wireshark, Zeek, Suricata or an EDR
- display every packet from every device on a switched network
- transmit, modify, replay or inject packets

Its purpose is first-look packet triage and networking study.

---

## Recommended Learning Workflow

1. Capture a small number of packets.
2. Read the one-line summaries.
3. Identify the protocol layers.
4. Note source and destination addresses.
5. Note ports and TCP flags.
6. Save the traffic as PCAP.
7. Open the same PCAP in Wireshark.
8. Compare the script output with Wireshark.
9. Investigate only after confirming the surrounding context.

---

## Authorised Use

Capture only interfaces, systems and networks that you own or are explicitly authorised to monitor.

Packet captures can contain sensitive metadata and communications. Store evidence securely and follow the applicable policies, laws and rules of engagement.
