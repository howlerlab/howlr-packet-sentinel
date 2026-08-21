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

## Main Features

Howlr Packet Sentinel v0.2.0 includes:

- live packet capture
- offline PCAP and PCAPNG analysis
- Ethernet, ARP, IPv4, IPv6, TCP, UDP, ICMP and ICMPv6 summaries
- DNS and DHCP metadata summaries
- common service-name labels
- readable TCP flags and TCP event classification
- network direction labels: `LAN`, `IN`, `OUT`, `TRANSIT`, `MULTICAST`, `BROADCAST`
- packet severity labels: `NORMAL`, `INFO`, `NOTICE`, `WARNING`
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

## Requirements

- Python 3.13 or newer
- Scapy
- Git, if cloning from GitHub
- Npcap on Windows for live capture
- Administrator privileges on Windows for live capture
- root or suitable packet-capture permissions on Linux

Current Python dependency:

```text
scapy>=2.7.0
```

---

## Clone the Repository

```bash
git clone https://github.com/howlerlab/howlr-packet-sentinel.git
cd howlr-packet-sentinel
```

If testing the development branch:

```bash
git switch develop-v0.2
```

---

## Windows Installation

Create a virtual environment:

```powershell
python -m venv .venv
```

Creating `.venv` does **not** install Scapy. It only creates an isolated Python environment.

Activate it:

```powershell
.\.venv\Scripts\Activate.ps1
```

If PowerShell blocks activation:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

Or run the virtual-environment Python directly:

```powershell
.\.venv\Scripts\python.exe .\howlr_packet_sentinel.py --help
```

Upgrade pip:

```powershell
python -m pip install --upgrade pip
```

Install dependencies:

```powershell
python -m pip install -r requirements.txt
```

Verify Scapy:

```powershell
python -c "import scapy; print(scapy.__version__)"
```

Verify Sentinel:

```powershell
python .\howlr_packet_sentinel.py --version
```

Expected:

```text
howlr_packet_sentinel.py 0.2.0
```

For live capture, install Npcap and run PowerShell or PyCharm as Administrator.

---

## Kali Linux Installation

Create a virtual environment:

```bash
python3 -m venv .venv
```

Activate it:

```bash
source .venv/bin/activate
```

Upgrade pip:

```bash
python3 -m pip install --upgrade pip
```

Install dependencies:

```bash
python3 -m pip install -r requirements.txt
```

Verify:

```bash
python3 -c "import scapy; print(scapy.__version__)"
python3 howlr_packet_sentinel.py --version
```

For live capture with the virtual environment:

```bash
sudo .venv/bin/python howlr_packet_sentinel.py -c 20
```

Offline PCAP analysis normally does not require root privileges.

---

## Using PyCharm

1. Open the entire `howlr-packet-sentinel` folder.
2. Select or create the `.venv` interpreter.
3. Open the PyCharm terminal.
4. Install dependencies:

```powershell
python -m pip install -r requirements.txt
```

5. Verify:

```powershell
python -c "import scapy; print(scapy.__version__)"
```

If PyCharm reports:

```text
ModuleNotFoundError: No module named 'scapy'
```

Scapy is not installed in the interpreter currently selected by PyCharm.

---

## Basic Usage

Show version:

```powershell
python .\howlr_packet_sentinel.py --version
```

Show help:

```powershell
python .\howlr_packet_sentinel.py --help
```

List interfaces:

```powershell
python .\howlr_packet_sentinel.py --list-interfaces
```

Capture 100 packets:

```powershell
python .\howlr_packet_sentinel.py -i "Wi-Fi" -c 100
```

Capture for 60 seconds:

```powershell
python .\howlr_packet_sentinel.py -i "Wi-Fi" -t 60
```

Press `Ctrl+C` to stop early.

---

## Network Direction Labels

Use `--local-network` to define local CIDRs.

```powershell
python .\howlr_packet_sentinel.py `
  -i "Wi-Fi" `
  --local-network 10.1.102.0/24 `
  -c 100
```

| Label | Meaning |
|---|---|
| `LAN` | Source and destination are inside a supplied local network |
| `OUT` | Local source to non-local destination |
| `IN` | Non-local source to local destination |
| `TRANSIT` | Neither endpoint is inside the supplied local network |
| `MULTICAST` | Destination is an IP multicast address |
| `BROADCAST` | Destination is the limited IPv4 broadcast address |

Multiple local networks may be supplied.

---

## Capture Filters

The `-f` or `--filter` option accepts BPF syntax.

```powershell
python .\howlr_packet_sentinel.py -i "Wi-Fi" -f "icmp" -c 20
python .\howlr_packet_sentinel.py -i "Wi-Fi" -f "port 53" -c 50
python .\howlr_packet_sentinel.py -i "Wi-Fi" -f "tcp" -c 100
python .\howlr_packet_sentinel.py -i "Wi-Fi" -f "udp" -c 100
python .\howlr_packet_sentinel.py -i "Wi-Fi" -f "tcp port 443" -c 100
```

---

## Session Mode

`--session` automatically creates timestamped PCAP, JSONL and CSV files.

```powershell
python .\howlr_packet_sentinel.py `
  -i "Wi-Fi" `
  --local-network 10.1.102.0/24 `
  --session ares-test `
  -c 50
```

Example:

```text
captures/
└── ares-test_20260821_171350.pcap

output/
├── ares-test_20260821_171350.jsonl
└── ares-test_20260821_171350.csv
```

The directories are created automatically and are excluded from Git.

---

## Manual Export

PCAP:

```powershell
python .\howlr_packet_sentinel.py -i "Wi-Fi" -c 100 --pcap-out captures\capture.pcap
```

JSONL:

```powershell
python .\howlr_packet_sentinel.py -i "Wi-Fi" -c 100 --jsonl-out output\capture.jsonl
```

CSV:

```powershell
python .\howlr_packet_sentinel.py -i "Wi-Fi" -c 100 --csv-out output\capture.csv
```

JSONL preserves richer structured metadata. CSV is convenient for tabular analysis. PCAP preserves packet evidence for Wireshark and similar tools.

---

## Offline PCAP Analysis

```powershell
python .\howlr_packet_sentinel.py `
  -r .\captures\capture.pcap `
  --local-network 10.1.102.0/24
```

Quiet summary mode:

```powershell
python .\howlr_packet_sentinel.py `
  -r .\captures\capture.pcap `
  --local-network 10.1.102.0/24 `
  -q
```

---

## Hunt Mode

Hunt mode analyses every packet but prints only packets containing triage observations.

```powershell
python .\howlr_packet_sentinel.py `
  -i "Wi-Fi" `
  --local-network 10.1.102.0/24 `
  --hunt
```

Use this as a first-look triage mode, not as a replacement for an IDS, EDR, Wireshark, Zeek or Suricata.

---

## Scan Heuristic

Defaults:

```text
--scan-threshold 20
--scan-window 10
```

Possible classifications:

- `POSSIBLE_PORT_SCAN`
- `POSSIBLE_HOST_SCAN`
- `POSSIBLE_SYN_SCAN`

These are heuristics and may have legitimate causes.

---

## ARP Monitoring

Sentinel tracks observed sender IP-to-MAC mappings during a capture.

A changed mapping may produce:

```text
ARP_MAC_CHANGE
```

A mapping change is not automatically an ARP-spoofing attack.

---

## Cleartext HTTP Metadata

For supported unencrypted HTTP traffic on ports 80 or 8080, Sentinel can extract:

- method
- host
- URI

It does **not** decrypt HTTPS.

---

## Capture Summary

The v0.2 summary can include:

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

Protocol counts overlap because one packet may contain several layers.

---

## Command Options

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

For the authoritative current list:

```powershell
python .\howlr_packet_sentinel.py --help
```

---

## Validated v0.2.0 Functionality

The development build has been manually validated for:

- startup and `--version`
- CLI help
- interface enumeration
- Windows live capture
- IPv4 and IPv6 parsing
- TCP and UDP parsing
- ARP parsing
- DNS parsing
- service-name labelling
- TCP event labelling
- `LAN`, `IN`, `OUT` and `MULTICAST` direction classification
- enhanced statistics
- automatic `--session` output
- PCAP export
- JSONL export
- CSV export
- offline PCAP re-analysis
- quiet summary mode

The remaining triage heuristics should still be treated as development features until deliberately exercised and validated.

---

## Current Limitations

Howlr Packet Sentinel does not:

- decrypt HTTPS
- identify the operating-system process responsible for every connection
- reassemble complete TCP streams
- extract transferred files
- conclusively detect malware
- replace Wireshark, Zeek, Suricata, NDR or EDR tooling
- display every packet from every device on a switched or managed network
- guarantee that every heuristic observation is malicious
- transmit, modify, replay or inject packets

Its purpose is lightweight packet visibility, networking education and first-look triage.

---

## Troubleshooting

### `ModuleNotFoundError: No module named 'scapy'`

```powershell
python -m pip install -r requirements.txt
```

### PowerShell cannot activate `.venv`

Either:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

or:

```powershell
.\.venv\Scripts\python.exe .\howlr_packet_sentinel.py --help
```

### Permission denied during live capture

Windows:

- install Npcap
- run PowerShell or PyCharm as Administrator

Linux:

- use root or suitable packet-capture permissions

### No interfaces found

```powershell
python .\howlr_packet_sentinel.py --list-interfaces
```

---

## Licence

This project is licensed under the MIT License.

See the `LICENSE` file for details.

---

## Authorised Use

Capture only interfaces, systems and networks that you own or are explicitly authorised to monitor.

Packet captures may contain sensitive information. Store them securely and follow applicable laws, organisational policies and rules of engagement.
