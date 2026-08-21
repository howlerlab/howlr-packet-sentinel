# Howlr Packet Sentinel — Installation Guide

This guide covers installation and initial setup for **Howlr Packet Sentinel v0.2.0** on Windows and Kali/Debian-based Linux.

If Howlr is already installed and you want command examples, go to **[USAGE.md](USAGE.md)**.

---

# Installation Overview

The normal setup path is:

```text
Install Python
      ↓
Install Git
      ↓
Clone the repository
      ↓
Create .venv
      ↓
Install requirements
      ↓
Install Npcap on Windows
      ↓
Verify version/help
      ↓
List interfaces
      ↓
Run first capture
```

Howlr v0.2.0 runs from:

```text
howlr_packet_sentinel.py
```

It is not yet packaged as a system-wide `howlr` executable.

---

# Requirements

## Core Requirements

- Python 3
- Scapy
- Git if cloning the repository
- permission to monitor the target interface

## Windows

For live capture:

- Npcap

## Kali / Debian Linux

Recommended packages:

- `python3`
- `python3-venv`
- `python3-pip`
- `git`
- `tcpdump`
- `libpcap-dev`

---

# Windows Installation

The commands below are written for PowerShell.

## Step 1 — Check Python

```powershell
python --version
```

You should see Python 3.

Also verify pip:

```powershell
python -m pip --version
```

If `python` is not recognised, install Python 3 and ensure it is available in PATH.

---

## Step 2 — Check Git

```powershell
git --version
```

If Git is not recognised, install Git for Windows and reopen PowerShell.

---

## Step 3 — Clone Howlr

```powershell
git clone https://github.com/howlerlab/howlr-packet-sentinel.git
```

Enter the project:

```powershell
cd .\howlr-packet-sentinel
```

Check files:

```powershell
Get-ChildItem
```

You should see files such as:

```text
howlr_packet_sentinel.py
requirements.txt
README.md
INSTALL.md
USAGE.md
CHANGELOG.md
LICENSE
```

---

## Step 4 — Create a Virtual Environment

```powershell
python -m venv .venv
```

The project now contains:

```text
howlr-packet-sentinel/
├── .venv/
├── howlr_packet_sentinel.py
└── ...
```

Using a virtual environment keeps Howlr's Python dependencies separate from other Python projects.

---

## Step 5 — Activate `.venv`

```powershell
.\.venv\Scripts\Activate.ps1
```

The prompt normally changes to:

```text
(.venv) PS C:\...\howlr-packet-sentinel>
```

### If PowerShell Blocks Activation

For the current PowerShell process only:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

Then retry:

```powershell
.\.venv\Scripts\Activate.ps1
```

Alternatively, skip activation and call the environment's Python directly:

```powershell
.\.venv\Scripts\python.exe .\howlr_packet_sentinel.py --version
```

---

## Step 6 — Install Requirements

With `.venv` active:

```powershell
python -m pip install -r requirements.txt
```

Verify Scapy:

```powershell
python -c "import scapy; print(scapy.__version__)"
```

If it prints a version without a traceback, Scapy is available in the active environment.

---

# Npcap on Windows

Windows live capture requires **Npcap**.

Npcap supplies packet-capture support used by Scapy and tools such as Wireshark.

During installation, the compatibility option commonly labelled:

```text
Install Npcap in WinPcap API-compatible Mode
```

is generally useful.

After installing Npcap:

1. close the current terminal;
2. open PowerShell again;
3. activate `.venv` if desired;
4. list interfaces.

```powershell
python .\howlr_packet_sentinel.py --list-interfaces
```

If interfaces are displayed, continue to the first-capture test.

---

# Windows Without Activating `.venv`

Activation is optional.

Version:

```powershell
.\.venv\Scripts\python.exe .\howlr_packet_sentinel.py --version
```

Help:

```powershell
.\.venv\Scripts\python.exe .\howlr_packet_sentinel.py --help
```

Interfaces:

```powershell
.\.venv\Scripts\python.exe .\howlr_packet_sentinel.py --list-interfaces
```

Capture:

```powershell
.\.venv\Scripts\python.exe .\howlr_packet_sentinel.py -i "<INTERFACE>" -c 20
```

---

# Windows First-Capture Test

## 1. List Interfaces

```powershell
python .\howlr_packet_sentinel.py --list-interfaces
```

Possible interface:

```text
Realtek PCIe GbE Family Controller
```

## 2. Capture 20 Packets

```powershell
python .\howlr_packet_sentinel.py -i "Realtek PCIe GbE Family Controller" -c 20
```

If no traffic appears, generate normal network activity such as:

```powershell
ping 1.1.1.1
```

or:

```powershell
curl http://example.com -UseBasicParsing
```

If live capture fails, see **[docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md)**.

---

# Kali / Debian Linux Installation

## Step 1 — Update Package Information

```bash
sudo apt update
```

## Step 2 — Install Packages

```bash
sudo apt install -y python3 python3-venv python3-pip git tcpdump libpcap-dev
```

Verify:

```bash
python3 --version
git --version
```

---

## Step 3 — Clone the Repository

```bash
git clone https://github.com/howlerlab/howlr-packet-sentinel.git
```

Enter it:

```bash
cd howlr-packet-sentinel
```

---

## Step 4 — Create `.venv`

```bash
python3 -m venv .venv
```

---

## Step 5 — Install Requirements

```bash
.venv/bin/pip install -r requirements.txt
```

Verify Scapy:

```bash
.venv/bin/python -c "import scapy; print(scapy.__version__)"
```

---

# Optional Linux `.venv` Activation

Activate:

```bash
source .venv/bin/activate
```

Deactivate later:

```bash
deactivate
```

Activation is optional. Direct execution is often clearer:

```bash
sudo .venv/bin/python howlr_packet_sentinel.py -i eth0 -c 20
```

---

# Linux Capture Privileges

Live packet capture generally requires elevated privileges:

```bash
sudo .venv/bin/python howlr_packet_sentinel.py -i eth0 -c 20
```

Offline analysis usually does not:

```bash
.venv/bin/python howlr_packet_sentinel.py -r capture.pcap
```

---

# Linux First-Capture Test

## 1. List Interfaces

```bash
.venv/bin/python howlr_packet_sentinel.py --list-interfaces
```

## 2. Inspect Addresses

```bash
ip -br addr
```

Example:

```text
eth0    UP    192.168.42.130/24
```

## 3. Capture 20 Packets

```bash
sudo .venv/bin/python howlr_packet_sentinel.py -i eth0 -c 20
```

Generate traffic in another terminal:

```bash
ping -c 4 1.1.1.1
```

---

# Interface Discovery

Always identify the interface before live capture.

## Windows

```powershell
python .\howlr_packet_sentinel.py --list-interfaces
```

## Linux

```bash
.venv/bin/python howlr_packet_sentinel.py --list-interfaces
```

Possible names:

```text
Wi-Fi
Ethernet
Realtek PCIe GbE Family Controller
eth0
wlan0
ens33
```

Use the exact interface name.

---

# Numeric Interface Index Limitation

v0.2.0 may display an interface index, but `-i` expects the interface name.

If you see:

```text
Index: 12
Name: Realtek PCIe GbE Family Controller
```

Use:

```powershell
python .\howlr_packet_sentinel.py -i "Realtek PCIe GbE Family Controller" -c 20
```

Do not use:

```powershell
python .\howlr_packet_sentinel.py -i 12 -c 20
```

---

# Finding Your Local Network

`--local-network` lets Howlr classify traffic direction.

You should use the network associated with the interface being captured.

## Windows

Run:

```powershell
ipconfig
```

Example:

```text
IPv4 Address. . . . . . . . . . . : 192.168.1.50
Subnet Mask . . . . . . . . . . . : 255.255.255.0
```

This normally corresponds to:

```text
192.168.1.0/24
```

Use:

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" --local-network 192.168.1.0/24 -c 50
```

You can also inspect addresses and routes:

```powershell
Get-NetIPAddress -AddressFamily IPv4
```

```powershell
Get-NetRoute -AddressFamily IPv4
```

---

## Linux

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

Confirm:

```bash
ip route
```

---

# CIDR Basics

Example:

```text
192.168.1.0/24
```

Common masks:

```text
/24 = 255.255.255.0
/16 = 255.255.0.0
/8  = 255.0.0.0
```

Do not copy the documentation subnet blindly. Use the subnet belonging to your actual interface.

---

# Multiple Interfaces

A system may contain:

```text
Ethernet
Wi-Fi
VMware adapters
VirtualBox adapters
Hyper-V adapters
Tailscale
VPN adapters
Docker bridges
Loopback
```

If traffic does not appear:

1. list interfaces;
2. inspect IP addresses;
3. inspect routes;
4. determine which interface carries the destination route;
5. capture that interface.

---

# VPN and Tailscale

VPNs and overlay networks can change routing and source addresses.

If expected traffic is missing from the physical NIC:

```text
1. inspect routes
2. check the chosen source IP
3. identify the virtual adapter
4. capture the interface actually carrying the traffic
```

Windows:

```powershell
Get-NetRoute -AddressFamily IPv4
```

Linux:

```bash
ip route
```

---

# VMware / VirtualBox / Hyper-V

VM networking modes such as NAT, bridged and host-only determine where traffic is visible.

Inside a Kali VM, the correct capture interface may simply be:

```text
eth0
```

even if the Windows host uses Wi-Fi or Ethernet.

Check inside the VM:

```bash
ip -br addr
ip route
```

---

# Installation Verification Checklist

## Windows

```powershell
python .\howlr_packet_sentinel.py --version
python .\howlr_packet_sentinel.py --help
python .\howlr_packet_sentinel.py --list-interfaces
python .\howlr_packet_sentinel.py -i "<INTERFACE>" -c 10
```

## Kali / Linux

```bash
.venv/bin/python howlr_packet_sentinel.py --version
.venv/bin/python howlr_packet_sentinel.py --help
.venv/bin/python howlr_packet_sentinel.py --list-interfaces
sudo .venv/bin/python howlr_packet_sentinel.py -i eth0 -c 10
```

The installation is ready if:

- version prints `0.2.0`;
- help prints the CLI;
- interfaces are listed;
- packets are processed;
- a summary appears without a Python traceback.

---

# Updating Howlr

Check repository state:

```bash
git status
```

For stable use, check branch:

```bash
git branch
```

Use `main` for the stable release.

If clean:

```bash
git pull origin main
```

If requirements changed:

### Windows

```powershell
python -m pip install -r requirements.txt
```

### Linux

```bash
.venv/bin/pip install -r requirements.txt
```

---

# Rebuilding `.venv`

The virtual environment can be deleted and recreated without deleting the project.

## Windows

Deactivate if active:

```powershell
deactivate
```

Remove:

```powershell
Remove-Item .\.venv -Recurse -Force
```

Recreate:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

## Linux

```bash
rm -rf .venv
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

---

# Common Setup Errors

## `ModuleNotFoundError: scapy`

Install into the Python environment actually running Howlr.

Windows:

```powershell
python -m pip install -r requirements.txt
```

Linux:

```bash
.venv/bin/pip install -r requirements.txt
```

## Help Works but Windows Capture Does Not

Check:

- Npcap
- interface name
- active adapter
- privileges

## Linux Help Works but Capture Fails

Use:

```bash
sudo .venv/bin/python howlr_packet_sentinel.py -i eth0 -c 20
```

---

# Next Steps

After installation:

1. read **[USAGE.md](USAGE.md)**;
2. run a short normal capture;
3. add `--local-network`;
4. try Hunt Mode;
5. create a session;
6. replay the saved PCAP;
7. read **[docs/OBSERVATIONS.md](docs/OBSERVATIONS.md)**.

Recommended first Windows command:

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" --local-network 192.168.1.0/24 -c 50
```

Recommended first Kali command:

```bash
sudo .venv/bin/python howlr_packet_sentinel.py -i eth0 --local-network 192.168.1.0/24 -c 50
```

> Use Howlr only on systems and networks you own or are explicitly authorised to monitor.
