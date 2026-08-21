# Howlr Packet Sentinel — Troubleshooting Guide

This guide covers common **Howlr Packet Sentinel v0.2.0** installation, capture, interface, routing, filtering and output problems.

Start with the simplest checks first. Avoid changing several things at once.

---

# Quick Diagnostic Checklist

Before deeper troubleshooting, confirm the basics.

## Windows

```powershell
python .\howlr_packet_sentinel.py --version
python .\howlr_packet_sentinel.py --help
python .\howlr_packet_sentinel.py --list-interfaces
```

## Kali / Linux

```bash
.venv/bin/python howlr_packet_sentinel.py --version
.venv/bin/python howlr_packet_sentinel.py --help
.venv/bin/python howlr_packet_sentinel.py --list-interfaces
```

If these commands fail, solve the Python/environment problem before debugging packet capture.

---

# Problem: `python` Is Not Recognised

Windows:

```powershell
python --version
```

If PowerShell cannot find Python:

- confirm Python is installed
- ensure Python is in PATH
- reopen PowerShell after installation

Check command resolution:

```powershell
Get-Command python
```

---

# Problem: `python3` Is Not Found

Linux:

```bash
python3 --version
```

Install if required:

```bash
sudo apt update
sudo apt install -y python3
```

---

# Problem: Scapy Is Missing

Typical error:

```text
ModuleNotFoundError: No module named 'scapy'
```

## Windows

With `.venv` active:

```powershell
python -m pip install -r requirements.txt
```

Verify:

```powershell
python -c "import scapy; print(scapy.__version__)"
```

Without activation:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

## Linux

```bash
.venv/bin/pip install -r requirements.txt
```

Verify:

```bash
.venv/bin/python -c "import scapy; print(scapy.__version__)"
```

---

# Problem: PowerShell Will Not Activate `.venv`

If PowerShell says script execution is disabled, allow it for the current process:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

Then:

```powershell
.\.venv\Scripts\Activate.ps1
```

Or skip activation:

```powershell
.\.venv\Scripts\python.exe .\howlr_packet_sentinel.py --help
```

---

# Problem: Interface Not Found

Possible error:

```text
Interface '12' not found
```

Run:

```powershell
python .\howlr_packet_sentinel.py --list-interfaces
```

Use the exact interface **name**.

Correct:

```powershell
python .\howlr_packet_sentinel.py -i "Realtek PCIe GbE Family Controller" -c 20
```

Incorrect in v0.2.0:

```powershell
python .\howlr_packet_sentinel.py -i 12 -c 20
```

The numeric index is informational in v0.2.0.

---

# Problem: Wrong Interface Selected

Symptoms:

- zero packets
- only irrelevant packets
- no browser traffic
- expected LAN traffic is absent

A machine may have:

```text
Ethernet
Wi-Fi
Tailscale
VPN
VMware
VirtualBox
Hyper-V
Docker
Loopback
```

Check interfaces:

```powershell
python .\howlr_packet_sentinel.py --list-interfaces
```

Check addressing:

```powershell
ipconfig
```

or:

```powershell
Get-NetIPAddress
```

Linux:

```bash
ip -br addr
```

Then inspect routes.

Windows:

```powershell
Get-NetRoute -AddressFamily IPv4
```

Linux:

```bash
ip route
```

Capture the interface that actually carries the traffic you want.

---

# Problem: No Packets Captured

Remove filters first.

Windows:

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" -c 20
```

Linux:

```bash
sudo .venv/bin/python howlr_packet_sentinel.py -i eth0 -c 20
```

Generate traffic while it runs.

Windows:

```powershell
ping 1.1.1.1
```

or:

```powershell
curl http://example.com -UseBasicParsing
```

Linux:

```bash
ping -c 4 1.1.1.1
```

or:

```bash
curl http://example.com
```

If packets appear now, the earlier issue was likely the filter or interface choice.

---

# Problem: Windows Help Works but Live Capture Does Not

Howlr's Python CLI can work without Npcap, but live Windows capture requires packet-capture support.

Check:

```text
Npcap installed?
Correct interface?
Interface active?
PowerShell has sufficient privileges?
```

Try opening PowerShell as Administrator for troubleshooting.

Then:

```powershell
python .\howlr_packet_sentinel.py --list-interfaces
```

and:

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" -c 20
```

---

# Problem: Linux Permission Error

Help/offline parsing may work while live capture fails.

Use:

```bash
sudo .venv/bin/python howlr_packet_sentinel.py -i eth0 -c 20
```

If capture packages are missing:

```bash
sudo apt install -y tcpdump libpcap-dev
```

---

# Problem: BPF Filter Captures Nothing

Example:

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" -f "tcp port 80" -t 30
```

If all browser traffic is HTTPS, there may be no port-80 traffic.

Test without filter:

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" -t 30
```

Then broaden:

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" -f "tcp" -t 30
```

Generate traffic matching the filter.

HTTP:

```powershell
curl http://example.com -UseBasicParsing
```

---

# Problem: BPF Syntax Error

Start with simple known filters:

```text
tcp
udp
icmp
port 53
tcp port 80
host 192.168.1.50
```

Only combine filters after simple filtering works.

Example:

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" -f "host 192.168.1.50 and tcp port 443" -t 60
```

---

# Problem: Hunt Mode Prints Nothing

This can be normal.

Hunt Mode:

```text
captures packets
analyses packets
updates statistics
prints only packets with observations
```

A quiet console can simply mean no observation rule matched.

Check the final summary.

For a controlled HTTP test:

Terminal 1:

```bash
sudo .venv/bin/python howlr_packet_sentinel.py -i eth0 --local-network 192.168.1.0/24 --hunt -t 30
```

Terminal 2:

```bash
curl http://example.com
```

Possible observations:

```text
CLEARTEXT_SERVICE:HTTP
CLEARTEXT_HTTP
```

---

# Problem: Cleartext HTTP Is Not Detected

Check:

1. the request is actually HTTP, not HTTPS;
2. the correct interface is captured;
3. traffic uses port 80 or supported HTTP-alt logic;
4. Hunt Mode is not ending before traffic is generated.

Generate:

```bash
curl http://example.com
```

Howlr does not decrypt HTTPS.

---

# Problem: HTTPS Does Not Show GET, Host or URI

Expected behaviour.

HTTPS payloads are encrypted with TLS.

Howlr can identify:

```text
443/HTTPS
```

but cannot normally read:

```text
GET
POST
Host
URI
```

from encrypted payloads.

---

# Problem: Traffic Direction Looks Wrong

Symptoms:

```text
expected LAN appears OUT
expected local traffic appears TRANSIT
IPv6 appears TRANSIT
```

Verify:

```text
--local-network
```

If your host is:

```text
192.168.0.111/24
```

the corresponding network is normally:

```text
192.168.0.0/24
```

not:

```text
192.168.1.0/24
```

Windows:

```powershell
ipconfig
```

Linux:

```bash
ip -br addr
ip route
```

---

# Problem: Lots of TRANSIT Traffic

Possible causes:

- incorrect local CIDR
- multiple networks visible
- IPv6 link-local traffic
- VPN
- virtual adapters
- routing/forwarding

`TRANSIT` is often a network-context clue, not an alert.

If expected local traffic appears as TRANSIT, check the configured local networks.

---

# Problem: VPN or Tailscale Changes Routing

VPNs and overlays can move traffic away from the physical NIC.

Symptoms:

```text
expected source IP: 192.168.x.x
actual source IP:   VPN/overlay address
```

Windows:

```powershell
Get-NetRoute -AddressFamily IPv4
```

```powershell
route print
```

Linux:

```bash
ip route
```

Identify which interface owns the route to the destination and capture there.

Do not change production routes without understanding the impact.

---

# Problem: Tailscale Route Takes Priority

A subnet route advertised through Tailscale can take precedence over a physical LAN path.

If a controlled lab test unexpectedly uses a Tailscale address:

1. inspect the route;
2. confirm the selected source address;
3. determine whether the test should use Tailscale or physical LAN;
4. capture the actual interface.

The issue is routing, not Howlr parsing.

---

# Problem: VMware / Kali Traffic Is Missing

Inside a VM, the correct interface may be:

```text
eth0
```

even if the host uses Wi-Fi.

Check:

```bash
ip -br addr
```

```bash
ip route
```

VM network mode affects visibility:

```text
NAT
bridged
host-only
```

Capture the interface where the VM traffic actually appears.

---

# Problem: Docker Interfaces Create Noise

Linux may show:

```text
docker0
br-xxxxxxxx
veth...
```

These are normal Docker interfaces.

If you want the VM's external traffic, the primary interface such as `eth0` is usually more relevant.

Use:

```bash
ip route
```

to verify.

---

# Problem: Service Count Seems Wrong

v0.2.0 service statistics recognise known service ports on either side of a TCP/UDP conversation.

Example inbound HTTPS:

```text
443 -> 49286
```

should still count as HTTPS.

If a service remains numeric:

- it may not be in Howlr's service map;
- it may be an ephemeral/custom port;
- port labels are not deep application detection.

---

# Problem: Too Much Console Output

Use Hunt Mode:

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" --local-network 192.168.1.0/24 --hunt -t 60
```

Or Quiet Mode:

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" --local-network 192.168.1.0/24 -t 60 -q
```

Hunt Mode prints observations. Quiet Mode focuses on the final summary/output files.

---

# Problem: Capture Stops Too Quickly

Check:

```text
-c
-t
```

Examples:

```text
-c 20
```

stops after 20 packets.

```text
-t 10
```

stops after 10 seconds.

Increase or remove the limit you do not want.

---

# Problem: Capture Keeps Running

If no count or timeout is used, live capture may continue until interrupted.

Stop with:

```text
Ctrl+C
```

or add:

```powershell
-c 100
```

or:

```powershell
-t 60
```

---

# Problem: Session Files Are Missing

Session output normally goes to:

```text
captures/
output/
```

Run Howlr from the project root.

Check:

### Windows

```powershell
Get-ChildItem .\captures
Get-ChildItem .\output
```

### Linux

```bash
ls -lah captures
ls -lah output
```

---

# Problem: Only One Output Type Exists

For automatic PCAP + JSONL + CSV:

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" --session test -c 50
```

For explicit output:

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" -c 50 --pcap-out capture.pcap --jsonl-out packets.jsonl --csv-out packets.csv
```

---

# Problem: Offline PCAP Cannot Be Found

Windows:

```powershell
Test-Path .\captures\capture.pcap
```

Linux:

```bash
ls -l ./captures/capture.pcap
```

Then:

```powershell
python .\howlr_packet_sentinel.py -r .\captures\capture.pcap
```

Check spelling and current directory.

---

# Problem: Summary Contains No Observations

Not an error.

It means Howlr processed traffic but none of the implemented rules matched.

Howlr is not a comprehensive signature IDS.

---

# Problem: `POSSIBLE_PORT_SCAN` Does Not Trigger

Check:

```text
--scan-threshold
--scan-window
```

Example test sensitivity:

```powershell
--scan-threshold 5 --scan-window 10
```

The source must generate enough relevant SYN activity inside the window.

If a test is too slow, the heuristic may not trigger.

Only perform scanning tests against systems you are authorised to test.

---

# Problem: `ARP_MAC_CHANGE` Does Not Trigger

Howlr must first observe one IP-to-MAC mapping and later observe the **same IP** with a **different MAC** during the same analysis.

One ARP reply produces:

```text
ARP_REPLY
```

A mapping change is required for:

```text
ARP_MAC_CHANGE
```

---

# Problem: Strange mDNS or SSDP Traffic

Common addresses/ports:

```text
224.0.0.251
239.255.255.250
ff02::fb
5353/MDNS
1900/SSDP
```

Common sources:

- Spotify
- smart TVs
- Chromecast
- printers
- Windows discovery
- mobile devices
- media applications

Presence alone is not suspicious.

---

# Problem: DNS REFUSED, NXDOMAIN or SERVFAIL Appears

Howlr may report:

```text
DNS_ERROR_RCODE
```

This can be normal.

Investigate:

```text
domain
source
resolver
rcode
frequency
```

One failed DNS query is not an incident.

---

# Problem: PowerShell `curl` Behaves Differently

PowerShell versions can treat `curl` differently.

For a controlled HTTP test:

```powershell
curl http://example.com -UseBasicParsing
```

or:

```powershell
Invoke-WebRequest http://example.com -UseBasicParsing
```

The purpose is simply to generate cleartext HTTP.

---

# Problem: Repository Is on the Wrong Branch

Check:

```bash
git branch
```

For stable use:

```text
main
```

Switch only with a clean/safely committed working tree:

```bash
git switch main
git pull origin main
```

---

# Problem: Git Working Tree Is Dirty

Run:

```bash
git status
```

Do not blindly discard files.

Determine whether changes are:

- intended code/docs
- generated outputs
- temporary test captures
- local environment files

Howlr runtime capture/output directories should normally be ignored by Git.

---

# Problem: Howlr Is Slow on a Busy Interface

Reduce workload:

1. add a BPF filter;
2. use `-q`;
3. shorten timeout;
4. capture one host;
5. save PCAP and analyse later.

Example:

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" -f "host 192.168.1.50" -t 60 -q
```

---

# Diagnostic Workflow

Use this order:

```text
Does Python work?
   ↓
Does --version work?
   ↓
Does --help work?
   ↓
Does --list-interfaces work?
   ↓
Can you capture with no filter?
   ↓
Can you generate visible traffic?
   ↓
Does the route use that interface?
   ↓
Does the filtered capture work?
```

Change one variable at a time.

---

# Minimal Known-Good Windows Test

```powershell
python .\howlr_packet_sentinel.py --version
```

```powershell
python .\howlr_packet_sentinel.py --list-interfaces
```

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" -c 20
```

While running:

```powershell
ping 1.1.1.1
```

---

# Minimal Known-Good Kali Test

```bash
.venv/bin/python howlr_packet_sentinel.py --version
```

```bash
.venv/bin/python howlr_packet_sentinel.py --list-interfaces
```

```bash
sudo .venv/bin/python howlr_packet_sentinel.py -i eth0 -c 20
```

In another terminal:

```bash
ping -c 4 1.1.1.1
```

---

# Known-Good HTTP Hunt Test

Terminal 1:

```bash
sudo .venv/bin/python howlr_packet_sentinel.py -i eth0 --local-network 192.168.1.0/24 --hunt -t 30
```

Terminal 2:

```bash
curl http://example.com
```

Possible output:

```text
CLEARTEXT_SERVICE:HTTP
CLEARTEXT_HTTP
HTTP GET host=example.com uri=/
```

---

# When to Move to Wireshark

Howlr is intended for triage.

Move to Wireshark when you need:

- packet-by-packet detail
- Follow TCP Stream
- deeper protocol fields
- retransmission analysis
- TLS handshake inspection
- payload analysis
- advanced display filters

Recommended workflow:

```text
Howlr
   ↓
Interesting traffic
   ↓
Session PCAP
   ↓
Wireshark
```

---

# Information to Collect Before Reporting a Bug

Record:

```text
Howlr version
operating system
Python version
Scapy version
interface name
exact command
full error message
live or offline mode
BPF filter, if any
```

Windows:

```powershell
python .\howlr_packet_sentinel.py --version
python --version
python -c "import scapy; print(scapy.__version__)"
```

Linux:

```bash
.venv/bin/python howlr_packet_sentinel.py --version
.venv/bin/python --version
.venv/bin/python -c "import scapy; print(scapy.__version__)"
```

Do not publicly share PCAPs containing sensitive traffic without reviewing them first.

---

For observation interpretation, see **[OBSERVATIONS.md](OBSERVATIONS.md)**.  
For detailed commands and use cases, see **[../USAGE.md](../USAGE.md)**.
