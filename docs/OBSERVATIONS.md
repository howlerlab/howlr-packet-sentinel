# Howlr Packet Sentinel — Observations, Directions and Severity Guide

This guide explains the traffic-direction labels, severity labels and lightweight observations produced by **Howlr Packet Sentinel v0.2.0**.

Howlr is a **triage tool**. Its observations are intended to answer:

```text
What should I look at next?
```

They do not automatically answer:

```text
Is this malicious?
```

> **Observations are triage hints, not proof of malicious activity.**

---

# Traffic Directions

Direction classification depends on the local network supplied with:

```text
--local-network
```

Example:

```text
--local-network 192.168.1.0/24
```

Assume:

```text
Local network: 192.168.1.0/24
Local host:    192.168.1.50
```

Possible labels:

```text
IN
OUT
LAN
MULTICAST
BROADCAST
TRANSIT
```

---

# IN — Inbound

`IN` means traffic is coming from outside the configured local network toward an address inside it.

Example:

```text
104.20.23.154 -> 192.168.1.50
```

Possible output:

```text
IN | IPv4 104.20.23.154 -> 192.168.1.50
```

Normal examples include:

- responses from websites
- cloud-service responses
- remote server replies
- responses to connections initiated by a local machine

Important:

```text
IN does not automatically mean unsolicited inbound traffic.
```

A response to your browser's outbound HTTPS connection is still inbound when it returns.

Questions to ask:

```text
Which external address is sending this?
Which local host receives it?
Which service is involved?
Was this communication expected?
```

---

# OUT — Outbound

`OUT` means traffic is leaving the configured local network.

Example:

```text
192.168.1.50 -> 104.20.23.154
```

Possible output:

```text
OUT | IPv4 192.168.1.50 -> 104.20.23.154
```

Common examples:

- web browsing
- software updates
- cloud applications
- DNS queries
- external APIs
- streaming
- remote services

Useful questions:

```text
Why is this host contacting that IP?
Which service is used?
Did a DNS query occur first?
Is the destination expected for the application?
```

Unexpected outbound traffic can be useful during investigation, but `OUT` itself is not suspicious.

---

# LAN — Local-to-Local Traffic

`LAN` means both source and destination are inside the configured local network.

Example:

```text
192.168.1.20 -> 192.168.1.50
```

Possible output:

```text
LAN | IPv4 192.168.1.20 -> 192.168.1.50
```

Common examples:

- SMB
- SSH
- RDP
- NAS traffic
- local DNS
- internal web applications
- workstation-to-workstation communication

Questions:

```text
Why are these two internal hosts communicating?
Is this service expected?
Should this source be able to reach this destination?
```

Unexpected LAN traffic can be useful when investigating lateral movement, but normal internal services can generate a large amount of LAN traffic.

---

# MULTICAST

Multicast traffic is sent to a group rather than one individual host.

IPv4 example:

```text
224.0.0.251
```

IPv6 example:

```text
ff02::fb
```

Possible output:

```text
MULTICAST | UDP 5353/MDNS -> 5353/MDNS
```

Common causes:

- mDNS
- printer discovery
- media devices
- local service discovery
- application discovery

Multicast is common on normal LANs.

High multicast volume can still be interesting during troubleshooting if discovery traffic becomes noisy.

---

# BROADCAST

Broadcast traffic is intended for all hosts on a local broadcast domain.

Common destination:

```text
255.255.255.255
```

Common uses:

- DHCP
- local service discovery
- bootstrapping
- legacy protocols

Broadcast traffic is normal in many networks.

Questions:

```text
Which protocol is broadcasting?
How frequently?
Is the volume expected?
```

---

# TRANSIT

`TRANSIT` means a packet does not fit the normal local-network relationship Howlr inferred from the configured local network.

Possible reasons:

- wrong `--local-network`
- another subnet is visible
- routing or forwarding
- VPN traffic
- virtual interfaces
- IPv6 traffic while only an IPv4 local network was configured
- multi-network capture environment

Example:

```text
TRANSIT | IPv6 fe80::... -> fe80::...
```

`TRANSIT` often means:

```text
check your network context
```

rather than:

```text
this traffic is malicious
```

If a large percentage of expected local traffic appears as `TRANSIT`, verify your local-network settings.

---

# Severity Levels

Howlr can display:

```text
NORMAL
INFO
NOTICE
WARNING
```

These are prioritisation aids.

They are not CVSS scores, SIEM incident severities or formal threat ratings.

---

# NORMAL

Example:

```text
NORMAL | IN | TCP 443/HTTPS -> 49286 flags=ACK event=ACK
```

This generally means the current Howlr logic did not attach a noteworthy observation to the packet.

`NORMAL` does **not** mean:

```text
trusted
safe
verified
benign
encrypted
authorised
```

It simply means no higher-priority rule matched.

---

# INFO

Often used for low-priority context.

Example:

```text
INFO | LAN | ARP reply ... | OBS=ARP_REPLY
```

Use INFO events as supporting context.

---

# NOTICE

Often used when a packet deserves more attention.

Example:

```text
NOTICE | OUT | ... | OBS=CLEARTEXT_HTTP
```

Possible reasons:

- readable cleartext HTTP
- DNS error
- another noteworthy but not necessarily dangerous event

---

# WARNING

Used for stronger heuristics or state changes.

Examples:

```text
WARNING | LAN | ... | OBS=POSSIBLE_PORT_SCAN
```

```text
WARNING | LAN | ... | OBS=ARP_MAC_CHANGE:...
```

A WARNING is still not proof of compromise.

---

# TCP_SYN

Observation:

```text
TCP_SYN
```

Meaning:

A TCP SYN was observed.

This usually means:

```text
a host is attempting to begin a TCP connection
```

Example:

```text
TCP 50836 -> 80/HTTP flags=SYN event=SYN | OBS=TCP_SYN
```

Normal reasons:

- browser opens connection
- SSH client connects
- application contacts API
- software updater connects
- service check

Potentially interesting when:

- SYNs occur rapidly
- many unique ports are touched
- target is unusual
- source is unexpected
- SYNs repeatedly fail

Investigation:

```text
source
destination
destination port
SYN-ACK?
RST?
repeated attempts?
POSSIBLE_PORT_SCAN?
```

---

# TCP_RST

Observation:

```text
TCP_RST
```

Meaning:

A TCP reset was observed.

Normal causes:

- closed port
- application abort
- connection-state mismatch
- service restart
- firewall behaviour
- client cancellation

Useful when:

- an application cannot connect
- many resets occur
- scanning is suspected
- one service repeatedly refuses traffic

Questions:

```text
Which side sent RST?
Which port?
Was there a SYN first?
Is the service expected to listen?
How frequently does it happen?
```

---

# ARP_REPLY

Observation:

```text
ARP_REPLY
```

Meaning:

An ARP reply was observed.

ARP maps IPv4 addresses to MAC addresses on the local network.

Conceptual example:

```text
192.168.1.20 is at aa:bb:cc:dd:ee:ff
```

Common causes:

- ordinary LAN operation
- gateway communication
- ARP cache refresh
- host discovery

`ARP_REPLY` is informational by itself.

Its value increases when combined with ARP mapping tracking.

---

# ARP_MAC_CHANGE

Observation:

```text
ARP_MAC_CHANGE
```

Meaning:

The same IPv4 address was observed with a different MAC address during the same analysis.

Example:

```text
ARP_MAC_CHANGE:192.168.1.50:02:00:00:00:00:01->02:00:00:00:00:02
```

Interpretation:

```text
IP:            192.168.1.50
Previous MAC:  02:00:00:00:00:01
New MAC:       02:00:00:00:00:02
```

Legitimate causes:

- DHCP reassignment
- device/NIC replacement
- VM migration
- failover
- high-availability behaviour
- network redesign

Security-related possibilities:

- ARP spoofing
- duplicate-IP conflict
- man-in-the-middle attempt

Investigation checklist:

```text
1. identify the IP owner
2. identify both MAC addresses
3. check router/switch ARP tables
4. confirm failover or VM movement
5. check for duplicate-IP symptoms
6. preserve a PCAP if behaviour continues
```

Do not conclude ARP spoofing from this observation alone.

---

# DNS_ERROR_RCODE

Observation:

```text
DNS_ERROR_RCODE
```

Meaning:

A DNS response returned a non-success/error condition.

Example:

```text
DNS response telemetry.example.com type=A answers=0 rcode=REFUSED | OBS=DNS_ERROR_RCODE:REFUSED
```

Possible conditions include:

```text
NXDOMAIN
SERVFAIL
REFUSED
```

Possible benign causes:

- nonexistent name
- resolver policy
- blocked query
- application typo
- split-DNS behaviour
- temporary resolver failure

Potentially interesting when:

- random-looking domains repeatedly fail
- one host creates large numbers of errors
- DNS policy blocks unexpected requests
- a process enters a retry loop

Questions:

```text
Which domain?
Which source host?
Which resolver?
Which rcode?
How often?
Did a later query succeed?
```

---

# CLEARTEXT_SERVICE

Observation:

```text
CLEARTEXT_SERVICE:<SERVICE>
```

Meaning:

Traffic used a port commonly associated with a service that may operate without transport encryption.

Examples:

```text
CLEARTEXT_SERVICE:HTTP
CLEARTEXT_SERVICE:TELNET
CLEARTEXT_SERVICE:FTP
```

Potential cleartext-associated services include:

- FTP
- Telnet
- HTTP
- POP3
- IMAP
- LDAP
- VNC

Important limitations:

The observation does **not** prove:

- credentials were exposed
- sensitive data was exposed
- the protocol actually matches the port
- the entire session is unencrypted

It means the service/port deserves attention.

Questions:

```text
Who initiated it?
Which host?
Which port?
Is an encrypted alternative available?
Is the service authorised?
```

---

# CLEARTEXT_HTTP

Observation:

```text
CLEARTEXT_HTTP
```

Meaning:

Howlr recognised readable metadata from an unencrypted HTTP request.

Example:

```text
HTTP GET host=example.com uri=/
```

Combined:

```text
OBS=CLEARTEXT_SERVICE:HTTP,CLEARTEXT_HTTP
```

Possible visible metadata:

- method
- Host
- URI

This demonstrates:

```text
unencrypted HTTP metadata can be visible to a passive observer
```

Potential risk depends on the application. URLs and headers can sometimes contain sensitive information.

Howlr does not decrypt normal HTTPS/TLS traffic.

Questions:

```text
Why is HTTP used?
What host?
What URI?
Is the application expected?
Could sensitive metadata be exposed?
```

---

# POSSIBLE_PORT_SCAN

Observation:

```text
POSSIBLE_PORT_SCAN
```

Meaning:

Howlr observed enough TCP SYN activity from one source toward multiple unique destination ports within the configured time window to trigger its scan heuristic.

Example:

```text
POSSIBLE_PORT_SCAN:192.168.1.20:5_ports_in_10s
```

Interpretation:

```text
Source:        192.168.1.20
Unique ports:  5
Window:        10 seconds
```

Possible security-testing causes:

- Nmap
- vulnerability scanner
- reconnaissance
- service discovery

Possible benign causes:

- administrator testing
- monitoring software
- asset inventory
- application fallback behaviour

Investigation:

```text
1. identify the source
2. identify the target
3. identify ports touched
4. check whether source is an authorised scanner
5. inspect timing
6. review SYN/SYN-ACK/RST pattern
7. save PCAP if needed
```

---

# Scan Threshold and Window

Example:

```text
--scan-threshold 5
--scan-window 10
```

Lower threshold:

```text
more sensitive
more likely to trigger on normal applications
```

Higher threshold:

```text
less sensitive
requires more ports
```

Short window:

```text
focuses on fast bursts
```

Longer window:

```text
includes slower behaviour
```

Tune based on your lab or network.

---

# Observation Combinations

A packet may carry multiple observations.

Example:

```text
OBS=TCP_SYN,CLEARTEXT_SERVICE:HTTP
```

Meaning:

```text
TCP connection attempt
+
destination is a cleartext-associated service port
```

Example:

```text
OBS=CLEARTEXT_SERVICE:HTTP,CLEARTEXT_HTTP
```

Meaning:

```text
HTTP service port
+
readable HTTP request metadata
```

Example:

```text
OBS=ARP_REPLY,ARP_MAC_CHANGE:...
```

Meaning:

```text
ARP reply
+
mapping changed
```

---

# How to Investigate an Observation

## 1. Read the Whole Packet

Do not focus only on `OBS=`.

Review:

```text
direction
source
destination
ports
service
TCP event
DNS metadata
HTTP metadata
```

## 2. Ask Whether It Is Expected

Examples:

```text
Known server?
Known scanner?
Expected application?
Intentional lab traffic?
```

## 3. Check Frequency

One event may be routine.

Repeated events may be more useful.

Review the final summary.

## 4. Correlate Events

Example:

```text
DNS query
   ↓
TCP SYN
   ↓
SYN-ACK
   ↓
HTTP GET
```

Context across packets is more meaningful than one isolated line.

## 5. Save Evidence

```powershell
python .\howlr_packet_sentinel.py -i "<INTERFACE>" --local-network 192.168.1.0/24 --session investigation -t 300
```

## 6. Move to Deeper Tools

Possible next steps:

- Wireshark
- firewall logs
- DNS logs
- OS logs
- EDR
- SIEM
- router/switch information

---

# False Positives and Normal Behaviour

Normal software can trigger observations.

Examples:

```text
browser opening many connections
software updater
administrator scan
monitoring agent
service discovery
failed DNS lookup
printer discovery
VM migration
failover
application retry loop
```

The correct response is:

```text
Observation
   ↓
Context
   ↓
Investigation
```

Not:

```text
Observation
   ↓
Attack confirmed
```

---

# Quick Observation Reference

| Observation | Meaning | What to Do |
|---|---|---|
| `TCP_SYN` | TCP connection attempt | Review in context |
| `TCP_RST` | TCP reset | Useful for troubleshooting or repeated failures |
| `ARP_REPLY` | ARP reply observed | Informational |
| `ARP_MAC_CHANGE` | Same IP changed MAC | Investigate context |
| `DNS_ERROR_RCODE` | DNS returned an error | Review if repeated/unexpected |
| `CLEARTEXT_SERVICE` | Cleartext-associated service port | Review service use |
| `CLEARTEXT_HTTP` | Readable HTTP metadata | Review why HTTP is used |
| `POSSIBLE_PORT_SCAN` | SYN threshold/window heuristic triggered | Investigate source/target |

---

# Quick Direction Reference

| Direction | Meaning |
|---|---|
| `IN` | Outside local network → inside |
| `OUT` | Inside local network → outside |
| `LAN` | Local network → local network |
| `MULTICAST` | Traffic to multicast group |
| `BROADCAST` | Traffic to local broadcast destination |
| `TRANSIT` | Does not fit configured local-network relationship |

---

# Recommended Mental Model

```text
Packet
   ↓
Observation
   ↓
Context
   ↓
Question
   ↓
Evidence
   ↓
Conclusion
```

Do not skip directly from observation to conclusion.
