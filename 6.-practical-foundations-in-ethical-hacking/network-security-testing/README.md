---
description: >-
  This section looks at common open source network security testing tools,
  specifically, Nmap, OpenVAS, Wireshark, and tcpdump
---

# Network security testing

## Learning objectives

* Understand the practical use of network scanners in network security testing
* Understand the practical use of packet analyzers in network security testing

This section covers the use of network scanners (Nmap and OpenVAS) and packet analyzers (Wireshark and tcpdump) in network security testing.

## Topics covered in this section

* **Introduction**
* **Network security testing**

### Introduction

Network administrators configure various monitoring tools and perform various testing activities to ensure smooth and secure network operation. Such activities and tools include:

• **Connectivity testing/troubleshooting** (basic netadmin) using such tools/technologies as ping, traceroute, whois, nslookup, dig, netstat, nbtstat, arp, and syslog.

• **Network availability monitoring** (part of Network Management System) to determine the availability of network resources to users, using such tools as Big Brother, OpenNMS, and Nagios. Network availability monitoring is "the concept of observing, measuring, and comparing the performance of a computer network using both technology and personnel". The purpose of network availability monitoring is "to detect faults within a network and ensure steady network operations" (Deveriya, 2005, p. 270).

Typically, a network-monitoring system is comprised of Windows- or UNIX-based network-ready computers loaded with network-monitoring software. The network-monitoring system polls the monitored nodes at regular intervals to determine the overall health of the network and its components. Based on the polled results, the network-monitoring system generates alerts. These alerts can be e-mailed, sent through pager messages, or relayed through a web page. The network-monitoring system also stores the historical data for reporting and trending. (Deveriya, 2005, p. 270)

Key concepts related to network availability monitoring include SLAs (Service-Level Agreements), MTTR (mean time to repair), and Five Nines.

• **Network performance monitoring** (part of NMS) to determine the adequacy of key performance parameters of network devices and links, using such tools as MRTG, Cacti, and Nagios. Network performance monitoring is "the process of collecting, storing, and analyzing network statistics" (Deveriya, 2005, p. 314).

Typically, performance-monitoring systems use the Simple Network Management Protocol (SNMP) to communicate with the monitored hosts. Using SNMP, the performance-monitoring system regularly polls the monitored hosts and collects performance-parameter samples. The samples are then stored in a central database for analysis and reporting, such as historical trending. (Deveriya, 2005, p. 314)

The most common parameters for monitoring network performance are throughput (kbps), latency (ms/RTT), jitter, packet loss, CPU and memory utilization of network devices, and hard device space.

• **Intrusion detection systems/intrusion prevention systems (IDS/IPS)** using such tools as Suricata and Snort. Most network intrusion detection systems (NIDS) are packet analyzers that watch for peculiar traffic patterns that are unique to network attacks.

• **Incident response and mitigation (SIEM) and endpoint detection and response (EDR)** using such tools as Wazuh SIEM/XDR.

• **Host and network firewalls** using such tools as ufw, iptables, nftables, pf (packet filter), OPNsense, and pfsense.

• **Network security testing** performed to assess and verify threats and vulnerabilities of a network, using such tools as Nmap, Nessus, OpenVAS, Netcat, Wireshark, and tcpdump.

### Network security testing

“Every organization on the planet that has any concern whatsoever for the security of its resources must perform various security assessments—and some don’t have a choice, if they need to comply with FISMA or other various government standards" (Walker, 2012, p. 312).

Network security is an ongoing process that can be described by the Cisco security wheel. The security wheel consists of the following four phases: Secure, Monitor, Test, and Improve. In the third phase, Test, or network security testing, netadmins verify the security design and discover vulnerabilities within the network.

![[Pasted image 20251010134024.png]]
The process of network security testing is also commonly known as security audit, security assessment, posture assessment, vulnerability assessment, penetration testing, and ethical hacking. All these terms are invoked to refer to "a legitimate process of attacking, discovering, and reporting security holes in a network" (Deveriya, 2005, p. 362).

Tools used for network security testing can be loosely classified into the following two categories:

* Scanners - Active tools that send out probe packets to the target host or network to attack or gather information.
* Packet analyzers - Passive in their operation because they do not send probe packets. Instead, packet analyzers work by capturing and analyzing the data that is flowing across the network.

**This section focuses on the following tools and methodologies of network security testing:**

• Network scanners - Nmap

• Vulnerability scanners - OpenVAS (forked Nessus)

• Packet analyzers (sniffers) - tcpdump and Wireshark

\*Nmap, OpenVAS, and tcpdump are covered in the section [Penetration testing technologies](../penetration-testing-technologies/). Wireshark is covered in the section [Defensive cybersecurity technologies](../defensive-cybersecurity-technologies/).

#### Network Scanners

Network scanners are software tools that probe a network to determine the hosts present on\
the network. Network scanners also probe the discovered hosts to determine the TCP and\
UDP ports that are open. Furthermore, based on the response of the probes, scanners can\
identify the OS, the services that are running, and the associated security vulnerabilities\
present on the discovered hosts. Some scanners can also display the results in the form of\
graphical reports. (Deveriya, 2005, p. 365)

• **Nmap** (Network Mapper): The Swiss army knife of network scanners; a popular and versatile tool. Nmap identifies live hosts, open ports, and what services are running.

• **Nessus**: A popular **vulnerability scanner** with the ability to regularly update the vulnerability database; comes preinstalled with many Linux live CD-ROMs; and has good reporting capability. Nessus turned commercial in October 2005 but a limited feature version is available (Nessus Essentials provides vulnerability scanning for up to 16 IP addresses per scanner).

• **OpenVAS** (forked Nessus): Automatically scans live hosts, open ports, and running services for known vulnerabilities.

#### Packet Analyzers

Packet analyzers are software or hardware devices that capture and analyze the data flowing through the network ... Many packet analyzers provide capabilities to filter, store, and analyze the captured data. In fact, most network intrusion detection systems (NIDS) are packet analyzers that watch for peculiar traffic patterns that are unique to network attacks. Packet analyzers work at Layers 1 and 2 of the OSI model but can also decode data at higher layers. This feature enables networking professionals to have a cross-sectional view of the data flowing through the network in real time. The ability to slice and view the raw data flowing through the wires is important when troubleshooting. Such views also help networking professionals to learn and understand the functioning of various protocols and applications. The views also provide clear proof that the network and its components are operational. (Deveriya, 2005, p. 386)

• **Wireshark**: A versatile network protocol analyzer that captures and interactively displays traffic on a network in real time. With its graphical interface and deep inspection capabilities, Wireshark allows users to analyze packet data for troubleshooting, security analysis, and protocol development. It supports hundreds of protocols and offers powerful filtering and visualization tools.

• **tcpdump**: A powerful command-line packet analyzer that captures and displays network traffic in real time, allowing deep inspection of packets for troubleshooting or security analysis.

Deep inspection involves analyzing not just Layer 3 (IP) and Layer 4 (TCP/UDP) headers, but also higher-layer protocols (L5-L7)—like HTTP requests, DNS queries, TLS handshakes, or even application-specific data (e.g., SSH encryption types, SMB file-sharing commands).

Layers 3-4 basic inspection of packets includes source/destination IPs, ports, TCP flags (SYN/ACK), packet size, and TTL (e.g., `tcpdump -i eth0 'tcp port 80'` shows HTTP traffic metadata).

Layers 5-7 deep inspection of packets includes:

* **Protocol dissection**: Decodes protocols like HTTP (`Host:` headers), DNS (`A? example.com`), FTP/SSH commands.
* **Payload analysis**: Displays partial/full payloads (e.g., `-X` flag for hex/ASCII output).
* Example: `tcpdump -A -s0 'port 443'` (attempts to show plaintext parts of TLS/SSL traffic).

**Basic vs. Deep Packet Inspection: tcpdump vs. Wireshark**

| **Feature**                  | **tcpdump (CLI)**                                                               | **Wireshark (GUI)**                                                                   |
| ---------------------------- | ------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------- |
| **Basic Inspection (L3-L4)** | ✅ IPs, ports, TCP/UDP flags, packet size                                        | ✅ Same as tcpdump, but with color-coding                                              |
| **Deep Inspection (L5-L7)**  | ❗ Limited (requires `-A`/`-X` flags, no automatic decoding)                     | ✅ Full protocol dissection (HTTP, DNS, TLS, etc.)                                     |
| **Decryption Support**       | ❌ No built-in decryption                                                        | ✅ Supports TLS (with keys), WEP/WPA, etc.                                             |
| **Filtering**                | ✅ BPF syntax (e.g., `host 1.1.1.1`)                                             | ✅ Advanced display + capture filters                                                  |
| **Stream Reassembly**        | ❌ Manual (hard to track streams)                                                | ✅ Reconstructs HTTP, TCP, VoIP streams                                                |
| **Expert Analysis**          | ❌ Minimal (manual interpretation)                                               | ✅ Warnings/errors (retransmissions, etc.)                                             |
| **Export/Reporting**         | ✅ Text/PCAP only                                                                | ✅ PCAP, CSV, JSON, graphs, statistics                                                 |
| **Typical Application**      | Quick checks on servers, minimal resource usage, or piping data to other tools. | Forensics, complex troubleshooting, or when you need protocol decoding/visualization. |

**Key Clarifications**

tcpdump is lightweight and fast for basic L3-L4 inspection (e.g., "Show me all traffic to port 443").

*   Example:

    sh

    ```
    tcpdump -i eth0 'tcp port 443' -X
    ```

    (Shows TCP metadata + hex/ASCII payload snippets.)

tcpdump cannot decrypt modern encrypted traffic (e.g., HTTPS), but it _can_ expose:

* Unencrypted protocols (HTTP, SMTP).
* Protocol anomalies (e.g., suspicious TCP retransmissions).
* Metadata (e.g., TLS ClientHello SNI, DNS exfiltration).

Wireshark excels at deep L5-L7 analysis (e.g., "Decode this HTTP/2 stream" or "Find malformed DNS packets").

* Example:
  * Right-click a packet → Follow → TCP Stream (reconstructs sessions).
  * Statistics → Protocol Hierarchy (shows traffic breakdown by protocol).

### Key takeaways

* Tools used for network security testing can be loosely classified into two categories: network scanners and packet analyzers
* Nmap and OpenVAS are two popular and complementary open source network scanners—Nmap identifies live hosts, open ports, and what services are running and OpenVAS automatically scans those hosts, ports, and services for known vulnerabilities
* tcpdump is a powerful command-line packet analyzer that captures and displays network traffic in real time, allowing deep inspection of packets for troubleshooting or security analysis
* While Nmap discovers hosts and services and OpenVAS scans for vulnerabilities, tcpdump provides visibility into the raw network traffic between them

### References

Deveriya, A. (2005). Network Administrators Survival Guide. Pearson Education.
