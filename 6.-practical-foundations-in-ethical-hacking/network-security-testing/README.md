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

<figure><img src="https://dti-techs.gitbook.io/practical-foundations-in-cybersecurity/~gitbook/image?url=https%3A%2F%2F3800590736-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252Fbt139QivYIJ8rAS9v8zR%252Fuploads%252FDBNAlxOLPPAvy0HB4QvD%252Fcisco-security-wheel.jpg%3Falt%3Dmedia%26token%3D34ef6a3b-decb-43ef-8acd-318e74e54230&width=768&dpr=2&quality=100&sign=15b8c83c&sv=2" alt="Cisco-security-wheel"><figcaption><p>Cisco Security Wheel (image courtesy of Deveriya, 2005, p. 362)</p></figcaption></figure>

Network security testing is also commonly referred to as security audit, security assessment, posture assessment, vulnerability assessment, penetration testing, and ethical hacking. All these terms are invoked to refer to "a legitimate process of attacking, discovering, and reporting security holes in a network" (Deveriya, 2005, p. 362).

Tools used for network security testing can be loosely classified into the following two categories:

* Scanners: Active tools that send out probe packets to the target host or network to attack or gather information.
* Packet analyzers: Passive in their operation because they do not send probe packets. Instead, packet analyzers work by capturing and analyzing the data that is flowing across the network.

**This discussion focuses on the following tools and methodologies of network security testing:**

• Network scanners: Nmap.

• Vulnerability scanners: OpenVAS (forked Nessus).

• Packet analyzers (sniffers): tcpdump and Wireshark.

Nmap, OpenVAS, and tcpdump are covered in the section [Penetration testing technologies](../penetration-testing-technologies/). Wireshark is covered in the section [Defensive cybersecurity technologies](../defensive-cybersecurity-technologies/).

#### Network Scanners

Network scanners are software tools that probe a network to determine the hosts present on the network. Network scanners also probe the discovered hosts to determine the TCP and UDP ports that are open. Furthermore, based on the response of the probes, scanners can identify the OS, the services that are running, and the associated security vulnerabilities present on the discovered hosts. Some scanners can also display the results in the form of graphical reports. (Deveriya, 2005, p. 365)

• **Nmap** (Network Mapper): The Swiss army knife of network scanners; a popular and versatile tool. Nmap identifies live hosts, open ports, and what services are running.

• **Nessus**: A popular **vulnerability scanner** with the ability to regularly update the vulnerability database; comes preinstalled with many Linux live CD-ROMs; and has good reporting capability. Nessus turned commercial in October 2005 but a limited feature version is available (Nessus Essentials provides vulnerability scanning for up to 16 IP addresses per scanner).

• **OpenVAS** (forked Nessus): Automatically scans live hosts, open ports, and running services for known vulnerabilities.

#### Packet Analyzers

Packet analyzers are software or hardware devices that capture and analyze the data flowing through the network ... Many packet analyzers provide capabilities to filter, store, and analyze the captured data. In fact, most network intrusion detection systems (NIDS) are packet analyzers that watch for peculiar traffic patterns that are unique to network attacks. Packet analyzers work at Layers 1 and 2 of the OSI model but can also decode data at higher layers. This feature enables networking professionals to have a cross-sectional view of the data flowing through the network in real time. The ability to slice and view the raw data flowing through the wires is important when troubleshooting. Such views also help networking professionals to learn and understand the functioning of various protocols and applications. The views also provide clear proof that the network and its components are operational. (Deveriya, 2005, p. 386)

• **Wireshark**: A versatile network protocol analyzer that captures and interactively displays traffic on a network in real time. With its graphical interface and deep inspection capabilities, Wireshark allows users to analyze packet data for troubleshooting, security analysis, and protocol development. It supports hundreds of protocols and offers powerful filtering and visualization tools.

• **tcpdump**: A powerful command-line packet analyzer that captures and displays network traffic in real time, allowing deep inspection of packets for troubleshooting or security analysis.

#### Basic vs deep packet inspection

Layers 3-4 basic inspection of packets includes source/destination IPs, ports, TCP flags (SYN/ACK), packet size, and TTL (e.g., `tcpdump -i eth0 'tcp port 80'` shows HTTP traffic metadata).

Deep inspection involves analyzing not just Layer 3 (IP) and Layer 4 (TCP/UDP) headers, but also higher-layer protocols (L5-L7)—like HTTP requests, DNS queries, TLS handshakes, or even application-specific data (e.g., SSH encryption types, SMB file-sharing commands). Layers 5-7 deep inspection of packets includes:

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

Wireshark excels at deep L5-L7 analysis (e.g., "Decode this HTTP/2 stream" or "Find malformed DNS packets"). For example,

  * Right-click a packet → Follow → TCP Stream (reconstructs sessions).
  * Statistics → Protocol Hierarchy (shows traffic breakdown by protocol).

#### Protocol analyzers vs software analyzers

##### Communications protocols analyzers

This is the domain of network traffic inspection.

- **Wireshark:** The industry-standard protocol analyzer. It captures network traffic and allows you to dissect hundreds of different protocols to see exactly what's happening on the wire.
- **tcpdump:** A command-line packet analyzer, often used on servers and for remote capture sessions.
- **Burp Suite / OWASP ZAP:** Specifically for web applications. These tools act as a proxy to intercept, analyze, and manipulate HTTP/HTTPS traffic between a browser and a web server. They are essential for finding web app vulnerabilities.

##### Software analyzers

While a protocol analyzer is a tool for analyzing communications protocols, analyzing the software itself requires a different toolkit.

- Protocol analyzers like Wireshark and tcpdump are used to understand the "**conversation**" between different components. They answer: "What data is being sent, in what order, and in what format?"
- Understanding the "**brain**" having the conversation—the software itself—requires a different set of tools to take the software apart and examine its internals.

Analyzing software products to determine the product architecture and security vulnerabilities is the core activity of **reverse engineering** and **vulnerability research**. The goal is to understand how a product works from the inside out, without necessarily having access to its original blueprints (source code). This process involves:

1. **Determining product architecture:** How do the different components of the software or device fit together? How do they communicate? What libraries do they use? What is the data flow?
2. **Identifying security vulnerabilities:** Once you understand how it's built, you look for flaws in that design or implementation—places where the logic can be broken, commands can be injected, or memory can be corrupted to take control of the device.

- **Disassemblers & Decompilers:**
    
    - **Ghidra:** A powerful, open-source tool from the NSA. It takes compiled software (binary/executable) and translates it back into a human-readable form (assembly code, and even partial C code) so an analyst can figure out what the program does.
    - **IDA Pro:** The long-time commercial industry standard for disassembly. It's incredibly powerful for interactive, deep-dive reverse engineering.
    - **Binary Ninja:** A newer, modern disassembler that is gaining popularity for its API and usability.
        
- **Debuggers:**
    
    - **x64dbg / WinDbg / GDB:** These tools allow the analyst to run the program and control its execution. They can pause it, inspect the state of the CPU's memory and registers at any given moment, and step through code line-by-line to understand its logic and find flaws. This is crucial for crafting exploits.
        
- **Binary Analysis Frameworks:**
    
    - **radare2:** An open-source, command-line framework for reverse engineering. It's very powerful but has a steep learning curve.
    - **Cutter:** A graphical user interface for radare2, making it more accessible.
        
- **Fuzzers (Fuzzing Tools):**
    
    - **AFL (American Fuzzy Lop)** and its derivatives.
    - **Peach Fuzzer.**
    - **Boofuzz.**  

Fuzzing tools automatically throw malformed, unexpected, or random data at a program or protocol to try and crash it. A crash often indicates a discoverable security vulnerability.

**Summary**

|If you are analyzing...|Concrete Analysis Goals & Examples|Primary Tools|
|---|---|---|
|**Communications Protocols**|**Goal:** To understand the _external_ communication behavior and find flaws in the protocol implementation.  <br>  <br>**Specific Examples:**  <br>• **Authentication:** Can I replay a login session packet to bypass authentication?  <br>• **Data Exposure:** Is sensitive data (passwords, keys, PII) sent in cleartext?  <br>• **Input Validation:** If I send a malformed, oversized, or unexpected packet, does the service crash or behave unexpectedly?  <br>• **Protocol Logic:** Can I manipulate sequence numbers or session IDs to hijack a connection?|**Wireshark, tcpdump, Burp Suite, OWASP ZAP**|
|**Software (Binaries)**|**Goal:** To understand the _internal_ logic and code execution to find memory corruption and logic flaws.  <br>  <br>**Specific Examples:**  <br>• **Memory Corruption:** Is there a place where user input is copied into a fixed-size buffer without checking the length, causing a buffer overflow?  <br>• **Command Injection:** Can user-controlled input be passed, unsanitized, to a system shell command?  <br>• **Backdoor Functions:** Are there hidden, undocumented commands or functions that bypass security?  <br>• **Cryptographic Flaws:** Are weak or custom encryption algorithms used? Are random number generators predictable?|**Ghidra, IDA Pro, Debuggers (x64dbg, GDB), Binary Ninja**|

Compiled software vs source code

What is "Compiled Software"?

When software is developed, programmers write source code in human-readable languages like C, C++, Swift, or Rust. This looks like:
c

// This is source code - humans can read it
#include <stdio.h>

int main() {
    printf("Hello, World!");
    return 0;
}

Compilation is the process of translating this human-readable source code into machine code - the raw 1s and 0s that the computer's processor understands directly.

The result is a binary executable file (like .exe on Windows, or no extension on macOS/Linux).



**Security Testing vs Vulnerability Analysis** 

| Aspect                     | Penetration Testing                                                                           | Vulnerability Research                                                                               |
| -------------------------- | --------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| **Primary Goal**           | Find and exploit **known vulnerabilities** using established methodologies                    | Discover **previously unknown vulnerabilities** (zero-days) by analyzing products from the ground up |
| **Mindset**                | "How can I break into this network/system using existing tools and techniques?"               | "How does this software/protocol actually work, and where are the design/implementation flaws?"      |
| **Tools Used**             | Mostly **pre-built tools** (Metasploit, Burp Suite, nmap, etc.)                               | **Deep reverse engineering tools** (Ghidra, IDA Pro, debuggers), fuzzers, protocol analyzers         |
| **Vulnerability Research** | Limited to identifying **publicly known vulnerabilities** and applying them                   | Creating **new vulnerability discovery techniques**, not just applying known ones                    |
| **Depth**                  | **Broad but shallow** - know about many attack vectors, but not necessarily deepest internals | **Narrow but extremely deep** - might spend weeks/months understanding one product                   |
| **Scripting**              | **Basic scripting** to automate tasks or modify existing exploits                             | **Advanced scripting** to build custom analysis tools and automation                                 |



### Key takeaways

* Tools used for network security testing can be loosely classified into two categories: network scanners and packet analyzers.
* Nmap and OpenVAS are two popular and complementary open source network scanners—Nmap identifies live hosts, open ports, and what services are running and OpenVAS automatically scans those hosts, ports, and services for known vulnerabilities.
* tcpdump is a powerful command-line packet analyzer that captures and displays network traffic in real time, allowing deep inspection of packets for troubleshooting or security analysis.
* While Nmap discovers hosts and services and OpenVAS scans for vulnerabilities, tcpdump provides visibility into the raw network traffic between them.

### References

Deveriya, A. (2005). Network Administrators Survival Guide. Pearson Education.
