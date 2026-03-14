---
description: >-
  This section looks at common open source network security testing tools,
  specifically, Nmap, OpenVAS, Wireshark, and tcpdump
---

# Network security testing

## Learning objectives

- Understand the practical use of network scanners like Nmap and OpenVAS in network security testing
- Understand the practical use of packet analyzers like Wireshark and tcpdump in network security testing
- Differentiate between active network scanning and passive packet analysis
- Develop a practical understanding of how protocol analyzers and software analyzers differ

This section establishes a practical understanding of network security testing by exploring both the underlying concepts and the essential tools used in the field. It begins by differentiating network security testing from routine network monitoring and administration, placing it within the context of a continuous security process like the "Test" phase of a security cycle. Next, the section looks at how network and vulnerability scanners like Nmap and OpenVAS actively probe a network to map assets and identify potential vulnerabilities. In contrast, we will explore how packet analyzers like Wireshark and tcpdump passively capture and dissect network traffic to provide deep visibility into the actual data in transit. This dual approach allows security professionals not only to discover what is on the network and what weaknesses may exist, but also to verify, troubleshoot, and perform forensic analysis on the network's live data. Finally, the section will expand this view by distinguishing protocol analysis from software analysis, introducing the specialized tools and methodologies used for deeper vulnerability research and reverse engineering. By the end, you will understand how these varied techniques work together to monitor and improve an organization's security posture.

## Topics covered in this section

* **Introduction**
* **Network security testing**
* **Protocol analyzers vs software analyzers**

### Introduction

Network administrators configure various monitoring tools and perform various testing activities to ensure smooth and secure network operation. Such activities and tools include:

- **Connectivity testing/troubleshooting** (basic network administration) using such tools/technologies as ping, traceroute, whois, nslookup, dig, netstat, nbtstat, arp, and syslog.
- **Network availability monitoring** (part of Network Management System) to determine the availability of network resources to users, using such tools as Big Brother, OpenNMS, and Nagios/Icinga. Network availability monitoring is "the concept of observing, measuring, and comparing the performance of a computer network using both technology and personnel". The purpose of network availability monitoring is "to detect faults within a network and ensure steady network operations" (Deveriya, 2005, p. 270). A typical network monitoring system is comprised of Windows-based or UNIX-based computers equipped with network-monitoring software. These systems regularly query the monitored devices at set intervals to assess the operational status of the network and its individual components. Based on the data collected from these queries, the monitoring system can generate alerts, which may be distributed through various channels such as email, pager notifications, or web-based dashboards. In addition to real-time alerting, the system retains historical data, enabling long-term reporting and trend analysis (Deveriya, 2005). Key concepts related to network availability monitoring include SLAs (Service-Level Agreements), MTTR (mean time to repair), and Five Nines.
- **Network performance monitoring** (part of Network Management System) to determine the adequacy of key performance parameters of network devices and links, using such tools as MRTG, Cacti, and Nagios/Icinga. Network performance monitoring is "the process of collecting, storing, and analyzing network statistics" (Deveriya, 2005, p. 314). Performance-monitoring systems typically rely on the Simple Network Management Protocol (SNMP) to interact with the devices under observation. Through SNMP, the monitoring system periodically polls these hosts to gather samples of key performance indicators. These collected data points are subsequently saved to a centralized repository, where they can be used for analysis and reporting purposes, including the generation of historical trends (Deveriya, 2005). The most common parameters for monitoring network performance are throughput (kbps), latency (ms/RTT), jitter, packet loss, CPU and memory utilization of network devices, and hard drive space.
- **Intrusion detection systems/intrusion prevention systems (IDS/IPS)** using such tools as Suricata and Snort. Most network intrusion detection systems (NIDS) are packet analyzers that watch for peculiar traffic patterns that are unique to network attacks.
- **Incident response and mitigation (SIEM) and endpoint detection and response (EDR)** using such tools as Wazuh SIEM/XDR.
- **Host and network firewalls** using such tools as ufw, iptables, nftables, pf (packet filter), OPNsense, and pfsense.
- **Network security testing** performed to assess and verify threats and vulnerabilities of a network, using such tools as Nmap, Nessus, OpenVAS, Netcat, Wireshark, and tcpdump.

### Network security testing

“Every organization on the planet that has any concern whatsoever for the security of its resources must perform various security assessments—and some don’t have a choice, if they need to comply with FISMA or other various government standards" (Walker, 2012, p. 312).

Network security is an ongoing process that can be described by the Cisco security wheel. The security wheel consists of the following four phases: Secure, Monitor, Test, and Improve. In the third phase, Test, or network security testing, netadmins verify the security design and discover vulnerabilities within the network.

<figure><img src="https://dti-techs.gitbook.io/practical-foundations-in-cybersecurity/~gitbook/image?url=https%3A%2F%2F3800590736-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252Fbt139QivYIJ8rAS9v8zR%252Fuploads%252FDBNAlxOLPPAvy0HB4QvD%252Fcisco-security-wheel.jpg%3Falt%3Dmedia%26token%3D34ef6a3b-decb-43ef-8acd-318e74e54230&#x26;width=768&#x26;dpr=2&#x26;quality=100&#x26;sign=15b8c83c&#x26;sv=2" alt="Cisco-security-wheel"><figcaption><p>Cisco Security Wheel (image courtesy of Deveriya, 2005, p. 362)</p></figcaption></figure>

Network security testing is also commonly referred to as security audit, security assessment, posture assessment, vulnerability assessment, penetration testing, and ethical hacking. All these terms are invoked to refer to "a legitimate process of attacking, discovering, and reporting security holes in a network" (Deveriya, 2005, p. 362).

Tools used for network security testing can be loosely classified into the following two categories:

* Scanners: Active tools that send out probe packets to the target host or network to attack or gather information.
* Packet analyzers: Passive in their operation because they do not send probe packets. Instead, packet analyzers work by capturing and analyzing the data that is flowing across the network.

**This discussion focuses on the following tools and methodologies of network security testing:**

- Network scanners: Nmap.
- Vulnerability scanners: OpenVAS (forked Nessus).
- Packet analyzers (sniffers): tcpdump and Wireshark.

Nmap and OpenVAS are covered in the section [Penetration testing technologies](../penetration-testing-technologies/). tcpdump and Wireshark are covered in the section [Defensive cybersecurity technologies](../defensive-cybersecurity-technologies/).

#### Network scanners

Network scanners are software tools that probe a network to determine the hosts present on the network. Network scanners also probe the discovered hosts to determine the TCP and UDP ports that are open. Furthermore, based on the response of the probes, scanners can identify the OS, the services that are running, and the associated security vulnerabilities present on the discovered hosts. Some scanners can also display the results in the form of graphical reports. (Deveriya, 2005, p. 365)

- **Nmap** (Network Mapper): The Swiss army knife of network scanners; a popular and versatile tool. Nmap identifies live hosts, open ports, and what services are running.
- **Nessus**: A popular **vulnerability scanner** with the ability to regularly update the vulnerability database; comes preinstalled with many Linux live CD-ROMs; and has good reporting capability. Nessus turned commercial in October 2005 but a limited feature version is available (Nessus Essentials provides vulnerability scanning for up to 16 IP addresses per scanner).
- **OpenVAS** (forked Nessus): Automatically scans live hosts, open ports, and running services for known vulnerabilities.

#### Packet analyzers

Packet analyzers, whether implemented as software applications or dedicated hardware devices, capture network traffic for inspection and analysis. These tools typically offer functionality for filtering, storing, and analyzing captured data. Many network intrusion detection systems (NIDS), for instance, function as specialized packet analyzers that monitor traffic for anomalous patterns associated with network attacks. Operating at the physical and data link layers (Layers 1 and 2 of the OSI model), packet analyzers can also decode protocol information from higher layers, providing networking professionals with a real-time, cross-sectional view of data traversing the network. This capability is invaluable when troubleshooting, as it allows administrators to inspect raw traffic at the packet level. It also serves as a learning tool for understanding protocol behavior and application communications, while simultaneously offering tangible proof that network components are functioning as intended (Deveriya, 2005).

- **Wireshark**: A versatile network protocol analyzer that captures and interactively displays traffic on a network in real time. With its graphical interface and deep inspection capabilities, Wireshark allows users to analyze packet data for troubleshooting, security analysis, and protocol development (Sanders, 2017). It supports hundreds of protocols and offers powerful filtering and visualization tools.
- **tcpdump**: A powerful command-line packet analyzer that captures and displays network traffic in real time, allowing deep inspection of packets for troubleshooting or security analysis.

#### Basic vs deep packet inspection

Layers 3-4 basic inspection of packets includes source/destination IPs, ports, TCP flags (SYN/ACK), packet size, and TTL (e.g., `tcpdump -i eth0 'tcp port 80'` shows HTTP traffic metadata).

Deep inspection involves analyzing not just Layer 3 (IP) and Layer 4 (TCP/UDP) headers, but also higher-layer protocols (L5-L7)—like HTTP requests, DNS queries, TLS handshakes, or even application-specific data (e.g., SSH encryption types, SMB file-sharing commands). Layers 5-7 deep inspection of packets includes:

* **Protocol dissection**: Decodes protocols like HTTP (`Host:` headers), DNS (`A? example.com`), FTP/SSH commands.
* **Payload analysis**: Displays partial/full payloads (e.g., `-X` flag for hex/ASCII output).
* Example: `tcpdump -A -s0 'port 443'` (attempts to show plaintext parts of TLS/SSL traffic).

**Basic vs Deep Packet Inspection: tcpdump vs Wireshark**

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

### Protocol analyzers vs software analyzers

A different class of tools becomes necessary when the focus shifts from observing network conversations to examining the internal logic of the applications themselves. The following discussion clarifies the difference between analyzing protocols, performed to identify network-level issues, and analyzing software, performed to discover flaws embedded within application code. The discussion contrasts protocol analyzers like Wireshark and tcpdump with software analysis tools such as disassemblers, debuggers, and decompilers which are used in reverse engineering and vulnerability research.
 
#### Communications protocols analyzers

This is the domain of network traffic inspection. Wireshark and tcpdump are protocol analyzers (or packet sniffers). They see everything on the wire at the network and transport layers (e.g., IP, TCP, UDP, ICMP). They are passive observers. In comparison, Burp Suite and OWASP ZAP are Web Application Security Proxies. They operate as a man-in-the-middle between your browser and the web server, specifically for HTTP/HTTPS traffic. They are active manipulators.

* **Wireshark:** The industry-standard protocol analyzer. It captures network traffic and allows the network admin/analyst to dissect hundreds of different protocols to see exactly what's happening on the wire.
* **tcpdump:** A command-line packet analyzer, often used on servers and for remote capture sessions.
* **Burp Suite / OWASP ZAP:** Specifically for web applications. These tools act as a proxy to intercept, analyze, and manipulate HTTP/HTTPS traffic between a browser and a web server. They are essential for finding web app vulnerabilities.

#### Software analyzers

Protocol analyzers like Wireshark and tcpdump are used to understand the "conversation" between different components. They answer: "What data is being sent, in what order, and in what format?" Understanding the "brain" having the conversation—the software itself—requires a different set of tools to take the software apart and examine its internals.

Analyzing software products to determine the product architecture and security vulnerabilities is the core activity of **reverse engineering** and **vulnerability research**. The goal is to understand how a product works from the inside out, without necessarily having access to its original blueprints (source code). This process involves:

1. **Determining product architecture:** How do the different components of the software or device fit together? How do they communicate? What libraries do they use? What is the data flow?
2. **Identifying security vulnerabilities:** Once you understand how it's built, you look for flaws in that design or implementation—places where the logic can be broken, commands can be injected, or memory can be corrupted to take control of the device.

While a protocol analyzer is a tool for analyzing communications protocols, analyzing the software itself requires a different toolkit.

* **Disassemblers and Decompilers:**
  * **Ghidra:** A powerful, open-source tool from the NSA. It takes compiled software (binary/executable) and translates it back into a human-readable form (assembly code, and even partial C code) so an analyst can figure out what the program does.
  * **IDA Pro:** The long-time commercial industry standard for disassembly. It's incredibly powerful for interactive, deep-dive reverse engineering.
  * **Binary Ninja:** A newer, modern disassembler that is gaining popularity for its API and usability.

* **Debuggers:**
  * **x64dbg / WinDbg / GDB:** These tools allow the analyst to run the program and control its execution. They can pause it, inspect the state of the CPU's memory and registers at any given moment, and step through code line-by-line to understand its logic and find flaws. This is crucial for crafting exploits.

* **Binary Analysis Frameworks:**
  * **radare2:** An open-source, command-line framework for reverse engineering. It's very powerful but has a steep learning curve.
  * **Cutter:** A graphical user interface for radare2, making it more accessible.

* **Fuzzers (Fuzzing Tools):**
  * **AFL (American Fuzzy Lop)** and its derivatives.
  * **Peach Fuzzer.**
  * **boofuzz.**

Disassemblers convert machine code (1s and 0s) to Assembly Language (human-readable processor instructions, e.g., `MOV EAX, 0x42`, `CALL printf`, `JMP loop_start`). Decompilers convert machine code (1s and 0s) to High-Level Language (C-like code with variables, functions, loops, and conditionals). Fuzzing tools automatically throw malformed, unexpected, or random data at a program or protocol to try and crash it. A crash often indicates a discoverable security vulnerability.

**Choosing Your Tools: Protocol Analysis vs Software Analysis**

| If you are analyzing...      | Concrete Analysis Goals & Examples                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    | Primary Tools                                              |
| ---------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------- |
| **Communications Protocols** | <p><strong>Goal:</strong> To understand the <em>external</em> communication behavior and find flaws in the protocol implementation.<br><br><strong>Specific Examples:</strong><br>• <strong>Authentication:</strong> Can I replay a login session packet to bypass authentication?<br>• <strong>Data Exposure:</strong> Is sensitive data (passwords, keys, PII) sent in cleartext?<br>• <strong>Input Validation:</strong> If I send a malformed, oversized, or unexpected packet, does the service crash or behave unexpectedly?<br>• <strong>Protocol Logic:</strong> Can I manipulate sequence numbers or session IDs to hijack a connection?</p>                                                                                 | **Wireshark, tcpdump, Burp Suite, OWASP ZAP**              |
| **Software (Binaries)**      | <p><strong>Goal:</strong> To understand the <em>internal</em> logic and code execution to find memory corruption and logic flaws.<br><br><strong>Specific Examples:</strong><br>• <strong>Memory Corruption:</strong> Is there a place where user input is copied into a fixed-size buffer without checking the length, causing a buffer overflow?<br>• <strong>Command Injection:</strong> Can user-controlled input be passed, unsanitized, to a system shell command?<br>• <strong>Backdoor Functions:</strong> Are there hidden, undocumented commands or functions that bypass security?<br>• <strong>Cryptographic Flaws:</strong> Are weak or custom encryption algorithms used? Are random number generators predictable?</p> | **Ghidra, IDA Pro, Debuggers (x64dbg, GDB), Binary Ninja** |

#### Compiled software vs source code

When software is developed, programmers write **source code** in human-readable languages like C, C++, Swift, or Rust. This looks like:

c

// This is source code - humans can read it 
#include \<stdio.h>

int main() { 
printf("Hello, World!"); 
return 0; 
}

**Compilation** is the process of translating this human-readable source code into **machine code** - the raw 1s and 0s that the computer's processor understands directly. The result is a **binary executable** file (like `.exe` on Windows, or no extension on macOS/Linux). (An interpreter is a program that reads and executes source code such as .py files directly, line by line, without compiling it to machine code first.)

Security researchers do not have the source code for Windows, Pages, or any other commercial product. They only have the compiled binary. Their job is to work backwards:

* **Input:** Compiled binary (machine code)
* **Process:** Use Ghidra/IDA Pro to **reverse engineer** it
* **Output:** Understand what the program does, find security flaws

#### Security testing vs vulnerability analysis

| Aspect                     | Penetration Testing                                                                       | Vulnerability Research                                                                           |
| -------------------------- | ----------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| **Primary Goal**           | Find and exploit known vulnerabilities using established methodologies                    | Discover previously unknown vulnerabilities (zero-days) by analyzing products from the ground up |
| **Mindset**                | "How can I break into this network/system using existing tools and techniques?"           | "How does this software/protocol actually work, and where are the design/implementation flaws?"  |
| **Tools Used**             | Mostly pre-built tools (Metasploit, Burp Suite, Nmap, etc.)                               | Deep reverse engineering tools (Ghidra, IDA Pro, debuggers), fuzzers, protocol analyzers         |
| **Vulnerability Research** | Typically limited to identifying publicly known vulnerabilities and applying them         | Creating new vulnerability discovery techniques, not just applying known ones                    |
| **Depth**                  | Broad but shallow - know about many attack vectors, but not necessarily deepest internals | Narrow but extremely deep - might spend weeks/months understanding one product                   |
| **Scripting**              | Basic scripting to automate tasks or modify existing exploits                             | Advanced scripting to build custom analysis tools and automation                                 |

### Key takeaways

* Tools used for network security testing can be loosely classified into two categories: network scanners and packet analyzers.
* Network scanners actively probe the network to discover assets and vulnerabilities, and packet analyzers passively capture and inspect raw traffic.
* Nmap and OpenVAS are two popular and complementary open source network scanners—Nmap identifies live hosts, open ports, and what services are running and OpenVAS automatically scans those hosts, ports, and services for known vulnerabilities.
* tcpdump is a powerful command-line packet analyzer that captures and displays network traffic in real time, allowing deep inspection of packets for troubleshooting or security analysis.
* Wireshark's graphical interface offers advanced protocol dissection and analysis for complex troubleshooting and forensic investigations.
* While Nmap discovers hosts and services and OpenVAS scans for vulnerabilities, tcpdump provides visibility into the raw network traffic between them.

### References

Deveriya, A. (2005). Network Administrators Survival Guide. Pearson Education.

Sanders, C. (2017). _Practical Packet Analysis: Using Wireshark to Solve Real-World Network Problems_ (3rd ed.). No Starch Press.

Walker, M. (2012). _CEH Certified Ethical Hacker All-in-One Exam Guide_. McGraw-Hill.