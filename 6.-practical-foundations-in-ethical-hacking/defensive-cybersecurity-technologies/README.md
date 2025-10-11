---
description: This section focuses on popular open source defensive cybersecurity tools used for firewalls, IDS/IPS, SIEM/EDR, and packet analyzers
---

# Defensive cybersecurity technologies

## Learning objectives

* Become familiar with popular open source host- and network-based firewalls
* Understand the difference between Web Application Firewalls (WAFs) and packet-filtering firewalls
* Become familiar with popular open source host- and network-based IDS, their key features, and their common use cases
* Become familiar with popular open source security event management technologies, their key features, and their common use cases
* Become familiar with popular open source packet analyzers, their key features, and their common use cases

This section explores major defensive cybersecurity technologies, including firewalls, IDS/IPS, SIEM/EDR, and packet analyzers. The discussion focuses on popular open-source tools used to implement these technologies, exploring their key characteristics and deployment (use cases). Key categories of defensive cybersecurity technologies discussed include host/network firewalls (e.g., UFW, iptables, nftables, PF, OPNsense, and pfSense), IDS/IPS (e.g., Suricata and Snort), network security monitoring/SIEM (e.g., Wazuh and OSSEC), and packet analyzers (e.g., Wireshark and tcpdump).

## Topics covered in this section

* **Firewalls**
* **IDS/IPS**
* **SIEM/EDR**
* **Packet analyzers**

### Firewalls

Popular open source host and network firewalls include UFW (Uncomplicated Firewall), iptables, nftables, PF or pfilter (packet filter), OPNsense, and pfSense (Community Edition).

Technology focus: nftables and OPNsense.

#### Firewalls Key features

#### **1. UFW (Uncomplicated Firewall)**

* **Type**: Host-based firewall (frontend for `iptables`/`nftables`).
* **Platform**: Linux (Ubuntu default).
* **Key Features**:
  * Simplified CLI for managing firewall rules (easier than raw `iptables`).
  * Supports IPv4 and IPv6.
  * Predefined application profiles (e.g., allow SSH, HTTP).
  * Integrates with `iptables` or `nftables` as the backend.
  * Designed for simplicity, ideal for desktop users and beginners.
* **Use Case:** Best for Linux beginners who need a simple, no-fuss host firewall.

#### **2. iptables**

* **Type**: Host/network firewall (kernel-level).
* **Platform**: Linux.
* **Key Features**:
  * Traditional Linux firewall using Netfilter framework.
  * Rule-based system (chains: INPUT, OUTPUT, FORWARD).
  * Supports NAT, packet filtering, and stateful inspection.
  * Complex syntax (requires expertise).
  * Being replaced by `nftables` but still widely used.
* **Use Case:** Legacy Linux firewall for experts needing granular control.

#### **3. nftables**

* **Type**: Host/network firewall (successor to `iptables`).
* **Platform**: Linux (kernel ≥ 3.13).
* **Key Features**:
  * Unified framework replacing `iptables`, `ip6tables`, `arptables`, etc.
  * Simpler syntax with JSON support.
  * Faster rule processing and better scalability.
  * Supports sets and maps for dynamic rules.
  * Backward-compatible with `iptables` via translation tools.
* **Use Case:** Modern Linux firewall unifying and simplifying `iptables` rules.

#### **4. PF (Packet Filter) / pfilter**

* **Type**: Host/network firewall.
* **Platform**: BSD (OpenBSD default, also FreeBSD, macOS).
* **Key Features**:
  * Stateful firewall with advanced features (NAT, QoS, traffic shaping).
  * Clean, readable rule syntax (e.g., `pass in on eth0 proto tcp to port 22`).
  * Supports logging, SYN proxy, and scrubbing.
  * Integrated in OpenBSD (security-focused).
* **Use Case:** Powerful BSD firewall with clean syntax for servers/networks.

#### **5. OPNsense**

* **Type**: Network firewall/router (open-source fork of pfSense).
* **Platform**: FreeBSD-based (dedicated appliance/VM).
* **Key Features**:
  * Web GUI for easy management.
  * Supports VPN (OpenVPN, WireGuard), IDS/IPS (Suricata), and traffic shaping.
  * Regular updates with a focus on security and usability.
  * Plugins for extended functionality (e.g., Nginx, CrowdSec).
  * Community and commercial support options.
* **Use Case:** Feature-rich open-source firewall with frequent updates for SMBs/enterprises.

#### **6. pfSense (Community Edition)**

* **Type**: Network firewall/router.
* **Platform**: FreeBSD-based (dedicated appliance/VM).
* **Key Features**:
  * Fork of m0n0wall, widely used in enterprises.
  * Web GUI with advanced features (VPN, captive portal, CARP for HA).
  * Supports packages (Snort, Squid, HAProxy).
  * Stateful firewall, NAT, and traffic shaping.
  * Large community but slower updates than OPNsense.
* **Use Case:** Reliable FreeBSD-based network firewall with a large support community.

**Firewall Comparison Table**

| Firewall         | Type         | Platform | GUI       | Ease of Use | Stateful | NAT | VPN Support       | IDS/IPS      | Traffic Shaping | IPv6 |
| ---------------- | ------------ | -------- | --------- | ----------- | -------- | --- | ----------------- | ------------ | --------------- | ---- |
| **UFW**          | Host         | Linux    | No (CLI)  | Very Easy   | Yes      | Yes | Limited           | No           | No              | Yes  |
| **iptables**     | Host/Network | Linux    | No (CLI)  | Complex     | Yes      | Yes | Manual            | No (add-ons) | Yes             | Yes  |
| **nftables**     | Host/Network | Linux    | No (CLI)  | Moderate    | Yes      | Yes | Manual            | No (add-ons) | Yes             | Yes  |
| **PF (pfilter)** | Host/Network | BSD      | No (CLI)  | Moderate    | Yes      | Yes | Manual            | No (add-ons) | Yes             | Yes  |
| **OPNsense**     | Network      | FreeBSD  | Yes (Web) | Easy        | Yes      | Yes | OpenVPN/WireGuard | Suricata     | Yes             | Yes  |
| **pfSense CE**   | Network      | FreeBSD  | Yes (Web) | Easy        | Yes      | Yes | OpenVPN/IPsec     | Snort        | Yes             | Yes  |

**Firewall Selection Guide**

This section provides a practical guide to help you select the most appropriate open-source tool based on your specific needs and context.

| Your Primary Need                                       | Recommended Tool(s)          | Key Reason                                                                                                                                                     |
| ------------------------------------------------------- | ---------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **A simple host firewall for a Linux desktop/server**   | **UFW**                      | Uncomplicated CLI, pre-configured profiles, and user-friendly.                                                                                                 |
| **Granular, expert-level control on a Linux system**    | **iptables** or **nftables** | Kernel-level power; choose `nftables` for a modern, unified syntax.                                                                                            |
| **A powerful firewall for a BSD-based system or macOS** | **PF (Packet Filter)**       | Clean syntax, stateful filtering, and integrated into the OS.                                                                                                  |
| **A full network security appliance with a web GUI**    | **OPNsense** or **pfSense**  | All-in-one solution (VPN, IDS/IPS, traffic shaping). Choose OPNsense for frequent updates and a modern approach, or pfSense for a vast, established community. |

**Summary**

* **UFW**: Best for Linux beginners needing simplicity.
* **iptables/nftables**: For advanced Linux users (legacy vs. modern).
* **PF**: Preferred on BSD for its clean syntax and power.
* **OPNsense/pfSense**: Feature-rich network firewalls; OPNsense has faster updates, pfSense has a larger legacy user base.

***

### IDS/IPS

Popular open source NIDS and HIDS include Suricata, Snort, Wazuh, OSSEC, Fail2Ban, Zeek (formerly Bro), Security Onion, and OpenWIPS-NG.

Technology focus: Suricata and Zeek (Bro).

#### IDS/IPS Key features

#### **1. Suricata**

* **Type**: NIDS/NIPS (Network Intrusion Detection/Prevention System).
* **Key Features**:
  * High-performance, multi-threaded engine.
  * Supports **real-time traffic analysis**, **automatic protocol detection** (HTTP, DNS, TLS).
  * Rule-based detection (compatible with **Snort rules**).
  * File extraction (e.g., malware detection via **YARA**).
  * Supports **EVE JSON** for structured logging.
  * Can act as an IPS (inline blocking).
* **Use Case**: Enterprise networks, high-speed traffic analysis.

#### **2. Snort**

* **Type**: NIDS/NIPS.
* **Key Features**:
  * The oldest and most widely used NIDS (since 1998).
  * **Signature-based detection** (custom/snort community rules).
  * Lightweight but single-threaded (lower throughput than Suricata).
  * Supports **PCAP analysis** for forensics.
  * Can be used as an IPS with inline mode.
* **Use Case**: Small to medium networks, basic threat detection.

#### **3. Wazuh**

* **Type**: HIDS + SIEM + Compliance.
* **Key Features**:
  * Fork of **OSSEC** with added cloud/SIEM features.
  * **Log analysis**, **file integrity monitoring (FIM)**, **rootkit detection**.
  * Supports **MITRE ATT\&CK mapping**.
  * Centralized management via web UI.
  * Integrates with **Elasticsearch** for log storage.
* **Use Case**: Endpoint security, compliance (PCI DSS, GDPR), and threat detection.

#### **4. OSSEC**

* **Type**: HIDS.
* **Key Features**:
  * Lightweight host-based monitoring.
  * **Log analysis**, **file integrity checks**, **rootkit detection**.
  * **Active response** (e.g., block IPs after brute-force attempts).
  * No native GUI (CLI-based, but Wazuh adds one).
* **Use Case**: Server security, compliance monitoring, and log-based intrusion detection.

#### **5. Fail2Ban**

* **Type**: HIDS (focused on log-based intrusion prevention).
* **Key Features**:
  * Scans log files (e.g., SSH, Apache) for brute-force attacks.
  * **Automatically bans malicious IPs** (via iptables/nftables).
  * Lightweight, easy to configure.
  * Limited to log-based attacks (not full HIDS).
* **Use Case**: Protecting servers from brute-force attacks.

#### **6. Zeek (formerly Bro)**

* **Type**: NIDS + Network Traffic Analysis (NTA).
* **Key Features**:
  * **Protocol-aware traffic analysis** (e.g., HTTP, DNS, SSL).
  * Generates **detailed logs** (`.log` files) for forensic analysis.
  * **Behavioral detection** (e.g., detecting C2 traffic).
  * No built-in IPS (passive monitoring only).
* **Use Case**: Best for network monitoring, forensics, and anomaly detection (deep traffic analysis).

#### **7. Security Onion**

* **Type**: NIDS/HIDS + SIEM + Network Monitoring.
* **Key Features**:
  * **All-in-one** distro (includes Suricata, Zeek, Wazuh, Elasticsearch).
  * **Full packet capture** (via Stenographer).
  * **SOC-friendly** with dashboards (Kibana, Grafana).
  * Heavy resource requirements (best for dedicated hardware).
* **Use Case**: Enterprise-grade network security monitoring.

#### **8. OpenWIPS-NG**

* **Type**: Wireless IDS/IPS (specialized for Wi-Fi).
* **Key Features**:
  * Detects **rogue APs**, **evil twin attacks**, **deauthentication floods**.
  * Supports **RFMON mode** for wireless monitoring.
  * Less maintained than others (but unique for Wi-Fi security).
* **Use Case**: Wireless network security.

**IDS/IPS Comparison Table**

| Tool               | Type           | Detection Method       | Key Strengths                               | IPS Capability     | GUI                | Logging/Output      | Best For                     |
| ------------------ | -------------- | ---------------------- | ------------------------------------------- | ------------------ | ------------------ | ------------------- | ---------------------------- |
| **Suricata**       | NIDS/NIPS      | Signature/Anomaly      | High-speed, multi-threaded, file extraction | Yes (inline)       | Web (e.g., Arkime) | EVE JSON, PCAP      | Enterprise networks          |
| **Snort**          | NIDS/NIPS      | Signature-based        | Lightweight, widely supported               | Yes (inline)       | No (CLI)           | PCAP, alerts        | Legacy networks              |
| **Wazuh**          | HIDS/SIEM      | Log/FIM/rootkit        | MITRE ATT\&CK, cloud integration            | No (HIDS)          | Yes                | Elasticsearch       | Compliance, cloud monitoring |
| **OSSEC**          | HIDS           | Log/FIM/rootkit        | Lightweight, active response                | No (HIDS)          | No (CLI)           | Text logs           | Servers, endpoint security   |
| **Fail2Ban**       | HIDS (log)     | Log parsing            | Simple brute-force protection               | Yes (via firewall) | No (CLI)           | Syslog              | SSH/web server protection    |
| **Zeek (Bro)**     | NIDS/NTA       | Behavioral/protocol    | Deep traffic analysis, forensics            | No                 | No (CLI)           | `.log` files        | Research, network forensics  |
| **Security Onion** | NIDS/HIDS/SIEM | Multiple engines       | All-in-one SOC platform                     | Via Suricata       | Yes (Kibana)       | Elasticsearch, PCAP | Security Operations Centers  |
| **OpenWIPS-NG**    | Wireless IDS   | Wi-Fi-specific attacks | Rogue AP detection                          | Limited            | No (CLI)           | Text logs           | Wi-Fi security monitoring    |

IDS/IPS Selection Matrix


|Your Primary Need|Recommended Tool(s)|Key Reason|
|---|---|---|
|**High-speed network intrusion detection/prevention (NIDS/NIPS)**|**Suricata**|Multi-threaded, high performance, and compatible with Snort rules.|
|**A lightweight, well-known NIDS for smaller networks**|**Snort**|The industry standard for decades, with extensive community support.|
|**Deep network traffic analysis and forensics**|**Zeek (Bro)**|Generates rich, structured logs of network protocols for behavioral analysis.|
|**Host-based monitoring (HIDS) and compliance**|**Wazuh**|Combines log analysis, FIM, vulnerability detection, and a central dashboard.|
|**A lightweight HIDS for servers with active response**|**OSSEC**|Lightweight, efficient, and can trigger actions like blocking IPs.|
|**Protection against brute-force attacks on services**|**Fail2Ban**|Scans logs and automatically blocks malicious IPs via the local firewall.|
|**An all-in-one distributed security monitoring platform**|**Security Onion**|Bundles Suricata, Zeek, Wazuh, and Elasticsearch for a complete SOC experience.|

**Summary**

* **For Networks**: **Suricata** (best performance), **Snort** (legacy), **Zeek** (deep analysis).
* **For Hosts**: **Wazuh** (full SIEM), **OSSEC** (lightweight), **Fail2Ban** (log-based).
* **For SOCs**: **Security Onion** (all-in-one).
* **For Wi-Fi**: **OpenWIPS-NG** (specialized).

***

### SIEM/EDR

Popular open source SIEM/EDR (Security Information and Event Management/Endpoint Detection and Response) technologies include Wazuh, TheHive, Zeek, OSSEC, Suricata, and Velociraptor.

Technology focus: Wazuh (SIEM/XDR).

#### SIEM/EDR Key features

#### **1. Wazuh**

* **Type**: SIEM + HIDS + Compliance
* **Key Features**:
  * **Log analysis**, **file integrity monitoring (FIM)**, **vulnerability detection**.
  * **MITRE ATT\&CK mapping** for threat detection.
  * **Endpoint protection** (Linux, Windows, macOS).
  * **Cloud/SaaS integration** (AWS, Azure, GCP).
  * **Centralized dashboard** (Elastic Stack/Kibana).
  * **Active response** (e.g., blocking malicious IPs).
* **Use Case**: Unified SIEM + endpoint security with compliance monitoring and threat detection.

#### **2. TheHive**

* **Type**: Incident Response + Case Management (Not a SIEM/EDR, but complementary)
* **Key Features**:
  * **Collaborative platform** for SOC teams.
  * **Integrates with MISP** (threat intelligence).
  * **Automated workflows** for incident handling.
  * **No detection capabilities** (relies on other tools like Wazuh/Suricata).
* **Use Case**: Collaborative incident response platform for SOC teams.

#### **3. Zeek (formerly Bro)**

* **Type**: Network Security Monitoring (NSM) + NTA
* **Key Features**:
  * **Protocol-aware traffic analysis** (HTTP, DNS, SSL).
  * **Behavioral detection** (e.g., C2 traffic, anomalies).
  * **Detailed logs** (`.log` files) for forensics.
  * **No built-in SIEM/EDR** (passive monitoring).
* **Use Case**: Network traffic analysis and behavioral threat detection via protocol logs.

#### **4. OSSEC**

* **Type**: HIDS (Host-based IDS)
* **Key Features**:
  * **Log analysis**, **file integrity checks**, **rootkit detection**.
  * **Active response** (e.g., block IPs after brute-force attempts).
  * **No native GUI** (CLI-based, but Wazuh extends it).
  * **Lightweight**, best for endpoint monitoring.
* **Use Case**: Lightweight HIDS for log analysis, file integrity, and active response.

#### **5. Suricata**

* **Type**: NIDS/NIPS (Network IDS/IPS)
* **Key Features**:
  * **Real-time traffic inspection** (supports Snort rules).
  * **File extraction** (YARA for malware detection).
  * **EVE JSON logs** for structured data.
  * **Can act as IPS** (inline blocking).
  * **Not an EDR** (focused on network traffic).
* **Use Case**: High-performance NIDS/NIPS with file extraction and IPS capabilities.

#### **6. Velociraptor**

* **Type**: EDR + Digital Forensics
* **Key Features**:
  * **Endpoint visibility** (Windows, Linux, macOS).
  * **Hunt for threats** (live query endpoints with VQL).
  * **Memory forensics**, **artifact collection**.
  * **No built-in SIEM** (but integrates with other tools).
* **Use Case**: Endpoint hunting and forensic investigation with live querying.

**SIEM/EDR Comparison Table**

| Tool             | Type               | Detection Capabilities          | Key Strengths                         | SIEM Integration | EDR Features | Best For                           |
| ---------------- | ------------------ | ------------------------------- | ------------------------------------- | ---------------- | ------------ | ---------------------------------- |
| **Wazuh**        | SIEM + HIDS        | Log/FIM/vulnerability detection | MITRE ATT\&CK, cloud support, Kibana  | Yes (Elastic)    | Basic EDR    | Compliance, centralized monitoring |
| **TheHive**      | Incident Response  | None (case management)          | SOC collaboration, MISP integration   | Via APIs         | No           | Incident handling, teamwork        |
| **Zeek**         | Network Monitoring | Behavioral/protocol analysis    | Deep traffic forensics                | Via logs         | No           | Network forensics, research        |
| **OSSEC**        | HIDS               | Log/FIM/rootkit detection       | Lightweight, active response          | Via Wazuh        | No           | Endpoint security                  |
| **Suricata**     | NIDS/NIPS          | Signature/anomaly detection     | High-speed, file extraction, IPS mode | Via logs         | No           | Network traffic analysis           |
| **Velociraptor** | EDR                | Endpoint forensics, hunting     | Live querying, memory analysis        | Via APIs         | Yes          | Threat hunting, IR                 |

SIEM/EDR Selection Matrix


|Your Primary Need|Recommended Tool(s)|Key Reason|
|---|---|---|
|**A unified SIEM with HIDS, compliance, and a dashboard**|**Wazuh**|All-in-one open-source SIEM/XDR platform with strong integration capabilities.|
|**Endpoint hunting, forensics, and live response**|**Velociraptor**|Powerful query language (VQL) for deep investigation and artifact collection on endpoints.|
|**Collaborative incident response and case management**|**TheHive**|Manages security incidents, integrates with MISP, and streamlines SOC workflows.|
|**To feed network traffic logs into your SIEM**|**Zeek** or **Suricata**|Both generate structured logs (e.g., EVE JSON) that can be ingested by SIEMs like Wazuh.|

**Best Combinations**:

* **Wazuh + TheHive + Suricata** → Full SIEM + IR (Incident Response) + NIDS.
* **Velociraptor + Zeek** → Advanced EDR + network forensics.

**Summary**

* **SIEM**: **Wazuh** (best all-in-one), **OSSEC** (lightweight HIDS).
* **EDR**: **Velociraptor** (advanced forensics), **Wazuh** (basic endpoint protection).
* **Network Analysis**: **Zeek** (deep inspection), **Suricata** (real-time IPS).
* **Incident Response**: **TheHive** (case management).

***

### Packet analyzers

Popular open source packet analyzers include Wireshark, tcpdump, Zeek, Snort, and Arkime.

Technology focus: Wireshark and tcpdump.

#### Packet analyzers Key features

#### **1. Wireshark**

* **Type**: GUI-based packet analyzer
* **Key Features**:
  * **Deep protocol dissection** (supports 3,000+ protocols).
  * **Live capture** + **offline analysis** (PCAP files).
  * **Filtering** (BPF syntax, e.g., `tcp.port == 443`).
  * **Visualization** (flow graphs, I/O graphs).
  * **Decryption** (TLS/SSL with keys, WEP/WPA).
  * **Cross-platform** (Windows, Linux, macOS).
* **Use Case**: Deep protocol inspection and troubleshooting via GUI.

#### **2. tcpdump**

* **Type**: CLI packet analyzer
* **Key Features**:
  * **Lightweight**, low-overhead capture.
  * **BPF filtering** (e.g., `tcpdump -i eth0 'port 80'`).
  * **Save to PCAP** for later analysis.
  * **No GUI** (often used with Wireshark for analysis).
  * **Ubiquitous** (preinstalled on most Unix-like systems).
* **Use Case**: Lightweight CLI packet capture for quick traffic analysis.

#### **3. Zeek (formerly Bro)**

* **Type**: Network Traffic Analyzer (NTA)
* **Key Features**:
  * **Protocol-aware logging** (generates `.log` files for HTTP, DNS, SSL, etc.).
  * **Behavioral analysis** (e.g., detecting C2 traffic).
  * **No live packet inspection** (post-capture analysis).
  * **Custom scripting** (Zeek scripts for advanced detection).
* **Use Case**: Generates structured network logs for forensic analysis.

#### **4. Snort**

* **Type**: NIDS (Network Intrusion Detection System)
* **Key Features**:
  * **Packet capture + rule-based detection** (signatures).
  * **Real-time traffic analysis** (alerts on malicious activity).
  * **Can dump PCAPs** of suspicious traffic.
  * **CLI-based** (no native GUI).
* **Use Case**: Rule-based NIDS for real-time traffic inspection and alerting.

#### **5. Arkime** (formerly Moloch)

* **Type**: Large-scale packet capture + analysis
* **Key Features**:
  * **Indexes and stores PCAPs** for long-term analysis.
  * **Web GUI** for searching/filtering traffic.
  * **Scalable** (handles multi-gigabit traffic).
  * **Integrates with Suricata/Wazuh** for alerts.
* **Use Case**: Large-scale PCAP storage and indexed traffic analysis.

**Packet Analyzers Comparison Table**

| Tool          | Type             | Interface | Live Capture | Protocol Decoding | Key Strengths                        | Best For                         |
| ------------- | ---------------- | --------- | ------------ | ----------------- | ------------------------------------ | -------------------------------- |
| **Wireshark** | Packet Analyzer  | GUI       | Yes          | 3,000+ protocols  | Deep inspection, visualization       | Troubleshooting, forensics       |
| **tcpdump**   | Packet Sniffer   | CLI       | Yes          | Basic protocols   | Lightweight, scripting-friendly      | Quick captures, server debugging |
| **Zeek**      | Traffic Analyzer | CLI/Logs  | No\*         | 50+ protocols     | Behavioral analysis, logging         | Network forensics, research      |
| **Snort**     | NIDS             | CLI       | Yes          | Limited           | Rule-based detection, PCAP dumping   | Security monitoring              |
| **Arkime**    | PCAP Storage     | Web GUI   | Yes          | 100+ protocols    | Scalable, long-term packet retention | SOCs, large networks             |

**Key Takeaways**

* **For deep analysis**: **Wireshark** (GUI) or **tcpdump** (CLI).
* **For traffic logging**: **Zeek** (creates structured logs).
* **For security monitoring**: **Snort** (NIDS mode).
* **For large-scale PCAP storage**: **Arkime** (web-based).

**Workflow Examples**:

1. **Capture with tcpdump** → Analyze in Wireshark.
2. **Zeek for traffic logs** + Arkime for PCAP retention.
3. **Snort for alerts** → Inspect PCAPs in Wireshark.

**Summary**

***

### Key takeaways

* Popular open source host-based firewalls include nftables and pf.
* Popular open source network-based firewalls include OPNsense and pfSense (CE).
* Packet-filtering firewall technologies such as iptables and pfilter (PF) operate at the network level (Layer 3/4).
* WAFs operate at the Application level (L7) and can be host- and network-based.
* Popular open source HIDS include Wazuh and OSSEC.
* Popular open source NIDS include Suricata and Snort.
* Popular open source SIEM include Wazuh and TheHive.
* Popular open source packet analyzers include Wireshark and tcpdump.
