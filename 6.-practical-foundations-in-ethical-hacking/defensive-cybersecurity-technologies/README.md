---
description: This section focuses on popular open source defensive cybersecurity tools used for firewalls, IDS/IPS, SIEM/EDR, and packet analyzers
---

# Defensive cybersecurity technologies

## Learning objectives

* Become familiar with popular open source host and network firewalls, their key features, and their common use cases
* Become familiar with popular open source host- and network-based IDS, their key features, and their common use cases
* Become familiar with popular open source security event management technologies, their key features, and their common use cases
* Become familiar with popular open source packet analyzers, their key features, and their common use cases
* Understand the difference between Web Application Firewalls (WAFs) and packet-filtering firewalls

This section explores major defensive cybersecurity technologies, including firewalls, IDS/IPS, SIEM/EDR, and packet analyzers. The discussion focuses on popular open-source tools used to implement these technologies, exploring their key characteristics and deployment (use cases). Key categories of defensive cybersecurity technologies discussed include host/network firewalls (e.g., UFW, iptables, nftables, PF, OPNsense, and pfSense), IDS/IPS (e.g., Suricata and Snort), network security monitoring/SIEM (e.g., Wazuh and OSSEC), and packet analyzers (e.g., Wireshark and tcpdump).

Note that many powerful open-source security tools have overlapping capabilities and can span multiple functional categories. A tool primarily classified as a Network Intrusion Detection System (NIDS), like Suricata, might also provide critical log data for a Security Information and Event Management (SIEM) system. This discussion categorizes tools by their primary function, but their real-world value often lies in how they are integrated into a broader security architecture.

## Topics covered in this section

* **Firewalls**
* **IDS/IPS**
* **SIEM/EDR**
* **Packet analyzers**

### Firewalls

Popular open source host and network firewalls include UFW (Uncomplicated Firewall), iptables, nftables, PF (pfilter or packet filter), ipfw, OPNsense, and pfSense (Community Edition).

Technology focus: nftables and OPNsense.

Key concepts: 
packet filtering firewalls
BSD (Berkeley Software Distribution) firewalls
connection-oriented vs connectionless transmission/communication
stateful vs stateless firewalls
Next-Generation Firewalls (NGFWs)
traffic shaping

---

#### **1. Core Concept: The Packet Filtering Firewall**

At its most basic, a firewall is a gatekeeper for network traffic. The simplest and oldest type is the packet filtering firewall. Packet-filtering firewall technologies operate at the network level (Layer 3/4). They allow network administrators to define rules for allowing, blocking, or modifying traffic based on IPs, ports, protocols, and connection states.

Packet filtering firewalls can be contrasted with:

1. Stateful Inspection Firewalls
2. Application-Level Gateways (Proxy Firewalls)
3. Next-Generation Firewalls (NGFWs)

#### **2. Stateless vs. Stateful Firewalls**

A critical evolution in firewall technology was the shift from stateless to stateful inspection. A **stateless firewall** treats each network packet in isolation, with no memory of previous packets. A rule like "allow TCP port 80" would permit all traffic to that port, regardless of whether it is a legitimate new connection or a random, malicious packet. 

A stateful firewall tracks the state of active connections (e.g., SYN, SYN-ACK, ESTABLISHED, RELATED, FIN) to make dynamic decisions. A stateful firewall understands sessions. It can tell the difference between an outgoing request to a web server and the returning traffic, and it can automatically allow the return traffic for an established session. This is a fundamental security improvement.

In contrast, a **stateful firewall** tracks the state of active network connections—such as NEW, ESTABLISHED, or RELATED—dramatically improving security. A **stateful firewall** can dynamically allow returning traffic for an outgoing connection it previously permitted, while blocking unsolicited incoming requests. While all modern firewalls are used in a stateful manner, their implementation differs. Some, like nftables, PF, and ipfw, are inherently stateful, with connection tracking as a core feature. Others, like the Linux iptables framework, achieve statefulness through the addition of the `conntrack` module and specific rules, which is considered a standard practice. Tools like UFW and systems like OPNsense/pfSense configure their underlying engines to be stateful by default.

**How Statefulness is Implemented in Common Tools**

| Firewall               | Stateful?            | Key Detail & Example                                                                                                                |
| ---------------------- | -------------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| **nftables, PF, ipfw** | **Inherently**       | Stateful tracking is a built-in, core feature. (e.g., PF uses `pass in proto tcp to port 22 keep state`)                            |
| **OPNsense / pfSense** | **Inherently**       | As distributions built on PF, statefulness is a fundamental, non-optional feature.                                                  |
| **iptables**           | **By Configuration** | Relies on the `conntrack` module. A rule like `-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT` enables statefulness. |
| **UFW**                | **By Default**       | As a front-end, it configures the underlying engine (iptables/nftables) to be stateful by default for ease of use.                  |

**Stateless vs Stateful Firewalls**

```
Stateless Firewall:
  [Packet] → [Check Rules] → Allow/Drop

Stateful Firewall:
  [Packet] → [Check State Table] → [Update State] → Allow/Drop
          ↳ (e.g., "Is this a reply to an existing SSH session?")
```


**Common States in `conntrack`**

| State           | Meaning                                                                          |
| --------------- | -------------------------------------------------------------------------------- |
| **NEW**         | First packet of a new connection (e.g., TCP SYN).                                |
| **ESTABLISHED** | Packets belonging to an already-seen connection (e.g., TCP handshake completed). |
| **RELATED**     | Packets related to an existing connection (e.g., FTP data connection).           |
| **INVALID**     | Malformed or suspicious packets (e.g., TCP RST without prior connection).        |


UFW, iptables, nftables, PF, ipfw, OPNsense, and pfSense (CE) are all considered packet filtering firewalls, but some have evolved into more sophisticated frameworks.
Furthermore, 
UFW, iptables, nftables, PF, ipfw, OPNsense, and pfSense (CE) are all considered stateful packet filtering firewalls, but with nuanced facts:
- **nftables, PF, ipfw, OPNsense, and pfSense** are architected as **stateful packet filters**.
- **iptables** is a framework that is almost universally **used as a stateful firewall**, but the statefulness comes from its connection tracking module, not the `iptables` command itself.
- **UFW** is a tool that **configures a stateful firewall** by default.

#### **3. Beyond Packet Filtering: Advanced Firewall Types**

While powerful, packet filtering firewalls are primarily concerned with _where_ traffic is going (IPs and ports). They are contrasted with more advanced firewalls that operate at higher layers and can inspect _what_ is inside the traffic. **Application-Level Gateways**, or **proxy firewalls**, operate at the Application Layer (Layer 7). Instead of simply forwarding packets, they act as an intermediary, terminating client connections and making new ones to the server. This allows them to inspect the actual content of the traffic, such as specific HTTP commands or SQL queries.

Packet filtering firewalls (even stateful ones) are contrasted with more advanced firewalls that operate at higher layers and make more intelligent decisions.

**Application-Level Gateways (Proxy Firewalls)**  
These operate at the Application Layer (OSI Layer 7). Instead of just forwarding packets, they act as an intermediary.

- **How it works:** The proxy terminates the client connection and initiates a new, separate connection to the server.
    
- **Key Advantage:** It can inspect the actual _content_ of the traffic (e.g., specific HTTP commands, SQL queries, malicious URLs), which a Layer 3/4 packet filter is blind to.
    

**Next-Generation Firewalls (NGFWs)**  
NGFWs represent the modern evolution, incorporating the features of all previous types and adding advanced security integrations.

An NGFW includes everything a stateful packet filter does, but also adds:

- **Deep Packet Inspection (DPI):** Looks _inside_ the packet payload to identify specific applications (e.g., "This is Facebook," not just "HTTP traffic on port 80").
    
- **Integrated Intrusion Prevention System (IPS):** Actively blocks known attack patterns and vulnerabilities within the traffic flow.
    
- **Identity & User Awareness:** Enforces policies based on user or group identity (e.g., from Active Directory), not just IP addresses.
    
- **Threat Intelligence Feeds:** Leverages cloud-based data to block traffic from known malicious sources in real-time.
    

**Summary & Comparison**

|Feature|Packet Filtering Firewall|Next-Generation Firewall (NGFW)|
|---|---|---|
|**Primary OSI Layer**|**Layers 3 & 4**|**Layers 3-7**|
|**Decision Basis**|IP, Port, Protocol|**IP, Port, Protocol, Application, User, Content**|
|**Connection Awareness**|Stateless or Stateful|**Stateful by default**|
|**Traffic Inspection**|Header-only|**Deep Packet Inspection (DPI)**|
|**Advanced Features**|Basic NAT, Logging|**IPS, Anti-Virus, Threat Intelligence, Identity Awareness**|


**Next-Generation Firewalls (NGFWs)**

Packet filtering firewalls are the oldest and most basic type. 
Packet filtering firewalls can be contrasted with firewalls that operate at higher layers of the OSI model and make more intelligent packet filtering decisions.

NGFWs provide a more comprehensive, intelligent, and application-aware security posture for modern networks.

NGFWs can perform stateful and Application layer packet filtering, in addition to:

- **Deep Packet Inspection (DPI):** Looking _inside_ the packet payload (like a proxy) to identify applications (e.g., "This is Facebook traffic," not just "HTTP traffic on port 80").
- **Integrated Intrusion Prevention Systems (IPS):** Actively blocking known threats and attack patterns within the traffic flow.
- **User & Group Identity Integration:** Blocking or allowing traffic based on user identity (e.g., from Active Directory), not just IP address.
- **Threat Intelligence Feeds:** Leveraging cloud-based data to block traffic from known malicious sources.

The modern evolution is the **Next-Generation Firewall (NGFW)**, which incorporates and expands upon all previous capabilities. An NGFW performs stateful packet inspection but also integrates features like **Deep Packet Inspection (DPI)** to identify specific applications (e.g., "This is Facebook," not just "HTTP on port 80"), **Intrusion Prevention Systems (IPS)** to block known attack patterns, and identity awareness to enforce policies based on users, not just IP addresses.

The key differences between a traditional packet filtering firewall and an NGFW can be summarized as follows:

**Summary Table**

|Feature|Packet Filtering Firewall|Next-Generation Firewall (NGFW)|
|---|---|---|
|**Primary OSI Layer**|**Layers 3 & 4** (Network & Transport)|**Layers 3-7** (Network to Application)|
|**Decision Basis**|IP Address, Port, Protocol|IP, Port, Protocol, **Application, User, Content**|
|**Connection Awareness**|Stateless or Stateful|**Stateful** by default|
|**Traffic Inspection**|Header-only|**Deep Packet Inspection (DPI)** of payload|
|**Additional Features**|Basic NAT, basic logging|**IPS, Anti-Virus, Threat Intelligence, Identity Awareness**|

---
### Stateless vs stateful firewalls pros and cons

Stateful and stateless firewalls serve different purposes in network security, each with its own advantages. Here’s a comparison highlighting the **advantages of stateful firewalls over stateless firewalls**:

**Advantages of Stateful Firewalls:**

Most modern firewalls (e.g., NGFW) are stateful by default due to their security advantages.

1. **Context-Aware Traffic Filtering**
   * Stateful firewalls track the **state** of active connections (e.g., TCP handshakes, UDP sessions), allowing them to make smarter decisions.
   * Example: Only allows inbound traffic if it’s part of an established outbound connection.
2. **Better Security Against Attacks**
   * Can detect and block malicious traffic that abuses protocol states (e.g., TCP SYN floods, session hijacking).
   * Prevents unauthorized traffic that doesn’t match an existing connection.
3. **Granular Control Over Sessions**
   * Can enforce policies based on connection state (e.g., allow only "established" or "related" traffic).
   * Supports dynamic rule adjustments (e.g., temporarily opening ports for FTP data connections).
4. **Protection Against Spoofing & DoS**
   * Recognizes abnormal traffic patterns (e.g., unexpected RST or FIN packets).
   * Can enforce rate limiting per connection.
5. **Supports Complex Protocols**
   * Handles protocols like FTP, SIP, and VoIP that use dynamic ports by tracking their control sessions.
6. **Logging & Monitoring**
   * Provides detailed logs of connection states, aiding in forensic analysis and troubleshooting.

**Why Stateful Filtering is Useful**

✅ **Simpler Rules**: No need to manually allow reply traffic.\
✅ **Security**: Blocks unsolicited/invalid packets (e.g., spoofed ACKs).\
✅ **Performance**: Faster than checking every packet against all rules.

**When Stateless Firewalls Are Better:**

Stateless firewalls (ACLs) are simpler and faster but lack intelligence. They are useful for:

* High-speed networks where performance is critical (e.g., backbone routers).
* Simple packet filtering based on static rules (e.g., IP/port blocking).
* Environments where connection tracking isn’t needed.



**Underlying Systems of Common Packet-Filtering Firewalls (Summary Table)**

| Firewall     | Underlying System | OS Family       | Notes                             |
| ------------ | ----------------- | --------------- | --------------------------------- |
| **iptables** | Netfilter (Linux) | Linux           | Legacy, replaced by nftables.     |
| **nftables** | Netfilter (Linux) | Linux           | Unifies IPv4/IPv6, better syntax. |
| **PF**       | BSD Kernel        | OpenBSD/FreeBSD | Powers OPNsense/pfSense.          |
| **ipfw**     | BSD Kernel        | FreeBSD/macOS   | Older, simpler than PF.           |
| **WFP**      | Windows Kernel    | Windows         | Native firewall for Windows.      |

Windows Filtering Platform (WFP) is Microsoft’s built-in firewall (CLI: `netsh advfirewall`).

**BSD-Based Firewalls**

BSD-based firewalls use networking and security tools native to BSD systems. BSD stands for Berkeley Software Distribution, a family of **Unix-like operating systems** derived from the original Berkeley Unix (developed at UC Berkeley).

**Key BSD Variants in Firewalling**

| BSD OS             | Firewall Used                          | Notes                                                                           |
| ------------------ | -------------------------------------- | ------------------------------------------------------------------------------- |
| **OpenBSD**        | **PF (Packet Filter)**                 | Famously secure/the gold standard for BSD firewalls (used in OPNsense/pfSense). |
| **FreeBSD**        | **PF** or **ipfw**                     | Supports both, but PF is more modern.                                           |
| **NetBSD**         | **NPF** or **IPFilter**                | Less common in firewalls.                                                       |
| **macOS (Darwin)** | **ipfw (legacy)** / **PF (partially)** | macOS inherited some BSD firewall tools.                                        |


### Web Application Firewalls (WAFs)

**WAF key characteristics:**

* Scope: Inspects payloads (e.g., "Block HTTP requests with SQLi").
* L7 Awareness: Understands HTTP, DNS, etc. (deep packet inspection)
* Performance Impact: High (parses full packets).

WAFs can be **host-based and network-based**, depending on deployment:

| Type                  | Example Tools                         | Deployment                                                      |
| --------------------- | ------------------------------------- | --------------------------------------------------------------- |
| **Host-Based WAF**    | ModSecurity (Apache/Nginx plugin)     | Runs on the web server (e.g., as a module).                     |
| **Network-Based WAF** | Cloudflare WAF, HAProxy + ModSecurity | Standalone appliance/cloud service (protects multiple servers). |


#### Firewalls key features

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
Predecessor to nftables. Part of the Linux kernel (Netfilter project), licensed under GPL.

#### **3. nftables**

* **Type**: Host/network firewall (successor to `iptables`).
* **Platform**: Linux (kernel ≥ 3.13).
* **Key Features**:
  * Unified framework replacing `iptables`, `ip6tables`, `arptables`, etc.
  * Simplified syntax with JSON support.
  * Faster rule processing and better scalability (than iptables).
  * Supports sets and maps for dynamic rules.
  * Backward-compatible with `iptables` via translation tools.
* **Use Case:** Modern Linux firewall unifying and simplifying `iptables` rules.
Modern successor to iptables, more flexible syntax. Also part of Linux (Netfilter), GPL-licensed.

#### **4. PF (Packet Filter) / pfilter**

* **Type**: Host/network firewall.
* **Platform**: BSD (OpenBSD default, also FreeBSD, macOS).
* **Key Features**:
  * Stateful firewall with advanced features (NAT, QoS, traffic shaping).
  * Clean, readable rule syntax (e.g., `pass in on eth0 proto tcp to port 22`).
  * Supports logging, SYN proxy, and scrubbing.
  * Integrated in OpenBSD (security-focused).
* **Use Case:** Powerful BSD firewall with clean syntax for servers/networks.
More advanced than iptables, used in BSD-based firewalls. Originally from OpenBSD, now also in FreeBSD and others, BSD license. CLI based macOS built-in Unix firewall.
PF handles high traffic efficiently (better than iptables in some cases).

**ipfw**: Older BSD firewall, mostly replaced by PF. Found in FreeBSD (and older macOS versions), BSD license. OS/platform: FreeBSD, macOS (legacy)

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

| Firewall         | Type         | Platform       | GUI       | Ease of Use | Stateful | NAT | VPN Support       | IDS/IPS      | Traffic Shaping (QoS) | IPv6 |
| ---------------- | ------------ | -------------- | --------- | ----------- | -------- | --- | ----------------- | ------------ | --------------------- | ---- |
| **UFW**          | Host         | Linux          | No (CLI)  | Very Easy   | Yes      | Yes | Limited           | No           | No                    | Yes  |
| **iptables**     | Host/Network | Linux          | No (CLI)  | Complex     | Yes      | Yes | Manual            | No (add-ons) | Yes                   | Yes  |
| **nftables**     | Host/Network | Linux          | No (CLI)  | Moderate    | Yes      | Yes | Manual            | No (add-ons) | Yes                   | Yes  |
| **PF (pfilter)** | Host/Network | OpenBSD, macOS | No (CLI)  | Moderate    | Yes      | Yes | Manual            | No (add-ons) | Yes                   | Yes  |
| **OPNsense**     | Network      | FreeBSD        | Yes (Web) | Easy        | Yes      | Yes | OpenVPN/WireGuard | Suricata     | Yes                   | Yes  |
| **pfSense CE**   | Network      | FreeBSD        | Yes (Web) | Easy        | Yes      | Yes | OpenVPN/IPsec     | Snort        | Yes                   | Yes  |

#### Stateless vs Stateful Firewalls

A stateless firewall performs packet filtering based solely on the static rule set and the headers of the individual packet in question, with no memory of prior packets. This necessitates explicit, bidirectional rules for any permitted communication. For example, to allow outbound HTTP, you would need one rule permitting TCP from an internal network to port 80 on any host, and a corresponding rule permitting TCP from any host on port 80 back to the internal network. This model cannot distinguish a legitimate HTTP response from an unsolicited incoming connection attempt, creating a larger attack surface. While stateless filtering is computationally cheaper and thus persists in high-throughput core routing (e.g., basic ACLs on Cisco IOS) or specific DDoS mitigation layers, its inherent limitations in security and administrative overhead have relegated it to niche roles.

In comparison, a stateful firewall operates at the network and transport layers but maintains a dynamic state table, often implemented within the kernel's connection tracking subsystem (`conntrack` in Linux, `pfstate` in OpenBSD). This table holds entries for each active session (e.g., source/destination IP, source/destination port, and protocol) and the TCP state (e.g., SYN_SENT, ESTABLISHED, and FIN_WAIT). For a TCP handshake, the firewall inspects the initial SYN packet, creates a state, and then validates the returning SYN-ACK against that state before permitting it. This allows for a fundamental rule simplification: a single `pass out` rule for an outgoing connection implicitly creates a temporary, dynamic `pass in` rule for the return traffic. Stateful inspection is the de facto standard in modern firewalls like PF (where `keep state` is the default on `pass` rules) and nftables (which leverages the `ct` expression for state matching).

#### Traffic Shaping

Traffic shaping is the active control of network traffic characteristics to enforce QoS policies, primarily implemented through queuing disciplines (qdiscs) and schedulers that manage packet buffers on egress interfaces. The core algorithmic model is the token bucket filter, which defines a bucket that fills with tokens at a specified rate (the committed information rate, or CIR) up to a defined burst capacity. Each packet requires a token of size proportional to its length to be transmitted; if the bucket is empty, the packet is delayed in a queue rather than immediately dropped (which would be policing). This mechanism smooths traffic bursts and enforces bandwidth ceilings.

**Firewall Selection Guide**

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

Popular open source NIDS (Network IDS) and HIDS (Host IDS) include Suricata, Snort, Wazuh, OSSEC, Fail2Ban, Zeek (formerly Bro), Security Onion, and OpenWIPS-NG.

Technology focus: Suricata and Zeek (Bro).

#### IDS/IPS key features

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

**IDS/IPS Selection Guide**

| Your Primary Need                                                 | Recommended Tool(s) | Key Reason                                                                      |
| ----------------------------------------------------------------- | ------------------- | ------------------------------------------------------------------------------- |
| **High-speed network intrusion detection/prevention (NIDS/NIPS)** | **Suricata**        | Multi-threaded, high performance, and compatible with Snort rules.              |
| **A lightweight, well-known NIDS for smaller networks**           | **Snort**           | The industry standard for decades, with extensive community support.            |
| **Deep network traffic analysis and forensics**                   | **Zeek (Bro)**      | Generates rich, structured logs of network protocols for behavioral analysis.   |
| **Host-based monitoring (HIDS) and compliance**                   | **Wazuh**           | Combines log analysis, FIM, vulnerability detection, and a central dashboard.   |
| **A lightweight HIDS for servers with active response**           | **OSSEC**           | Lightweight, efficient, and can trigger actions like blocking IPs.              |
| **Protection against brute-force attacks on services**            | **Fail2Ban**        | Scans logs and automatically blocks malicious IPs via the local firewall.       |
| **An all-in-one distributed security monitoring platform**        | **Security Onion**  | Bundles Suricata, Zeek, Wazuh, and Elasticsearch for a complete SOC experience. |

**Summary**

* **For Networks**: **Suricata** (best performance), **Snort** (legacy), **Zeek** (deep analysis).
* **For Hosts**: **Wazuh** (full SIEM), **OSSEC** (lightweight), **Fail2Ban** (log-based).
* **For SOCs**: **Security Onion** (all-in-one).
* **For Wi-Fi**: **OpenWIPS-NG** (specialized).

***

### SIEM/EDR

Popular open source SIEM/EDR (Security Information and Event Management/Endpoint Detection and Response) technologies include Wazuh, TheHive, Zeek, OSSEC, Suricata, and Velociraptor.

Technology focus: Wazuh (SIEM/XDR).

#### SIEM/EDR key features

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

**SIEM/EDR Selection Guide**

| Your Primary Need                                         | Recommended Tool(s)      | Key Reason                                                                                 |
| --------------------------------------------------------- | ------------------------ | ------------------------------------------------------------------------------------------ |
| **A unified SIEM with HIDS, compliance, and a dashboard** | **Wazuh**                | All-in-one open-source SIEM/XDR platform with strong integration capabilities.             |
| **Endpoint hunting, forensics, and live response**        | **Velociraptor**         | Powerful query language (VQL) for deep investigation and artifact collection on endpoints. |
| **Collaborative incident response and case management**   | **TheHive**              | Manages security incidents, integrates with MISP, and streamlines SOC workflows.           |
| **To feed network traffic logs into your SIEM**           | **Zeek** or **Suricata** | Both generate structured logs (e.g., EVE JSON) that can be ingested by SIEMs like Wazuh.   |

**Summary**

* **SIEM**: **Wazuh** (best all-in-one), **OSSEC** (lightweight HIDS).
* **EDR**: **Velociraptor** (advanced forensics), **Wazuh** (basic endpoint protection).
* **Network Analysis**: **Zeek** (deep inspection), **Suricata** (real-time IPS).
* **Incident Response**: **TheHive** (case management).

***

### Packet analyzers

Popular open source packet analyzers include Wireshark, tcpdump, Zeek, Snort, and Arkime.

Technology focus: Wireshark and tcpdump.

#### Packet analyzers key features

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

**Packet Analyzers Selection Guide**

| Your Primary Need                                                 | Recommended Tool(s) | Key Reason                                                                                  |
| ----------------------------------------------------------------- | ------------------- | ------------------------------------------------------------------------------------------- |
| **Deep, interactive protocol analysis with a GUI**                | **Wireshark**       | The definitive tool for deep packet inspection, decryption, and visualization.              |
| **Quick, scriptable packet capture from the command line**        | **tcpdump**         | Lightweight, ubiquitous, and perfect for capturing traffic on servers or for automation.    |
| **Behavioral analysis and structured logging of network traffic** | **Zeek (Bro)**      | Doesn't inspect packets live but generates comprehensive protocol logs for forensic review. |
| **Large-scale, indexed packet capture and retention**             | **Arkime**          | Designed for storing and quickly searching PCAPs across high-traffic networks.              |

**Summary**

* **For deep analysis**: **Wireshark** (GUI) or **tcpdump** (CLI).
* **For traffic logging**: **Zeek** (creates structured logs).
* **For security monitoring**: **Snort** (NIDS mode).
* **For large-scale PCAP storage**: **Arkime** (web-based).

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

**Stateful Firewalls:** Open-source examples include iptables/nftables (Linux), PF (BSD), and OPNsense.
* **Use stateful firewalls** when you need **stronger security**, session awareness, and protection against modern threats.
* **Use stateless firewalls** for **raw speed** or when dealing with simple, static filtering.

**Firewall Roots:** Linux uses Netfilter (iptables/nftables), BSD uses PF/ipfw, Windows uses WFP.

**WAFs:** Can be host-based (ModSecurity) or network-based (Cloudflare WAF). Host WAF: Protects a single service (e.g., one NGINX instance). Network WAF: Protects all traffic before it reaches servers (e.g., a reverse proxy).

### References

Bejtlich, R. (2013). _The practice of network security monitoring: Understanding incident detection and response_. No Starch Press.

Chapple, M., Seidl, D., & Stewart, J. M. (2022). _CISSP (ISC)2 certified information systems security professional official study guide_ (9th ed.). Sybex.

Sanders, C. (2017). _Practical packet analysis: Using Wireshark to solve real-world network problems_ (3rd ed.). No Starch Press.