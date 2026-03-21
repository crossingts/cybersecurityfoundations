---
description: This section focuses on major open source defensive cybersecurity tools used for firewalls, IDS/IPS, and SIEM/EDR
---

# Defensive cybersecurity technologies

## Learning objectives

* Become familiar with popular open source host and network firewalls, their key features, and their common use cases
* Understand the difference between packet-filtering firewalls and Web Application Firewalls (WAFs)
* Become familiar with popular open source host and network IDS, their key features, and their common use cases
* Become familiar with popular open source security event management technologies (SIEM/EDR), their key features, and their common use cases

This section explores major defensive cybersecurity technologies, including firewalls, IDS/IPS, and SIEM/EDR (Security Information and Event Management/Endpoint Detection and Response). The discussion focuses on popular open-source tools used to implement these technologies, exploring their key features and deployment use cases. Key categories of defensive cybersecurity technologies discussed include host and network firewalls (e.g., UFW, iptables, nftables, PF, OPNsense, and pfSense), IDS/IPS (e.g., Suricata and Snort), and network security monitoring/SIEM (e.g., Wazuh and OSSEC). This discussion categorizes tools by their primary function, but their real-world value often lies in how they are integrated into a broader security architecture. Many open source security tools have overlapping capabilities and can span multiple functional categories. A tool primarily classified as a Network Intrusion Detection System (NIDS), like Suricata, might also provide critical log data for a Security Information and Event Management (SIEM) system. 

## Topics covered in this section

* **Firewalls**
* **IDS/IPS**
* **SIEM/EDR**

### Firewalls

Popular open source host and network firewalls include UFW (Uncomplicated Firewall), iptables, nftables, PF (pfilter or packet filter), ipfw, OPNsense, and pfSense (Community Edition). Key firewall concepts discussed in this section include packet filtering firewalls, stateful vs stateless firewalls, proxy firewalls, Web Application Firewalls (WAFs), and Next-Generation Firewalls (NGFWs). 

At its most basic, a firewall is a gatekeeper for network traffic. The simplest and oldest type is the packet filtering firewall. Packet-filtering firewalls operate at the network level (Layers 3/4). They allow network administrators to define rules for allowing, blocking, or modifying traffic based on IPs, ports, and protocols. Packet‑filtering firewalls (stateless) can be contrasted with stateful inspection firewalls, while application-level gateways (proxy firewalls) and Next-Generation Firewalls (NGFWs) build on stateful inspection by adding application‑layer awareness.

A critical evolution in firewall technology was the shift from stateless to stateful inspection. A stateless firewall deployed via ACLs (access control lists) treats each network packet in isolation, with no memory of previous packets. A rule like "allow TCP port 80" would permit all traffic to that port, regardless of whether it is a legitimate new connection or a random, malicious packet. 

A stateful firewall builds on the stateless model by maintaining a state table that tracks active connections. When a packet arrives, the firewall checks not only its header fields (IPs, ports, protocol) but also whether it matches an existing session—for example, a response to an outbound TCP SYN. If the packet belongs to an allowed, established connection, it is automatically permitted without requiring explicit inbound rules. This approach eliminates the need for separate rules to allow return traffic, reduces the attack surface, and prevents many spoofing-based evasions that stateless filters cannot detect. 

Proxy firewalls operate as an intermediary between two end systems. Instead of allowing direct communication, the proxy firewall establishes two separate connections: one from the client to the proxy and another from the proxy to the server. This allows it to perform deep inspection of the application-layer traffic (like HTTP or FTP), filter specific content, and hide the internal client's IP address, providing a high level of security at the cost of increased latency and processing overhead.

Web Application Firewalls (WAFs) take the proxy concept one step further by focusing exclusively on HTTP/HTTPS traffic. Whereas a general proxy firewall might handle FTP, SMTP, or other application protocols, a WAF specializes in understanding the nuances of web requests—parsing URLs, inspecting parameters, and detecting attack patterns like SQL injection or cross‑site scripting. By acting as a reverse proxy or inline filter, a WAF protects web applications from application‑layer exploits that traditional network firewalls cannot see.

NGFWs represent the modern evolution of firewall technologies, incorporating the capabilities of all previous types and adding advanced security integrations. NGFWs can perform stateful and Application layer packet filtering, in addition to more advanced inspection capabilities such as Deep Packet Inspection (DPI) and Intrusion Prevention Systems (IPS).

#### Packet filtering firewalls

The most fundamental type of packet filters are ACLs. There are several variations of ACLs.

**1. Standard ACLs**

This is the simplest form of a stateless firewall filter. It makes filtering decisions based **only on the source IP address** of the packet.

- **How it works:** It examines the source address field in the IP packet header. If the address matches a deny entry, the packet is dropped. If it matches a permit entry, it's forwarded.
- **Where it's used:** Typically placed close to the _destination_ network to minimize processing overhead. Because it only filters on the source, it's less precise.
- **Example Logic:** `deny 192.168.1.0 0.0.0.255` (Block all traffic coming from the 192.168.1.0/24 network).

**2. Extended ACLs**

This is the more common and powerful form of a stateless ACL. It makes filtering decisions based on a combination of several fields in the packet header, including:

- Source IP address
- Destination IP address
- IP Protocol (e.g., TCP, UDP, ICMP)
- Source and Destination Port Numbers (for TCP/UDP)
- Protocol-specific flags (e.g., TCP ACK bit)
- **How it works:** It performs a deeper inspection of Layers 3 and 4 headers. This allows for very granular control.
- **Where it's used:** Typically placed close to the _source_ network to prevent unwanted traffic from traversing the network in the first place.
- **Example Logic:** `deny tcp 192.168.1.0 0.0.0.255 any eq 80` (Block traffic from the 192.168.1.0/24 network destined to any web server on port 80).

**3. VLAN ACLs (VACLs)**

VACLs are a specific type of stateless filter applied to traffic _within a VLAN_ (Virtual Local Area Network), rather than traffic passing between VLANs (which is handled by a router ACL). They operate at the switch level.

- **How it works:** They filter all packets bridged within a VLAN. You can filter based on Layer 2 (MAC addresses, Ethernet type) and Layer 3/4 information.
- **Why it's distinct:** It controls traffic that never leaves the switch, applying security even within the same broadcast domain.

**4. Port ACLs (PACLs)**

Similar to VACLs, Port ACLs are applied directly to a specific physical or logical switch port. They filter all traffic entering or leaving that single port.

- **How it works:** You can attach an ACL (standard or extended) to a Layer 2 interface to filter traffic coming in from a specific host or device.
- **Why it's distinct:** This provides security at the network edge, right where the device connects. For example, you could apply a PACL to a port connected to a public Wi-Fi hotspot to only allow HTTP/HTTPS traffic and block everything else.

**5. Stateless Firewall Context in Virtual Switches (vACLs)**

In virtualized environments (like VMware vSphere, Microsoft Hyper-V), the virtual switch can implement stateless packet filtering rules, often called Virtual ACLs (vACLs).

- **How it works:** As traffic passes between virtual machines (VMs) on the same physical host, the virtual switch intercepts it and applies stateless filtering rules defined in the VM's security policy or on the virtual port.
- **Why it's distinct:** This shifts security enforcement from a physical hardware appliance into the hypervisor software.

**6. Stateless NAT (Network Address Translation)**

While not a firewall in the classic sense, Stateless NAT is a related technology that operates on a per-packet basis without maintaining a state table.

- **How it works:** A one-to-one mapping between a private IP and a public IP is statically configured (e.g., 1:1 NAT). The router/firewall translates the addresses in the header for every packet, regardless of context.
- **The Connection:** It contrasts with Stateful NAT (often called NAPT or PAT), which _does_ maintain a state table to track hundreds of connections from a single public IP.

**Firewall Technologies and Their Packet‑Filtering Foundations**

iptables, nftables, PF, and ipfw are core packet‑filtering engines that operate at Layers 3 and 4. UFW is a front‑end that simplifies iptables/nftables management. OPNsense and pfSense (CE) are full firewall platforms built on PF; they add stateful inspection, a web interface, and additional security services while relying on PF for packet filtering.

**Firewall Technologies and Their Packet‑Filtering Foundations (Summary Table)**

The following table maps common firewall implementations to their underlying systems and typical layers of operation.

| Firewall / Platform                  | Underlying System   | OS Family              | Layers             | Notes                                                   |
| ------------------------------------ | ------------------- | ---------------------- | ------------------ | ------------------------------------------------------- |
| **iptables**                         | Netfilter           | Linux                  | L3/L4              | Legacy, replaced by nftables.                           |
| **nftables**                         | Netfilter           | Linux                  | L3/L4              | Unifies IPv4/IPv6, improved syntax.                     |
| **UFW**                              | iptables / nftables | Linux                  | L3/L4              | Front‑end for simplifying rule management.              |
| **PF (Packet Filter)**               | PF (in‑kernel)      | OpenBSD, FreeBSD, etc. | L3/L4              | Modern BSD firewall; supports stateful inspection.      |
| **ipfw**                             | ipfw (in‑kernel)    | FreeBSD, macOS         | L3/L4              | Legacy; still available but PF is preferred on FreeBSD. |
| **Windows Filtering Platform (WFP)** | WFP (in‑kernel)     | Windows                | L3–L7 (extensible) | Native framework; used by Windows Defender Firewall.    |
| **OPNsense**                         | PF (FreeBSD)        | FreeBSD                | L3–L7              | Full security platform; adds web UI, IPS, proxy, etc.   |
| **pfSense (CE)**                     | PF (FreeBSD)        | FreeBSD                | L3–L7              | Full security platform; adds web UI, VPN, proxy, etc.   |

BSD-based firewalls use networking and security tools native to BSD systems. BSD stands for Berkeley Software Distribution, a family of **Unix-like operating systems** derived from the original Berkeley Unix (developed at UC Berkeley).

#### Stateless vs stateful firewalls

A stateless firewall performs packet filtering based solely on the static rule set and the headers of the individual packet in question, with no memory of prior packets. This necessitates explicit, bidirectional rules for any permitted communication. For example, to allow outbound HTTP, you would need one rule permitting TCP from an internal network to port 80 on any host, and a corresponding rule permitting TCP from any host on port 80 back to the internal network. This model cannot distinguish a legitimate HTTP response from an unsolicited incoming connection attempt, creating a larger attack surface. While stateless filtering is computationally cheaper and thus persists in high-throughput core routing (e.g., basic ACLs on Cisco IOS) or specific DDoS mitigation layers, its inherent limitations in security and administrative overhead have relegated it to niche roles.

In comparison, a stateful firewall maintains a dynamic state table, often implemented within the kernel's connection tracking subsystem (`conntrack` in Linux, `pfstate` in OpenBSD). This table holds entries for each active session (e.g., source/destination IP, source/destination port, and protocol) and the TCP state (e.g., SYN_SENT, ESTABLISHED, and FIN_WAIT). For a TCP handshake, the firewall inspects the initial SYN packet, creates a state, and then validates the returning SYN-ACK against that state before permitting it. This allows for a fundamental rule simplification: a single `pass out` rule for an outgoing connection implicitly creates a temporary, dynamic `pass in` rule for the return traffic. Stateful inspection is the de facto standard in modern firewalls like PF (where `keep state` is the default on `pass` rules) and nftables (which leverages the `ct` expression for state matching).

**Stateless vs Stateful Firewalls Diagram**

```
Stateless Firewall:
  [Packet] → [Check Rules] → Allow/Drop

Stateful Firewall:
  [Packet] → [Check State Table] → [Update State] → Allow/Drop
          ↳ (e.g., "Is this a reply to an existing SSH session?")
```

A stateful firewall can tell the difference between an outgoing request to a web server and the returning traffic, and it can automatically allow the return traffic for an established session. This is a fundamental security improvement.

While all modern firewalls are used in a stateful manner, their implementation differs. Some, like nftables, PF, ipfw, OPNsense, and pfSense are inherently stateful, with connection tracking as a core feature. Others like the Linux iptables framework achieve statefulness through the addition of the `conntrack` module and specific rules, which is considered a standard practice (statefulness comes from its connection tracking module, not the `iptables` command itself). Tools like UFW configure their underlying engines to be stateful by default.

**How Statefulness is Implemented in Common Tools**

| Firewall               | Stateful?            | Key Detail & Example                                                                                                                |
| ---------------------- | -------------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| **nftables, PF, ipfw** | **Inherently**       | Stateful tracking is a built-in, core feature. (e.g., PF uses `pass in proto tcp to port 22 keep state`)                            |
| **OPNsense / pfSense** | **Inherently**       | As distributions built on PF, statefulness is a fundamental, non-optional feature.                                                  |
| **iptables**           | **By Configuration** | Relies on the `conntrack` module. A rule like `-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT` enables statefulness. |
| **UFW**                | **By Default**       | As a front-end, it configures the underlying engine (iptables/nftables) to be stateful by default for ease of use.                  |

**Common States in `conntrack`**

| State           | Meaning                                                                          |
| --------------- | -------------------------------------------------------------------------------- |
| **NEW**         | First packet of a new connection (e.g., TCP SYN).                                |
| **ESTABLISHED** | Packets belonging to an already-seen connection (e.g., TCP handshake completed). |
| **RELATED**     | Packets related to an existing connection (e.g., FTP data connection).           |
| **INVALID**     | Malformed or suspicious packets (e.g., TCP RST without prior connection).        |

**Stateless vs. Stateful Firewalls: Core Features**

| Feature               | Stateless Firewall (e.g., ACLs)                                  | Stateful Firewall                                                                                   |
| --------------------- | ---------------------------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| **Packet Evaluation** | Each packet in isolation.                                        | Part of a larger connection or session.                                                             |
| **Decision Factors**  | Header info (IP, Port, Protocol).                                | Header info + state table (past packets).                                                           |
| **Configuration**     | Requires two rules (inbound + outbound) to allow a conversation. | Typically requires one rule to allow a conversation; the return traffic is automatically permitted. |
| **Performance**       | Very fast, low resource usage.                                   | Can be slower due to the overhead of maintaining the state table.                                   |
| **Security**          | Vulnerable to certain evasions (e.g., fragmented packets).       | More secure as it understands the context of the traffic.                                           |

**Stateless vs. Stateful Firewalls: General Features**

| Feature                               | Stateless Firewall                                                                                                 | Stateful Firewall                                                                                                                                                              |
| ------------------------------------- | ------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Context-Aware Traffic Filtering**   | **None.** Examines each packet in isolation with no memory of previous packets.                                    | **Full.** Tracks the state of active connections (e.g., ESTABLISHED, RELATED) to make dynamic decisions.                                                                       |
| **Security Against Attacks**          | **Limited.** Cannot detect or block protocol-based attacks like TCP SYN floods or session hijacking.               | **Advanced.** Can identify and block malicious traffic that abuses protocol states and unauthorized packets not part of a valid session.                                       |
| **Protection Against Spoofing & DoS** | **Basic.** Can only block based on static IP/port rules, offering minimal protection against spoofing or flooding. | **Robust.** Recognizes abnormal traffic patterns (e.g., unexpected RST packets) and can enforce rate limiting per connection.                                                  |
| **Granular Control Over Sessions**    | **Static.** Rules are fixed; cannot dynamically adjust for multi-stage protocols.                                  | **Dynamic.** Can enforce policies based on connection state (e.g., allow only "established" or "related" traffic) and temporarily open ports for related sessions (e.g., FTP). |
| **Support of Complex Protocols**      | **Poor.** Cannot handle protocols like FTP, SIP, or VoIP that require dynamic port negotiation.                    | **Excellent.** Tracks control sessions to automatically manage the data channels for complex protocols.                                                                        |
| **Performance**                       | **Lower resource usage** per packet, making it suitable for very high-speed, simple filtering tasks.               | **Higher initial resource overhead** for connection tracking, but more efficient for managing traffic within established sessions.                                             |

#### Proxy firewalls

A proxy firewall is the most secure type of firewall, acting as a dedicated gateway or intermediary between an internal network and the internet. Unlike traditional firewalls, it operates at the Application layer, filtering messages for specific protocols like HTTP, FTP, and SMTP. Its core security principle is preventing direct contact between internal systems and external servers; every connection is brokered by the proxy, which has its own IP address, effectively isolating the internal network. Instead of simply forwarding packets, the proxy firewall terminates client connections and initiates new ones to the server. This allows the proxy firewall to inspect the actual content of the traffic, such as specific HTTP commands, SQL queries or malicious URLs, which a Layer 3/4 packet filter is blind to.

The high level of security is achieved through deep inspection techniques. The proxy firewall doesn't just look at packet headers; it performs DPI to analyze the actual contents of every packet flowing in and out. This allows it to assess threats, detect malware, validate data, and enforce corporate security policies at the application level. By centralizing all application activity through a single point, it provides a comprehensive view and control over network traffic that simpler firewalls cannot.

The connection process illustrates this intermediary role. When a user requests an external resource, their computer connects only to the proxy, not the final destination. The proxy then establishes a separate, independent connection to the external server on the user's behalf. It continuously analyzes all communication passing through these two connections, ensuring compliance and security before any data is relayed. This meticulous, application-aware process makes proxy firewalls extremely effective at preventing unauthorized access and advanced cyberattacks, though it can impact network speed and functionality due to the intensive inspection.

**Proxy Firewalls: Form Factors**

Proxy firewalls (also called application‑level gateways) can be deployed in multiple ways:

1. **Hardware Appliances** – Purpose‑built physical devices that combine proxy functions with other firewall features. This is the traditional enterprise model (e.g., older Check Point, Forcepoint, or Blue Coat appliances).
2. **Software / Virtual Appliances** – Many modern proxy firewalls are delivered as software that runs on standard servers or as virtual machines (e.g., Palo Alto Networks VM‑Series, FortiGate‑VM, or open‑source options like Squid combined with pfSense). They are common in virtualized data centers and cloud environments.
3. **Integrated in Next‑Generation Firewalls (NGFW)** – Today’s NGFW often include application‑level proxying (transparent or explicit) as a feature set, blending stateful inspection with application‑aware proxy capabilities.

#### Web Application Firewalls (WAFs)

A Web Application Firewall (WAF) is a specialized security tool designed to protect web applications and APIs by inspecting Hypertext Transfer Protocol (HTTP/HTTPS) traffic. Its primary focus is on the application layer (Layer 7) of the OSI model, where it performs DPI to understand the actual content and intent of web requests. This allows it to identify and block sophisticated attack patterns that target application vulnerabilities, such as SQL Injection (SQLi), cross-site scripting (XSS), and other zero-day threats, before they reach the web server or users.

In contrast, a traditional network firewall operates at a broader level, typically controlling traffic between network segments based on IP addresses, ports, and protocols (Layers 3 and 4). Its main function is to establish a barrier between a trusted internal network and untrusted external networks, like the internet, by enforcing access control policies. It acts as a gatekeeper for all network traffic but lacks the granularity to inspect the contents of web traffic for application-specific attacks.

The need for a WAF has grown with the adoption of modern IT practices, including cloud services, SaaS, and BYOD policies, which expand the attack surface for web applications. While a network firewall is essential for foundational network perimeter security, it is not designed to understand the structure of web communications and therefore cannot defend against attacks embedded within legitimate web traffic. Consequently, network firewalls and WAFs are not replacements for each other but are complementary, layered defenses.

In summary, a network firewall secures the network infrastructure by controlling which traffic can enter or leave, whereas a WAF specifically secures business-critical web applications by analyzing the behavior and payload of web requests. 

Many WAFs are reverse proxies (e.g., ModSecurity running in a reverse‑proxy mode, cloud‑based WAFs like Cloudflare). However, not all proxy firewalls are WAFs—a generic proxy firewall can handle FTP, SMTP, etc., while a WAF is narrowly focused on HTTP/HTTPS.

For comprehensive protection, organizations require both: the network firewall to guard the network perimeter and the WAF to protect the applications exposed to the internet from targeted layer-7 attacks.

| Type                  | Example Tools                         | Deployment                                                                                |
| --------------------- | ------------------------------------- | ----------------------------------------------------------------------------------------- |
| **Host-Based WAF**    | ModSecurity (Apache/Nginx plugin)     | Runs directly on the web server itself (e.g., as a module).                               |
| **Network-Based WAF** | Cloudflare WAF, HAProxy + ModSecurity | Deployed as a standalone appliance or cloud service, protecting multiple backend servers. |

#### Next-Generation Firewalls (NGFWs)  

The modern evolution is the Next-Generation Firewall (NGFW), which incorporates and expands upon all previous capabilities. NGFWs provide a more comprehensive, intelligent, and application-aware security posture for modern networks. NGFWs can perform stateful and Application layer packet filtering, in addition to more advanced inspection capabilities such as:

- **Deep Packet Inspection (DPI) & Application Awareness:** Unlike basic firewalls that only inspect packet headers, DPI examines the actual _data_ within the packet payload. This allows the NGFW to identify and control traffic based on the specific application (e.g., Facebook, Spotify) or service, regardless of the port it uses, and to classify and block malicious content.
- **Integrated Intrusion Prevention System (IPS):** This feature actively scans for, blocks, and prevents known attack patterns, exploits, and vulnerabilities within the network traffic flow in real-time.
- **User & Group Identity Integration:** Rules can be created to allow or block traffic based on a user's or group's identity (e.g., from Active Directory), moving beyond simple IP address-based filtering for more precise access control.
- **Threat Intelligence Feeds:** NGFWs leverage dynamic, cloud-based threat intelligence to automatically block traffic to and from known malicious IP addresses, domains, and botnets.

The key differences between a traditional packet filtering firewall and an NGFW can be summarized as follows:

|Feature|Packet Filtering Firewall|Next-Generation Firewall (NGFW)|
|---|---|---|
|**Primary OSI Layer**|**Layers 3 & 4** (Network & Transport)|**Layers 3-7** (Network to Application)|
|**Decision Basis**|IP Address, Port, Protocol|IP, Port, Protocol, **Application, User, Content**|
|**Connection Awareness**|Stateless or Stateful|**Stateful** by default|
|**Traffic Inspection**|Header-only|**Deep Packet Inspection (DPI)** of payload|
|**Additional Features**|Basic NAT, basic logging|**IPS, Anti-Virus, Threat Intelligence, Identity Awareness**|

UFW, iptables, nftables, PF, ipfw, OPNsense, and pfSense (CE) all have their foundation in packet filtering, and they can all be considered stateful packet filtering firewalls, but some have evolved into more sophisticated frameworks. For example, pfSense and OPNsense are complete, GUI-based firewall distributions (operating systems). They use PF (Packet Filter) as their core packet filtering engine. However, the systems themselves are full-featured NGFWs) because they include many features beyond simple packet filtering.

#### Firewalls key features

**1. UFW (Uncomplicated Firewall)**

* **Type**: Host-based firewall (frontend for `iptables`/`nftables`).
* **Platform**: Linux (Ubuntu default).
* **Key Features**:
  * Simplified CLI for managing firewall rules (easier than raw `iptables`).
  * Supports IPv4 and IPv6.
  * Predefined application profiles (e.g., allow SSH, HTTP).
  * Integrates with `iptables` or `nftables` as the backend.
  * Designed for simplicity, ideal for desktop users and beginners.
* **Use Case:** Best for Linux beginners who need a simple, no-fuss host firewall.

**2. iptables**

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

**3. nftables**

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

**4. PF (Packet Filter) / pfilter**

* **Type**: Host/network firewall.
* **Platform**: BSD (OpenBSD default, also FreeBSD, macOS).
* **Key Features**:
  * Stateful firewall with advanced features (NAT, QoS, traffic shaping).
  * Clean, readable rule syntax (e.g., `pass in on eth0 proto tcp to port 22`).
  * Handles high traffic efficiently (better than iptables in some cases).
  * Supports logging, SYN proxy, and scrubbing.
  * Integrated in OpenBSD (security-focused).
* **Use Case:** Powerful BSD firewall with clean syntax for servers/networks.
More advanced than iptables, used in BSD-based firewalls. Originally from OpenBSD, now also in FreeBSD and others, BSD license. CLI based macOS built-in Unix firewall.

**5. ipfw**

- **Type**: Host/network firewall.
- **Platform**: FreeBSD (legacy), macOS (legacy, pre-macOS Sierra).
- **Key Features**:
   - Traditional, stateful packet filter for BSD-based systems.
   - Uses a sequential rule numbering system and a consistent, predictable syntax.
   - Integrated with `dummynet` for advanced traffic shaping, bandwidth management, and network emulation.
   - Provides a robust set of features for packet filtering, NAT, and logging.
   - Largely superseded by PF (`pfilter`) on modern FreeBSD and macOS.
- **Use Case:** Managing firewalls on legacy FreeBSD systems or older macOS versions, or for leveraging its integrated `dummynet` traffic-shaping capabilities.
Older BSD firewall, mostly replaced by PF. Found in FreeBSD (and older macOS versions), BSD license. OS/platform: FreeBSD, macOS (legacy)

**6. OPNsense**

* **Type**: Network firewall/router (open-source fork of pfSense).
* **Platform**: FreeBSD-based (dedicated appliance/VM).
* **Key Features**:
  * Web GUI for easy management.
  * Supports VPN (OpenVPN, WireGuard), IDS/IPS (Suricata), and traffic shaping.
  * Regular updates with a focus on security and usability.
  * Plugins for extended functionality (e.g., Nginx, CrowdSec).
  * Community and commercial support options.
* **Use Case:** Feature-rich open-source firewall with frequent updates for SMBs/enterprises.

**7. pfSense (Community Edition)**

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

All the following firewalls are open source, stateful, perform NAT, and have IPv6 routing capability.

| Firewall         | Type         | Platform                | GUI       | Ease of Use | VPN Support       | IDS/IPS      | Traffic Shaping (QoS) |
| ---------------- | ------------ | ----------------------- | --------- | ----------- | ----------------- | ------------ | --------------------- |
| **UFW**          | Host         | Linux                   | No (CLI)  | Very Easy   | Limited           | No           | No                    |
| **iptables**     | Host/Network | Linux                   | No (CLI)  | Complex     | Manual            | No (add-ons) | Yes                   |
| **nftables**     | Host/Network | Linux                   | No (CLI)  | Moderate    | Manual            | No (add-ons) | Yes                   |
| **ipfw**         | Host/Network | FreeBSD, macOS (legacy) | No (CLI)  | Complex     | Manual            | No (add-ons) | Yes (via dummynet)    |
| **PF (pfilter)** | Host/Network | OpenBSD, FreeBSD, macOS | No (CLI)  | Moderate    | Manual            | No (add-ons) | Yes                   |
| **OPNsense**     | Network      | FreeBSD                 | Yes (Web) | Easy        | OpenVPN/WireGuard | Suricata     | Yes                   |
| **pfSense CE**   | Network      | FreeBSD                 | Yes (Web) | Easy        | OpenVPN/IPsec     | Snort        | Yes                   |

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

### Key takeaways

* Popular open source host-based firewalls include nftables and pf.
* Popular open source network-based firewalls include OPNsense and pfSense (CE).
* Packet-filtering firewall technologies such as iptables and pfilter (PF) operate at the network level (Layer 3/4).
* Firewall Roots: Linux uses Netfilter (iptables/nftables), BSD uses PF/ipfw, Windows uses WFP.
* Use stateful firewalls when you need stronger security, session awareness, and protection against modern threats.
* Use stateless firewalls for raw speed or when dealing with simple, static filtering.
* WAFs operate at the Application level (L7) and can be host-based (ModSecurity) or network-based (Cloudflare WAF). Host WAF: Protects a single service (e.g., one NGINX instance). Network WAF: Protects all traffic before it reaches servers (e.g., a reverse proxy).
* Popular open source HIDS include Wazuh and OSSEC.
* Popular open source NIDS include Suricata and Snort.
* Popular open source SIEM include Wazuh and TheHive.

### References

Bejtlich, R. (2013). _The practice of network security monitoring: Understanding incident detection and response_. No Starch Press.

Chapple, M., Seidl, D., & Stewart, J. M. (2022). _CISSP (ISC)2 certified information systems security professional official study guide_ (9th ed.). Sybex.
