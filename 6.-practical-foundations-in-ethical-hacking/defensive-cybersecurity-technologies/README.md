---
description: This section explores major open source firewall, IDS/IPS, and SIEM/EDR technologies, focusing on their key features and common use cases
---

# Defensive cybersecurity technologies

## Learning objectives

* Become familiar with popular open source host and network firewalls, their key features, and their common use cases
* Understand the difference between packet filtering firewalls and Web Application Firewalls (WAFs)
* Become familiar with popular open source host and network IDS, their key features, and their common use cases
* Become familiar with popular open source security event management technologies (SIEM/EDR), their key features, and their common use cases

This section explores major defensive cybersecurity technologies, including firewalls, IDS/IPS, and SIEM/EDR (Security Information and Event Management/Endpoint Detection and Response). The discussion focuses on popular open source tools used to implement these technologies, exploring their key features and deployment use cases. Key categories of defensive cybersecurity technologies discussed include host and network firewalls (e.g., UFW, iptables, nftables, PF, OPNsense, and pfSense), IDS/IPS (e.g., Suricata and Snort), and network security monitoring/SIEM (e.g., Wazuh and OSSEC). This discussion categorizes tools by their primary function, but their real-world value often lies in how they are integrated into a broader security architecture. Many open source security tools have overlapping capabilities and can span multiple functional categories. A tool primarily classified as a Network Intrusion Detection System (NIDS), like Suricata, might also provide critical log data for a Security Information and Event Management (SIEM) system. 

## Topics covered in this section

* **Firewalls**
* **IDS/IPS**
* **SIEM/EDR**

### Firewalls

Popular open source host and network firewalls include UFW (Uncomplicated Firewall), iptables, nftables, PF (Packet Filter), ipfw, OPNsense, and pfSense (Community Edition). Key firewall concepts discussed in this section include packet filtering firewalls, stateful vs stateless firewalls, proxy firewalls, Web Application Firewalls (WAFs), and Next-Generation Firewalls (NGFWs).

At its most basic, a firewall is a gatekeeper for network traffic. The simplest and oldest type is the packet filtering firewall. Packet filtering firewalls operate at the network level (Layers 3/4). They allow network administrators to define rules for allowing, blocking, or modifying traffic based on IPs, ports, and protocols. Packet‑filtering firewalls can be stateless or stateful, while proxy firewalls (application‑level gateways) and Next‑Generation Firewalls (NGFWs) build on stateful inspection by adding application‑layer awareness.

A critical evolution in firewall technology was the shift from stateless to stateful inspection. A stateless firewall deployed via ACLs (access control lists) treats each network packet in isolation, with no memory of previous packets. A rule like "allow TCP port 80" would permit all traffic to that port, regardless of whether it is a legitimate new connection or a random, malicious packet. A stateful firewall builds on the stateless model by maintaining a state table that tracks active connections. When a packet arrives, the firewall checks not only its header fields (IPs, ports, protocol) but also whether it matches an existing session—for example, a response to an outbound TCP SYN. If the packet belongs to an allowed, established connection, it is automatically permitted without requiring explicit inbound rules. This approach eliminates the need for separate rules to allow return traffic, reduces the attack surface, and prevents many spoofing-based evasions that stateless filters cannot detect. 

Proxy firewalls operate as an intermediary between two end systems. Instead of allowing direct communication, the proxy firewall establishes two separate connections: one from the client to the proxy and another from the proxy to the server. This allows it to perform deep inspection of the application-layer traffic (like HTTP or FTP), filter specific content, and hide the internal client's IP address, providing a high level of security at the cost of increased latency and processing overhead.

Web Application Firewalls (WAFs) take the proxy concept one step further by focusing exclusively on HTTP/HTTPS traffic. Whereas a general proxy firewall might handle FTP, SMTP, or other application protocols, a WAF specializes in understanding the nuances of web requests—parsing URLs, inspecting parameters, and detecting attack patterns like SQL injection or cross‑site scripting. By acting as a reverse proxy or inline filter, a WAF protects web applications from application‑layer exploits that traditional network firewalls cannot see.

NGFWs represent the modern evolution of firewall technologies, incorporating the capabilities of all previous types and adding advanced security integrations. NGFWs can perform stateful and Application layer packet filtering, in addition to more advanced inspection capabilities such as Deep Packet Inspection (DPI) and Intrusion Prevention Systems (IPS).

#### Stateless vs stateful firewalls

A stateless firewall treats each network packet in isolation, with no memory of previous packets. It examines packet headers (source/destination IP, port, protocol) against a static rule set and makes an allow/deny decision per packet. A rule like “allow TCP port 80” would permit all traffic to that port, regardless of whether it is a legitimate new connection or a random, malicious packet. Stateless filtering requires explicit, bidirectional rules for any permitted communication. For example, to allow outbound HTTP, you would need one rule permitting TCP from an internal network to port 80 on any host, and a corresponding rule permitting TCP from any host on port 80 back to the internal network. This model cannot distinguish a legitimate HTTP response from an unsolicited incoming connection attempt, creating a larger attack surface. While stateless filtering is computationally cheaper and thus persists in high‑throughput core routing (e.g., basic ACLs on Cisco IOS, where reflexive ACLs or the `established` keyword can add stateful behavior), its inherent limitations in security and administrative overhead have relegated it to niche roles.

In comparison, a stateful firewall maintains a dynamic state table, often implemented within the kernel’s connection tracking subsystem (`conntrack` in Linux, `pfstate` in OpenBSD). This table holds entries for each active session (e.g., source/destination IP, source/destination port, protocol) and the TCP state (e.g., SYN_SENT, ESTABLISHED, FIN_WAIT). For a TCP handshake, the firewall inspects the initial SYN packet, creates a state, and then validates the returning SYN‑ACK against that state before permitting it. This allows for a fundamental rule simplification: a single `pass out` rule for an outgoing connection implicitly creates a temporary, dynamic `pass in` rule for the return traffic. Stateful inspection is the de facto standard in modern firewalls like PF (where `keep state` is the default on `pass` rules) and nftables (which leverages the `ct` expression for state matching).

All firewall types beyond basic ACLs are stateful. "Stateful” is typically used for connection tracking at layers 3/4. Proxy firewalls and WAFs operate at higher layers but they still maintain session context (just not the same kind as a stateful packet filter). 

- **Basic ACLs** (standard/extended, VACLs, and PACLs) are stateless – they evaluate each packet in isolation with no connection tracking.
- **Stateful packet‑filtering firewalls** (PF, nftables, iptables with `conntrack`, etc.) maintain a connection table and are therefore stateful.
- **Proxy firewalls** – because they terminate the client connection and establish a separate connection to the server – inherently maintain session state. They are stateful at the application layer.
- **WAFs** – especially those deployed as reverse proxies or inline – track HTTP sessions, request/response pairs, and often maintain state (e.g., to enforce session integrity). 
- **NGFWs** – by definition – incorporate stateful inspection, deep packet inspection, and often IPS; they are stateful.

**Stateless vs Stateful Firewalls Core Features**

|Feature|Stateless Firewall|Stateful Firewall|
|---|---|---|
|Packet evaluation|Each packet in isolation.|Part of a larger connection or session.|
|Decision factors|Header info (IP, Port, Protocol).|Header info + state table (past packets).|
|Configuration|Requires two rules (inbound + outbound) to allow a conversation.|Typically requires one rule to allow a conversation; return traffic is automatically permitted.|
|Context‑aware filtering|None. Examines each packet in isolation.|Full. Tracks the state of active connections (e.g., ESTABLISHED, RELATED) to make dynamic decisions.|
|Security against attacks|Limited. Cannot detect or block protocol‑based attacks like TCP SYN floods or session hijacking.|Advanced. Can identify and block malicious traffic that abuses protocol states and unauthorized packets not part of a valid session.|
|Protection against spoofing & DoS|Basic. Can only block based on static IP/port rules, offering minimal protection against spoofing or flooding.|Robust. Recognizes abnormal traffic patterns (e.g., unexpected RST packets) and can enforce rate limiting per connection.|
|Granular control over sessions|Static. Rules are fixed; cannot dynamically adjust for multi‑stage protocols.|Dynamic. Can enforce policies based on connection state (e.g., allow only ESTABLISHED or RELATED traffic) and temporarily open ports for related sessions (e.g., FTP).|
|Support of complex protocols|Poor. Cannot handle protocols like FTP, SIP, or VoIP that require dynamic port negotiation.|Excellent. Tracks control sessions to automatically manage data channels for complex protocols.|
|Performance|Lower resource usage per packet, making it suitable for very high‑speed, simple filtering tasks.|Higher initial resource overhead for connection tracking, but more efficient for managing traffic within established sessions.|

#### ACL types (standard, extended, VLAN, port)

The most fundamental type of packet filters are ACLs (access control lists). There are several variations.

1. Standard ACLs – the simplest form of a stateless firewall filter. It makes filtering decisions based only on the source IP address of the packet. It examines the source address field in the IP packet header. If the address matches a deny entry, the packet is dropped. If it matches a permit entry, it is forwarded. Standard ACLs are typically placed close to the destination network to minimize processing overhead. Because it only filters on the source, it is less precise. Example logic: `deny 192.168.1.0 0.0.0.255` (block all traffic coming from the 192.168.1.0/24 network).
2. Extended ACLs – a more common and powerful form of a stateless ACL. It makes filtering decisions based on a combination of several fields in the packet header, including source IP, destination IP, IP protocol (e.g., TCP, UDP, ICMP), source and destination port numbers (for TCP/UDP), and protocol‑specific flags (e.g., TCP ACK bit). Extended ACLs perform a deeper inspection of Layers 3 and 4 headers, allowing very granular control. They are typically placed close to the source network to prevent unwanted traffic from traversing the network in the first place. Example logic: `deny tcp 192.168.1.0 0.0.0.255 any eq 80` (block traffic from the 192.168.1.0/24 network destined to any web server on port 80).
3. VLAN ACLs (VACLs) – a type of stateless filter applied to traffic within a VLAN, rather than traffic passing between VLANs (which is handled by a router ACL). They operate at the switch level, filtering all packets bridged within a VLAN. VACLs can filter based on Layer 2 (MAC addresses, Ethernet type) and Layer 3/4 information. This controls traffic that never leaves the switch, applying security even within the same broadcast domain.
4. Port ACLs (PACLs) – similar to VACLs, but applied directly to a specific physical or logical switch port. They filter all traffic entering or leaving that single port. A PACL (standard or extended) can be attached to a Layer 2 interface to filter traffic coming from a specific host or device, providing security at the network edge. For example, a PACL could be applied to a port connected to a public Wi‑Fi hotspot to allow only HTTP/HTTPS traffic and block everything else.
5. Stateless firewall context in virtual switches (vACLs) – in virtualized environments (like VMware vSphere, Microsoft Hyper‑V), the virtual switch can implement stateless packet filtering rules, often called virtual ACLs (vACLs). As traffic passes between virtual machines on the same physical host, the virtual switch intercepts it and applies stateless filtering rules defined in the VM’s security policy or on the virtual port. This shifts security enforcement from a physical hardware appliance into the hypervisor software.
6. Stateless NAT (Network Address Translation) – while not a firewall in the classic sense, stateless NAT operates on a per‑packet basis without maintaining a state table. A one‑to‑one mapping between a private IP and a public IP is statically configured (e.g., 1:1 NAT). The router or firewall translates the addresses in the header for every packet, regardless of context. This contrasts with stateful NAT (often called NAPT or PAT), which does maintain a state table to track hundreds of connections from a single public IP.

#### Stateful inspection: Implementation and connection states

While all modern firewalls are used in a stateful manner, their implementation differs. Some, like nftables, PF, ipfw, OPNsense, and pfSense are inherently stateful, with connection tracking as a core feature. Others, like the Linux iptables framework, achieve statefulness through the addition of the `conntrack` module and specific rules, which is considered a standard practice (statefulness comes from its connection tracking module, not the `iptables` command itself). Tools like UFW configure their underlying engines to be stateful by default.

**How Statefulness is Implemented in Common Tools**

| Firewall           | Stateful?        | Key Detail & Example                                                                                                                |
| ------------------ | ---------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| UFW                | By Default       | As a front‑end, it configures the underlying engine (iptables/nftables) to be stateful by default for ease of use.                  |
| iptables           | By Configuration | Relies on the `conntrack` module. A rule like `-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT` enables statefulness. |
| nftables, PF, ipfw | Inherently       | Stateful tracking is a built‑in, core feature. (e.g., PF uses `pass in proto tcp to port 22 keep state`)                            |
| OPNsense / pfSense | Inherently       | As distributions built on PF, statefulness is a fundamental, non‑optional feature.                                                  |

**Common States in Conntrack**

|State|Meaning|
|---|---|
|NEW|First packet of a new connection (e.g., TCP SYN).|
|ESTABLISHED|Packets belonging to an already‑seen connection (e.g., TCP handshake completed).|
|RELATED|Packets related to an existing connection (e.g., FTP data connection).|
|INVALID|Malformed or suspicious packets (e.g., TCP RST without prior connection).|

#### Proxy firewalls

A proxy firewall is the most secure type of firewall, acting as a dedicated gateway or intermediary between an internal network and the internet. Unlike traditional firewalls, it operates at the Application layer, filtering messages for specific protocols like HTTP, FTP, and SMTP. Its core security principle is preventing direct contact between internal systems and external servers; every connection is brokered by the proxy, which has its own IP address, effectively isolating the internal network. Instead of simply forwarding packets, the proxy firewall terminates client connections and initiates new ones to the server. This allows the proxy firewall to inspect the actual content of the traffic, such as specific HTTP commands, SQL queries, or malicious URLs, which a Layer 3/4 packet filter is blind to.

The high level of security is achieved through deep inspection techniques. The proxy firewall does not just look at packet headers; it performs deep packet inspection (DPI) to analyze the actual contents of every packet flowing in and out. This allows it to assess threats, detect malware, validate data, and enforce corporate security policies at the application level. By centralizing all application activity through a single point, it provides a comprehensive view and control over network traffic that simpler firewalls cannot.

The connection process illustrates this intermediary role. When a user requests an external resource, their computer connects only to the proxy, not the final destination. The proxy then establishes a separate, independent connection to the external server on the user’s behalf. The proxy continuously analyzes all communication passing through these two connections, ensuring compliance and security before any data is relayed. This meticulous, application‑aware process makes proxy firewalls extremely effective at preventing unauthorized access and advanced cyberattacks, though it can impact network speed and functionality due to the intensive inspection.

**Proxy Firewalls: Form Factors**

Proxy firewalls can be deployed in multiple ways:

1. Hardware appliances – purpose‑built physical devices that combine proxy functions with other firewall features. This is the traditional enterprise model (e.g., older Check Point, Forcepoint, or Blue Coat appliances).
2. Software/virtual appliances – many modern proxy firewalls are delivered as software that runs on standard servers or as virtual machines (e.g., Palo Alto Networks VM‑Series, FortiGate‑VM, or open‑source options like Squid combined with pfSense). They are common in virtualized data centers and cloud environments.
3. Integrated in Next‑Generation Firewalls (NGFW) – today’s NGFW often include application‑level proxying (transparent or explicit) as a feature set, blending stateful inspection with application‑aware proxy capabilities.

#### Web Application Firewalls (WAFs)

A Web Application Firewall (WAF) is a specialized security tool designed to protect web applications and APIs by inspecting HTTP/HTTPS traffic. Its primary focus is on the application layer (Layer 7) of the OSI model, where it performs deep packet inspection to understand the actual content and intent of web requests. This allows it to identify and block sophisticated attack patterns that target application vulnerabilities, such as SQL injection (SQLi) and cross‑site scripting (XSS), before they reach the web server or users.

In contrast, a traditional network firewall operates at a broader level, typically controlling traffic between network segments based on IP addresses, ports, and protocols (Layers 3 and 4). Its main function is to establish a barrier between a trusted internal network and untrusted external networks, like the internet, by enforcing access control policies. It acts as a gatekeeper for all network traffic but lacks the granularity to inspect the contents of web traffic for application‑specific attacks.

The need for a WAF has grown with the adoption of modern IT practices, including cloud services, SaaS, and BYOD policies, which expand the attack surface for web applications. While a network firewall is essential for foundational network perimeter security, it is not designed to understand the structure of web communications and therefore cannot defend against attacks embedded within legitimate web traffic. Consequently, network firewalls and WAFs are not replacements for each other but are complementary, layered defenses.

Many WAFs are reverse proxies (e.g., ModSecurity running in reverse‑proxy mode, cloud‑based WAFs like Cloudflare). However, not all proxy firewalls are WAFs—a generic proxy firewall can handle FTP, SMTP, etc., while a WAF is narrowly focused on HTTP/HTTPS. For comprehensive protection, organizations require both: the network firewall to guard the network perimeter and the WAF to protect the applications exposed to the internet from targeted layer‑7 attacks.

|WAF Deployment Type|Example Tools|Description|
|---|---|---|
|Host‑based WAF|ModSecurity (Apache/Nginx plugin)|Runs directly on the web server itself (e.g., as a module).|
|Network‑based WAF|Cloudflare WAF, HAProxy + ModSecurity|Deployed as a standalone appliance or cloud service, protecting multiple backend servers.|

**Proxy Firewall vs WAF Comparison**

|Feature|Proxy Firewall (Application‑level Gateway)|Web Application Firewall (WAF)|
|---|---|---|
|Primary protocol focus|Multiple (HTTP, FTP, SMTP, etc.)|HTTP/HTTPS only|
|Deployment model|Often as a gateway or transparent proxy|Reverse proxy, inline, or cloud‑based|
|Primary security function|Content filtering, access control, isolation|Detects and blocks web application attacks|
|Attack types addressed|Policy violations, malware, command injection|SQLi, XSS, CSRF, path traversal, etc.|
|Typical location in network|Between internal network and internet|In front of web servers / applications|

#### Next-Generation Firewalls (NGFWs)

The modern evolution is the Next-Generation Firewall (NGFW), which incorporates and expands upon all previous capabilities. NGFWs provide a more comprehensive, intelligent, and application‑aware security posture for modern networks. NGFWs can perform stateful and Application layer packet filtering, in addition to more advanced inspection capabilities such as:

- Deep Packet Inspection (DPI) and Application Awareness: Unlike basic firewalls that only inspect packet headers, DPI examines the actual data within the packet payload. This allows the NGFW to identify and control traffic based on the specific application (e.g., Facebook, Spotify) or service, regardless of the port it uses, and to classify and block malicious content.
- Integrated Intrusion Prevention System (IPS): This feature actively scans for, blocks, and prevents known attack patterns, exploits, and vulnerabilities within the network traffic flow in real time.
- User & Group Identity Integration: Rules can be created to allow or block traffic based on a user’s or group’s identity (e.g., from Active Directory), moving beyond simple IP address‑based filtering for more precise access control.
- Threat Intelligence Feeds: NGFWs leverage dynamic, cloud‑based threat intelligence to automatically block traffic to and from known malicious IP addresses, domains, and botnets.

The key differences between a traditional packet filtering firewall and an NGFW can be summarized as follows:

|Feature|Packet Filtering Firewall|Next-Generation Firewall (NGFW)|
|---|---|---|
|Primary OSI Layer|Layers 3 & 4 (Network & Transport)|Layers 3‑7 (Network to Application)|
|Decision Basis|IP Address, Port, Protocol|IP, Port, Protocol, Application, User, Content|
|Connection Awareness|Stateless or Stateful|Stateful by default|
|Traffic Inspection|Header‑only|Deep Packet Inspection (DPI) of payload|
|Additional Features|Basic NAT, basic logging|IPS, Anti‑Virus, Threat Intelligence, Identity Awareness|

pfSense and OPNsense are complete, GUI‑based firewall distributions (operating systems). They use PF (Packet Filter) as their core packet filtering engine. However, the systems themselves are NGFWs because they include many features beyond simple packet filtering.

#### Firewall roots and technology mapping

The following table maps common firewall implementations to their underlying systems and typical layers of operation.

| Firewall / Platform | Underlying System   | OS Family              | Layers | Notes                                                   |
| ------------------- | ------------------- | ---------------------- | ------ | ------------------------------------------------------- |
| UFW                 | iptables / nftables | Linux                  | L3/L4  | Front‑end for simplifying rule management.              |
| iptables            | Netfilter           | Linux                  | L3/L4  | Traditional Linux firewall, being replaced by nftables. |
| nftables            | Netfilter           | Linux                  | L3/L4  | Unifies IPv4/IPv6, improved syntax.                     |
| PF (Packet Filter)  | PF (in‑kernel)      | OpenBSD, FreeBSD, etc. | L3/L4  | Modern BSD firewall; supports stateful inspection.      |
| ipfw                | ipfw (in‑kernel)    | FreeBSD, macOS         | L3/L4  | Legacy; still available but PF is preferred on FreeBSD. |
| OPNsense            | PF (FreeBSD)        | FreeBSD                | L3–L7  | Full security platform; adds web UI, IPS, proxy, etc.   |
| pfSense (CE)        | PF (FreeBSD)        | FreeBSD                | L3–L7  | Full security platform; adds web UI, VPN, proxy, etc.   |

BSD‑based firewalls use networking and security tools native to BSD systems. BSD stands for Berkeley Software Distribution, a family of Unix‑like operating systems derived from the original Berkeley Unix (developed at UC Berkeley).

#### Choosing the right firewall type

The following guide helps you match firewall types to common scenarios. In practice, many environments use a combination—for example, a stateful firewall at the network perimeter, a WAF in front of public web applications, and host‑based packet filters on critical servers.

| Scenario/Primary Need                                                                         | Recommended Firewall Type(s)                                                                             | Rationale                                                                                                                                                                               |
| --------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Simple home or small office network with no public‑facing services                            | Stateful firewall (e.g., integrated in a home router, OPNsense, pfSense)                                 | Provides essential protection with minimal configuration. Stateful tracking allows outbound traffic while blocking unsolicited inbound connections.                                     |
| A simple host firewall for a Linux desktop or server                                          | UFW (Uncomplicated Firewall)                                                                             | Uncomplicated CLI, pre‑configured profiles, user‑friendly, and leverages the kernel’s stateful connection tracking.                                                                     |
| Granular, expert‑level control on a Linux system                                              | iptables or nftables                                                                                     | Kernel‑level power; choose nftables for a modern, unified syntax. nftables also gives expert users fine‑grained control.                                                                |
| A powerful firewall for a BSD‑based system or macOS                                           | PF (Packet Filter)                                                                                       | Clean syntax, stateful filtering, integrated into the OS. Suitable for servers and networks.                                                                                            |
| High‑performance core router where packet latency is critical (e.g., ISP backbone)            | Stateless ACLs on the router                                                                             | Stateless filtering imposes almost no processing overhead, preserving line‑rate forwarding. Security relies on perimeter firewalls upstream.                                            |
| Corporate network perimeter with hundreds of internal users                                   | Stateful firewall + NGFW                                                                                 | Stateful inspection handles the bulk of traffic, while NGFW features (application control, IPS, threat intelligence) protect against advanced threats and enforce user‑based policies.  |
| Protecting a public web application (e‑commerce, API, portal)                                 | Web Application Firewall (WAF)                                                                           | A WAF inspects HTTP/HTTPS payloads to block SQLi, XSS, and other Layer‑7 attacks that a network firewall cannot detect. Often deployed as a reverse proxy (cloud‑based or on‑premises). |
| Legacy applications that use non‑HTTP protocols (e.g., FTP, SMTP) and require deep inspection | Proxy firewall (application‑level gateway)                                                               | A proxy firewall terminates the connection and inspects the protocol content, allowing fine‑grained control over commands, attachments, or authentication.                              |
| Isolating a high‑risk network segment (e.g., guest Wi‑Fi, DMZ)                                | Stateful firewall with strict rule sets                                                                  | Placed between segments to enforce access policies. Use stateful inspection to allow established return traffic while denying unsolicited cross‑segment connections.                    |
| Internal VLAN traffic control within a switch                                                 | VLAN ACLs (VACLs) or Port ACLs (PACLs)                                                                   | These stateless filters apply to bridged traffic, preventing lateral movement even when traffic never passes through a router.                                                          |
| Virtualized data center with east‑west traffic between VMs                                    | Virtual switch ACLs (vACLs) or distributed firewall (e.g., VMware NSX)                                   | Enforce micro‑segmentation at the hypervisor level, applying stateless or stateful rules to traffic that stays inside the physical host.                                                |
| A full network security appliance with a web GUI                                              | OPNsense or pfSense                                                                                      | All‑in‑one solution (VPN, IDS/IPS, traffic shaping). Choose OPNsense for frequent updates and a modern approach, or pfSense for a vast, established community.                          |
| Comprehensive defense‑in‑depth for an enterprise                                              | Layered approach: Perimeter NGFW + internal stateful firewalls + WAF for web apps + host‑based firewalls | No single firewall type blocks all threats. Combining them creates overlapping controls that compensate for individual weaknesses.                                                      |

#### Firewall tools: key features and comparison

**1. UFW (Uncomplicated Firewall)**

- Type: Host‑based firewall (frontend for iptables/nftables).
- Platform: Linux (Ubuntu default).
- Key features: Simplified CLI for managing firewall rules (easier than raw iptables). Supports IPv4 and IPv6. Predefined application profiles (e.g., allow SSH, HTTP). Integrates with iptables or nftables as the backend. Designed for simplicity, ideal for desktop users and beginners.
- Use case: Best for Linux beginners who need a simple, no‑fuss host firewall.

**2. iptables**

- Type: Host/network firewall (kernel‑level).
- Platform: Linux.
- Key features: Traditional Linux firewall using Netfilter framework. Rule‑based system (chains: INPUT, OUTPUT, FORWARD). Supports NAT, packet filtering, and stateful inspection. Complex syntax (requires expertise). Being replaced by nftables but still widely used.
- Use case: Legacy Linux firewall for experts needing granular control. Predecessor to nftables. Part of the Linux kernel (Netfilter project).

**3. nftables**

- Type: Host/network firewall (successor to iptables).
- Platform: Linux (kernel ≥ 3.13).
- Key features: Unified framework replacing iptables, ip6tables, arptables, etc. Simplified syntax with JSON support. Faster rule processing and better scalability (than iptables). Supports sets and maps for dynamic rules. Backward‑compatible with iptables via translation tools.
- Use case: Modern Linux firewall unifying and simplifying iptables rules. Also part of Linux (Netfilter).

**4. PF (Packet Filter)**

- Type: Host/network firewall.
- Platform: BSD (OpenBSD default, also FreeBSD, macOS).
- Key features: Stateful firewall with advanced features (NAT, QoS, traffic shaping). Clean, readable rule syntax (e.g., `pass in on eth0 proto tcp to port 22`). Handles high traffic efficiently (better than iptables in some cases). Supports logging, SYN proxy, and scrubbing. Integrated in OpenBSD (security‑focused).
- Use case: Powerful BSD firewall with clean syntax for servers/networks. More advanced than iptables, used in BSD‑based firewalls.

**5. ipfw**

- Type: Host/network firewall.
- Platform: FreeBSD (legacy), macOS (legacy, pre‑10.11 El Capitan).
- Key features: Traditional, stateful packet filter for BSD‑based systems. Uses a sequential rule numbering system and a consistent, predictable syntax. Integrated with dummynet for advanced traffic shaping, bandwidth management, and network emulation. Provides a robust set of features for packet filtering, NAT, and logging. Largely superseded by PF on modern FreeBSD and macOS.
- Use case: Managing firewalls on legacy FreeBSD systems or older macOS versions, or for leveraging its integrated dummynet traffic‑shaping capabilities.

**6. OPNsense**

- Type: Network firewall/router (open‑source fork of pfSense).
- Platform: FreeBSD‑based (dedicated appliance/VM).
- Key features: Web GUI for easy management. Supports VPN (OpenVPN, WireGuard), IDS/IPS (Suricata), and traffic shaping. Regular updates with a focus on security and usability. Plugins for extended functionality (e.g., Nginx, CrowdSec). Community and commercial support options.
- Use case: Feature‑rich open‑source firewall with frequent updates for SMBs/enterprises.

**7. pfSense (Community Edition)**

- Type: Network firewall/router.
- Platform: FreeBSD‑based (dedicated appliance/VM). Key features: Fork of m0n0wall, widely used in enterprises. Web GUI for easy management. Supports VPN (OpenVPN, IPsec), IDS/IPS (Snort), and traffic shaping. Advanced features (captive portal, CARP for HA). Supports packages (Snort, Squid, HAProxy). Stateful firewall, NAT, and traffic shaping. Large community but slower updates than OPNsense.
- Use case: Reliable FreeBSD‑based network firewall with a large support community.

**Firewall Comparison Table**

All the firewalls listed in the following table are open source, stateful, perform NAT, and have IPv6 routing capability.

| Firewall   | Type         | Platform                | GUI       | Ease of Use | IDS/IPS      | Traffic Shaping (QoS) |
| ---------- | ------------ | ----------------------- | --------- | ----------- | ------------ | --------------------- |
| UFW        | Host         | Linux                   | No (CLI)  | Very Easy   | No           | No                    |
| iptables   | Host/Network | Linux                   | No (CLI)  | Complex     | No (add-ons) | Yes                   |
| nftables   | Host/Network | Linux                   | No (CLI)  | Moderate    | No (add-ons) | Yes                   |
| PF         | Host/Network | OpenBSD, FreeBSD, macOS | No (CLI)  | Moderate    | No (add-ons) | Yes                   |
| ipfw       | Host/Network | FreeBSD, macOS (legacy) | No (CLI)  | Complex     | No (add-ons) | Yes (via dummynet)    |
| OPNsense   | Network      | FreeBSD                 | Yes (Web) | Easy        | Suricata     | Yes                   |
| pfSense CE | Network      | FreeBSD                 | Yes (Web) | Easy        | Snort        | Yes                   |

**Summary**

- UFW: Best for Linux beginners needing simplicity.
- iptables/nftables: For advanced Linux users (legacy vs. modern).
- PF: Preferred on BSD for its clean syntax and power.
- OPNsense/pfSense: Feature‑rich network firewalls; OPNsense has faster updates, pfSense has a larger legacy user base.

### IDS/IPS

Popular open source NIDS/NIPS (Network IDS/IPS) and HIDS (Host IDS) include Suricata, Snort, Wazuh, OSSEC, Fail2Ban, Zeek (formerly Bro), Security Onion, and OpenWIPS-NG. The following discussion explores the core concepts and practical deployment of IDS/IPS technologies. Key IDS/IPS concepts discussed in this section include intrusion detection methodologies (signature‑based, anomaly‑based, and behavioural), deployment architectures (inline vs passive), and the complementary roles of network and host‑based monitoring.

Intrusion Detection Systems (IDS) and Intrusion Prevention Systems (IPS) are foundational defensive technologies that monitor network traffic or host activity for signs of malicious behaviour. An IDS passively alerts when suspicious activity is detected; an IPS actively blocks or modifies malicious traffic inline. Both play critical roles in a defense in depth strategy.

The following discussion begins by distinguishing intrusion detection methodologies—signature‑based, anomaly‑based, and behavioural—and explains how they are applied in both network‑based (NIDS/NIPS) and host‑based (HIDS) tools. Deployment architectures are examined, contrasting passive monitoring (IDS mode) with inline prevention (IPS mode), and highlighting specialized solutions such as wireless IDS/IPS. The section then surveys popular open‑source tools, including Suricata, Snort, Zeek, Wazuh, OSSEC, Fail2Ban, Security Onion, and OpenWIPS‑NG, mapping each to its typical use case. By the end, you will understand how to select and position IDS/IPS technologies as part of a layered defence strategy.

#### IDS/IPS detection methodologies

IDS/IPS tools use one or more detection methods to identify threats:

- Signature‑based detection – matches traffic or activity against a database of known attack patterns (signatures). It is highly accurate for known threats but cannot detect zero‑day attacks without an updated signature. Examples: Snort, Suricata.
- Anomaly‑based detection – establishes a baseline of “normal” behaviour and flags deviations. It can detect novel attacks but may generate false positives. Often implemented with statistical or machine‑learning models.
- Behavioural detection – focuses on patterns of activity that indicate compromise (e.g., command‑and‑control traffic, data exfiltration). It overlaps with anomaly detection but is often rule‑based. Zeek specializes in behavioural analysis.

Most modern IDS/IPS engines combine these approaches.

**NIDS vs HIDS: Typical Deployment**

|Type|Placement|Purpose|Examples|
|---|---|---|---|
|Network IDS/IPS (NIDS/NIPS)|Monitored network segment (e.g., via SPAN port, tap, or inline)|Detects or prevents network‑based attacks, lateral movement, and malicious traffic patterns|Suricata, Snort, Zeek|
|Host IDS/IPS (HIDS)|Installed on individual servers or endpoints|Monitors file integrity, system logs, rootkits, and local activity|OSSEC, Wazuh, Fail2Ban|

#### IDS/IPS deployment architectures

**Network‑Based Deployment**

**Inline vs Passive Deployment**

- Passive (IDS mode) – copies traffic (via SPAN port or tap) for analysis. No impact on traffic flow, but cannot block attacks in real time.
- Inline (IPS mode) – sits directly in the traffic path. Can drop malicious packets, reset connections, or block IPs. Adds latency but enables active prevention.

NIDS/NIPS appliances or virtual instances are placed at strategic points:

- Perimeter – monitors traffic entering or leaving the network.
- Internal segments – monitors east‑west traffic to detect lateral movement.
- DMZ – inspects traffic to/from public‑facing servers.

For passive monitoring, a switch SPAN (mirror) port or network tap copies traffic. For inline IPS, the device is inserted between two network segments.

**Host‑Based Deployment**

HIDS agents are installed on each endpoint or server. They collect logs, monitor file integrity, and detect local anomalies. Centralized management consoles (e.g., Wazuh) aggregate alerts across many hosts.

**Wireless IDS/IPS**

Specialized tools like OpenWIPS‑NG monitor Wi‑Fi channels for rogue access points, de-authentication floods, and other wireless‑specific attacks.

#### Technology mapping

The following table maps common IDS/IPS tools to their detection methods, deployment type, and underlying technology.

| Tool           | Type             | Detection Method                | Deployment        | Key Technology / Notes                                                                   |
| -------------- | ---------------- | ------------------------------- | ----------------- | ---------------------------------------------------------------------------------------- |
| Suricata       | NIDS/NIPS        | Signature, anomaly, behavioural | Inline or passive | Multi‑threaded, Snort‑rule compatible, EVE JSON logging, file extraction                 |
| Snort          | NIDS/NIPS        | Signature                       | Inline or passive | Single‑threaded (v2), widely used; Snort 3 adds multi‑threading                          |
| Zeek (Bro)     | NIDS / NSM       | Behavioural, protocol‑based     | Passive only      | Generates rich logs; ideal for forensic analysis, not inline blocking                    |
| Wazuh          | HIDS / SIEM      | Log analysis, FIM, rootkit      | Host agent        | Fork of OSSEC with Elastic Stack integration, MITRE ATT&CK mapping                       |
| OSSEC          | HIDS             | Log analysis, FIM, rootkit      | Host agent        | Lightweight, active response (e.g., block IPs)                                           |
| Fail2Ban       | HIDS (log‑based) | Log parsing                     | Host              | Scans logs for brute‑force attempts, bans IPs via firewall                               |
| Security Onion | NIDS/HIDS/SIEM   | Multiple (bundled)              | Passive           | Complete Linux distribution with Suricata, Zeek, Wazuh, Elastic, and full packet capture |
| OpenWIPS‑NG    | Wireless IDS/IPS | Wireless‑specific               | Passive or inline | Detects rogue APs, evil twin, deauthentication floods                                    |

#### Choosing the right IDS/IPS tool

The following guide helps match IDS/IPS technologies to common scenarios. Many environments combine network‑based and host‑based tools for layered coverage.

| Scenario/Primary Need                                                                                            | Recommended Tool(s) | Rationale                                                                                                                                                                                         |
| ---------------------------------------------------------------------------------------------------------------- | ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| High‑speed network perimeter with inline blocking; high‑speed network intrusion detection/prevention (NIDS/NIPS) | Suricata (IPS mode) | Multi‑threaded, high throughput; can drop malicious packets in real time. Snort‑rule compatible, supports file extraction and EVE JSON logging.                                                   |
| Small to medium network needing a well‑documented NIDS; a lightweight, well‑known NIDS for smaller networks      | Snort               | Industry standard with extensive community ruleset, widely supported. Can run in IDS or IPS mode; lightweight but single‑threaded in v2 (v3 adds multi‑threading).                                |
| Deep network forensics and behavioural analysis; deep network traffic analysis and forensics                     | Zeek (Bro)          | Produces detailed, structured logs (HTTP, DNS, TLS) suitable for offline analysis, anomaly detection, and SIEM integration. Passive monitoring only; can integrate with firewalls via netcontrol. |
| Centralised endpoint security, compliance, and SIEM; host‑based monitoring (HIDS) and compliance                 | Wazuh               | Combines HIDS, file integrity monitoring, vulnerability detection, MITRE ATT&CK mapping, and a modern web dashboard (Elastic Stack). Supports cloud environments and active response.             |
| Host‑based intrusion detection with active response; a lightweight HIDS for servers with active response         | OSSEC               | Lightweight; monitors logs, file integrity, rootkits. Can automatically block IPs after failed logins or trigger custom actions. No native GUI (Wazuh extends it).                                |
| Quick brute‑force protection for SSH, web servers; protection against brute‑force attacks on services            | Fail2Ban            | Simple to configure; scans logs (e.g., SSH, Apache) and bans malicious IPs at the local firewall. Lightweight, not a full HIDS.                                                                   |
| All‑in‑one security monitoring platform (SOC); an all‑in‑one distributed security monitoring platform            | Security Onion      | Provides full packet capture, multiple detection engines (Suricata, Zeek), and a central console (Kibana) out of the box. Designed for enterprise SOC environments.                               |
| Wireless network security monitoring; wireless intrusion detection and prevention                                | OpenWIPS‑NG         | Detects rogue access points, evil twin attacks, deauthentication floods, and other wireless‑specific threats that wired IDS cannot see.                                                           |

#### IDS/IPS tools: key features and comparison

**1. Suricata**

- Type: NIDS/NIPS
- Key features:
    - High‑performance, multi‑threaded engine.
    - Real‑time traffic analysis, automatic protocol detection (HTTP, DNS, TLS).
    - Rule‑based detection (compatible with Snort rules).
    - File extraction and malware detection via YARA.
    - EVE JSON output for structured logging.
    - Can act as an IPS (inline blocking).
- Use case: Enterprise networks, high‑speed traffic analysis.

**2. Snort**

- Type: NIDS/NIPS
- Key features:
    - One of the oldest and most widely used NIDS (since 1998).
    - Signature‑based detection with custom or community rules.
    - Lightweight, though version 2 is single‑threaded (version 3 supports multi‑threading).
    - PCAP analysis for forensics.
    - Inline mode available for IPS functionality.
- Use case: Small to medium networks, basic threat detection.

**3. Zeek (formerly Bro)**

- Type: NIDS / Network Security Monitoring (NSM)
- Key features:
    - Protocol‑aware traffic analysis (HTTP, DNS, SSL, etc.).
    - Generates detailed log files (`.log`) for forensic analysis.
    - Behavioural detection (e.g., detecting C2 traffic, anomalies).
    - No built‑in IPS; passive monitoring only. However, Zeek can integrate with firewalls (e.g., PF and iptables) via its netcontrol framework to enforce blocking decisions.
- Use case: Best for network monitoring, forensics, and anomaly detection (deep traffic analysis).

**4. Wazuh**

- Type: HIDS + SIEM + Compliance
- Key features:
    - Fork of OSSEC with added cloud and SIEM features.
    - Log analysis, file integrity monitoring (FIM), rootkit detection, vulnerability detection.
    - MITRE ATT&CK mapping for threat detection.
    - Centralised management via web UI (Kibana).
    - Integrates with Elasticsearch for log storage.
- Use case: Endpoint security, compliance (PCI DSS, GDPR), and threat detection.

**5. OSSEC**

- Type: HIDS
- Key features:
    - Lightweight host‑based monitoring.
    - Log analysis, file integrity checks, rootkit detection.
    - Active response (e.g., block IPs after brute‑force attempts).
    - No native GUI (CLI‑based; Wazuh adds a web interface).
- Use case: Server security, compliance monitoring, log‑based intrusion detection.

**6. Fail2Ban**

- Type: HIDS (log‑based intrusion prevention)
- Key features:    
    - Scans log files (e.g., SSH, Apache) for brute‑force attacks.
    - Automatically bans malicious IPs via iptables/nftables.
    - Lightweight, easy to configure.
    - Limited to log‑based attacks; not a full HIDS.
- Use case: Protecting servers from brute‑force attacks.

**7. Security Onion**

- Type: NIDS/HIDS + SIEM + Network Monitoring
- Key features:
    - All‑in‑one distribution (includes Suricata, Zeek, Wazuh, Elasticsearch, Kibana, etc.).
    - Full packet capture (via Stenographer).
    - SOC‑friendly dashboards (Kibana, Grafana).
    - Heavy resource requirements; best for dedicated hardware.
- Use case: Enterprise‑grade network security monitoring.

**8. OpenWIPS‑NG**

- Type: Wireless IDS/IPS
- Key features:
    - Detects rogue APs, evil twin attacks, deauthentication floods.
    - Supports RFMON mode for wireless monitoring.
    - Less maintained than others but unique for Wi‑Fi security.
- Use case: Wireless network security monitoring.

**IDS/IPS Comparison Table**

|Tool|Type|Detection Method|Key Strengths|IPS Capability|GUI|Logging/Output|Best For|
|---|---|---|---|---|---|---|---|
|Suricata|NIDS/NIPS|Signature/Anomaly/Behavioural|High‑speed, multi‑threaded, file extraction|Yes (inline)|Web (e.g., Arkime)|EVE JSON, PCAP|Enterprise networks|
|Snort|NIDS/NIPS|Signature‑based|Lightweight, widely supported|Yes (inline)|No (CLI)|PCAP, alerts|Legacy networks, small‑medium|
|Zeek|NIDS/NTA|Behavioural/protocol|Deep traffic analysis, forensics|No|No (CLI)|`.log` files|Research, network forensics|
|Wazuh|HIDS/SIEM|Log/FIM/rootkit|MITRE ATT&CK, cloud integration|No (HIDS)|Yes|Elasticsearch|Compliance, cloud monitoring|
|OSSEC|HIDS|Log/FIM/rootkit|Lightweight, active response|No (HIDS)|No (CLI)|Text logs|Servers, endpoint security|
|Fail2Ban|HIDS (log)|Log parsing|Simple brute‑force protection|Yes (firewall)|No (CLI)|Syslog|SSH/web server protection|
|Security Onion|NIDS/HIDS/SIEM|Multiple engines|All‑in‑one SOC platform|Via Suricata|Yes (Kibana)|Elasticsearch, PCAP|Security Operations Centers|
|OpenWIPS‑NG|Wireless IDS|Wi‑Fi‑specific|Rogue AP detection|Limited|No (CLI)|Text logs|Wi‑Fi security monitoring|

**Summary**

- For networks: Suricata (best performance), Snort (legacy), Zeek (deep analysis).
- For hosts: Wazuh (full SIEM), OSSEC (lightweight), Fail2Ban (log‑based).
- For SOCs: Security Onion (all‑in‑one).
- For Wi‑Fi: OpenWIPS‑NG (specialised).

### SIEM/EDR

Popular open source SIEM/EDR (Security Information and Event Management/Endpoint Detection and Response) technologies include Wazuh, TheHive, Zeek, OSSEC, Suricata, and Velociraptor. Key concepts discussed in this section include the distinction between SIEM and EDR, log aggregation and normalization, correlation rules, threat hunting, and incident response workflows. This section also examines how these tools integrate with network‑based data sources (e.g., Zeek, Suricata) and host-based agents to provide a unified view of security events.

SIEM and EDR are central pillars of modern security operations centres (SOCs). SIEM aggregates and correlates logs from across the enterprise to provide visibility into security events, while EDR focuses on endpoint telemetry and enables rapid investigation and response. Together, they form a powerful combination for threat detection, incident response, and compliance.

The following discussion explores the core concepts and practical deployment of SIEM and EDR technologies. It begins by distinguishing SIEM from EDR, explaining their complementary roles in a security operations centre. Deployment architectures are examined, covering centralized log aggregation, agent-based endpoint telemetry, and integrated SOC platforms. The section then surveys popular open source tools, including Wazuh, TheHive, Zeek, OSSEC, Suricata, and Velociraptor, mapping each to its typical use case. By the end, you will understand how to select and position SIEM and EDR technologies as part of a layered defense strategy.

#### Introducing SIEM and EDR

**What is SIEM?**

A Security Information and Event Management (SIEM) system collects, aggregates, normalizes, and analyses log data from diverse sources: firewalls, IDS/IPS, servers, applications, and endpoints. It provides:

- Log aggregation and retention.
- Event correlation and rule‑based alerting.
- Dashboards and visualization.
- Compliance reporting (e.g., PCI DSS, HIPAA).

SIEMs are typically centralized platforms that ingest data via syslog, APIs, or agents. They help security analysts identify patterns indicative of attacks (e.g., multiple failed logins followed by privilege escalation) and manage incident response workflows.

**What is EDR?**

Endpoint Detection and Response (EDR) focuses on endpoint telemetry—processes, file system changes, registry modifications, network connections, and user activity. EDR solutions provide:

- Continuous endpoint monitoring.
- Threat hunting (proactive search for indicators of compromise).
- Forensic data collection.
- Automated or manual response (e.g., isolating a compromised endpoint).

Unlike traditional antivirus, EDR emphasizes visibility and investigation rather than static prevention. Many modern EDR platforms incorporate threat intelligence and behavioural analytics.

**SIEM vs EDR: Complementary Roles**

|Aspect|SIEM|EDR|
|---|---|---|
|Primary data source|Logs from network devices, servers, applications|Endpoint telemetry (processes, file activity, registry, network connections)|
|Focus|Broad visibility across the enterprise|Deep visibility on individual endpoints|
|Alerting|Correlation across multiple sources|Behavioural rules, indicators of attack (IOAs)|
|Response|Typically manual (ticketing, orchestration)|Can include automated containment (kill process, isolate endpoint)|
|Use case|Compliance, incident correlation, long‑term retention|Threat hunting, forensic investigation, fast containment|

In practice, a mature SOC uses both: SIEM for cross‑domain correlation and long‑term storage, and EDR for in‑depth endpoint investigation and rapid response. Some open‑source platforms (e.g., Wazuh) blur the line by providing both HIDS and SIEM functionality.

#### Deployment architectures

**SIEM Deployment**

SIEM systems are typically deployed as centralized platforms. Agents may be installed on endpoints to forward logs, or logs are sent via syslog, Windows Event Forwarding, or API. Key components include:

- Log collection layer: agents, syslog servers, collectors.
- Central processing engine: normalisation, correlation, enrichment.
- Storage: often Elasticsearch or similar.
- User interface: dashboards, search, reporting (e.g., Kibana).

**EDR Deployment**

EDR is agent‑based. Agents are installed on endpoints (servers, workstations) and communicate with a management server. The management server provides:

- Centralised policy management.
- Real‑time telemetry collection.
- Threat hunting interface (query endpoints).
- Response capabilities (isolate, collect files, run commands).

**Integrated SOC Platforms**

Some open‑source projects combine multiple functions:

- Security Onion bundles Suricata, Zeek, and Elastic for network‑centric SOC.
- Wazuh combines HIDS, SIEM, and basic EDR (with active response).
- TheHive provides case management and can ingest alerts from other tools.

#### Technology mapping

The following table maps common SIEM/EDR tools to their primary function and key technology.

|Tool|Primary Function|Key Technology / Notes|
|---|---|---|
|Wazuh|SIEM + HIDS + basic EDR|Fork of OSSEC; integrates with Elastic Stack; MITRE ATT&CK mapping; cloud support|
|TheHive|Incident Response / Case Management|Collaborative platform; integrates with MISP; no native detection|
|Zeek (Bro)|Network Security Monitoring|Generates detailed logs; used as a data source for SIEM|
|OSSEC|HIDS (host‑based IDS)|Lightweight log analysis, file integrity monitoring, active response|
|Suricata|NIDS/NIPS|Network traffic inspection; logs can be ingested by SIEM|
|Velociraptor|EDR + Digital Forensics|Live endpoint queries (VQL); memory forensics; artifact collection|

#### Choosing the right SIEM/EDR tool

The following guide helps match tools to common scenarios. Many organisations use a combination—for example, Wazuh for centralized SIEM and Velociraptor for deep endpoint hunting.

| Scenario/Primary Need                                                                                   | Recommended Tool(s) | Rationale                                                                                                                                                                                           |
| ------------------------------------------------------------------------------------------------------- | ------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Centralised log management, compliance, and HIDS; a unified SIEM with HIDS, compliance, and a dashboard | Wazuh               | All‑in‑one open‑source SIEM/XDR platform with Elastic Stack integration; compliance reporting, file integrity monitoring, vulnerability detection, MITRE ATT&CK mapping, and a central dashboard.   |
| Lightweight HIDS with active response; lightweight host‑based intrusion detection with active response  | OSSEC               | Low overhead; monitors logs, file integrity, rootkits; can automatically block IPs after failed logins. No GUI out of the box (Wazuh extends it).                                                   |
| Deep endpoint forensics and threat hunting; endpoint hunting, forensics, and live response              | Velociraptor        | Powerful query language (VQL) for live endpoint queries, memory analysis, and artifact collection; enables deep investigation and incident response.                                                |
| Network traffic logs for SIEM enrichment; to feed network traffic logs into your SIEM                   | Zeek or Suricata    | Generate structured logs (e.g., EVE JSON, Zeek `.log` files) that can be ingested by SIEMs like Wazuh or Elastic. Zeek provides deep protocol‑aware metadata; Suricata adds signature‑based alerts. |
| Collaborative incident response case management; collaborative incident response and case management    | TheHive             | Manages security incidents with collaborative workflows; integrates with MISP for threat intelligence; streamlines SOC case management.                                                             |
| All‑in‑one SOC platform (network + host)                                                                | Security Onion      | Full packet capture, multiple detection engines (Suricata, Zeek), and a central console (Kibana) out of the box; designed for enterprise SOC environments.                                          |

#### SIEM/EDR tools: key features and comparison

A mature SIEM/EDR deployment often combines a central analytics platform with dedicated data sources. Tools like _Zeek_ and _Suricata_ provide the network telemetry layer, feeding rich, structured logs into a central SIEM such as _Wazuh_ for correlation, alerting, and long‑term storage. Endpoint telemetry is typically handled by agents (e.g., Wazuh agent, Velociraptor). The following list highlights the primary role of each tool in a SIEM/EDR ecosystem.

**1. Wazuh**

- Type: SIEM + HIDS + Compliance + basic EDR
- Key features:
    - Log analysis, file integrity monitoring (FIM), vulnerability detection.
    - MITRE ATT&CK mapping for threat detection.
    - Endpoint protection (Linux, Windows, macOS).
    - Cloud/SaaS integration (AWS, Azure, GCP).
    - Centralized dashboard (Elastic Stack/Kibana).
    - Active response (e.g., blocking malicious IPs, quarantining files).
- Use case: Unified SIEM and endpoint security with compliance monitoring.

**2. TheHive**

- Type: Incident Response + Case Management (complementary to SIEM/EDR)
- Key features:
    - Collaborative platform for SOC teams.
    - Integrates with MISP (threat intelligence).
    - Automated workflows for incident handling.
    - No native detection capabilities; relies on external tools (Wazuh, Suricata, etc.).
- Use case: Collaborative incident response platform for SOC teams.

**3. Zeek (formerly Bro)**

- Type: Network Security Monitoring (NSM) / Data Source
- Role in SIEM/EDR: _Zeek_ is a network telemetry generator. It passively analyses traffic, producing highly detailed, structured logs (HTTP, DNS, TLS, etc.) that serve as rich input for a central SIEM. It does not perform inline blocking, but its logs enable deep behavioural analysis and forensic investigation.
- Use case: Feeding high‑fidelity network metadata into a SIEM for anomaly detection and forensics.

**4. OSSEC**

- Type: HIDS
- Key features:
    - Log analysis, file integrity checks, rootkit detection.
    - Active response (e.g., block IPs after brute‑force attempts).
    - No native GUI (CLI‑based; Wazuh extends it).
    - Lightweight, best for endpoint monitoring.
- Use case: Lightweight HIDS for log analysis, file integrity, and active response.

**5. Suricata**

- Type: NIDS/NIPS / Data Source
- Role in SIEM/EDR: _Suricata_ acts as a network intrusion detection engine that can also supply real‑time alerts and EVE JSON logs to a SIEM. When deployed in passive mode, it provides signature‑based and behavioural alerts that a SIEM can correlate with other data sources. Its inline IPS capability is typically used at the network perimeter, independent of the SIEM.
- Use case: High‑performance network threat detection with seamless SIEM integration via structured log output.

**6. Velociraptor**

- Type: EDR + Digital Forensics
- Key features:
    - Endpoint visibility (Windows, Linux, macOS).
    - Hunt for threats (live query endpoints with VQL).
    - Memory forensics, artifact collection.
    - No built‑in SIEM (but integrates with other tools).
- Use case: Endpoint hunting and forensic investigation with live querying.

**SIEM/EDR Comparison Table**

|Tool|Type|Detection Capabilities|Key Strengths|SIEM Integration|EDR Features|Best For|
|---|---|---|---|---|---|---|
|Wazuh|SIEM + HIDS|Log/FIM/vulnerability|MITRE ATT&CK, cloud support, Kibana|Yes (Elastic)|Basic|Compliance, centralised monitoring|
|TheHive|Incident Response|None (case management)|SOC collaboration, MISP integration|Via APIs|No|Incident handling, teamwork|
|Zeek|Network Monitoring|Behavioural/protocol|Deep traffic forensics|Via logs|No|Network forensics, research|
|OSSEC|HIDS|Log/FIM/rootkit|Lightweight, active response|Via Wazuh|No|Endpoint security|
|Suricata|NIDS/NIPS|Signature/anomaly|High‑speed, file extraction, IPS mode|Via logs|No|Network traffic analysis|
|Velociraptor|EDR|Endpoint forensics, hunting|Live querying, memory analysis|Via APIs|Yes|Threat hunting, incident response|

**Summary**

- For a centralized SIEM with endpoint visibility: Wazuh.
- For advanced endpoint forensics and threat hunting: Velociraptor.
- For incident response collaboration: TheHive.
- For network‑derived logs: Zeek (forensic detail) or Suricata (real‑time alerts).
- For lightweight host‑based monitoring: OSSEC.

### Key takeaways

* Popular open source host-based firewalls include nftables and pf.
* Popular open source network-based firewalls include OPNsense and pfSense (CE).
* Packet filtering firewall technologies such as iptables and Packet Filter (PF) operate at the network level (Layer 3/4).
* Firewall Roots: Linux uses Netfilter (iptables/nftables) and BSD uses PF/ipfw.
* Packet filtering firewalls are either stateless, which are basic ACLs, and stateful, such as PF, nftables, etc. Beyond basic ACLs, all other firewall types - proxy firewalls, WAFs, and NGFWs - are all stateful. 
* Use stateful firewalls when you need stronger security, session awareness, and protection against modern threats.
* Use stateless firewalls for raw speed or when dealing with simple, static filtering.
* WAFs operate at the Application level (L7) and can be host-based (ModSecurity) or network-based (Cloudflare WAF). Host WAF: Protects a single service (e.g., one NGINX instance). Network WAF: Protects all traffic before it reaches servers (e.g., a reverse proxy).
* Popular open source HIDS include Wazuh and OSSEC.
* Popular open source NIDS include Suricata and Snort.
* Popular open source SIEM include Wazuh and TheHive.

### References

Bejtlich, R. (2013). _The practice of network security monitoring: Understanding incident detection and response_. No Starch Press.

Chapple, M., Seidl, D., & Stewart, J. M. (2022). _CISSP (ISC)2 certified information systems security professional official study guide_ (9th ed.). Sybex.
