# Firewalls

### Core Packet-Filtering Firewall Technologies

Packet-filtering firewall technologies such as iptables and pfilter (PF) operate at the network level (Layer 3/4). These tools allow administrators to define rules for allowing, blocking, or modifying traffic based on IPs, ports, protocols, and connection states.&#x20;

**Core Packet-Filtering Firewall Technologies (Open Source Except WFP)**

| Firewall                             | OS/Platform                              | Notes                                                                                                                           |
| ------------------------------------ | ---------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| **iptables**                         | Linux                                    | Predecessor to nftables. Part of the Linux kernel (Netfilter project), licensed under GPL.                                      |
| **nftables**                         | Linux (replaces iptables)                | Modern successor to iptables, more flexible syntax. Also part of Linux (Netfilter), GPL-licensed.                               |
| **PF (Packet Filter)**               | BSD (OpenBSD, FreeBSD, OPNsense/pfSense) | More advanced than iptables, used in BSD-based firewalls. Originally from OpenBSD, now also in FreeBSD and others, BSD license. |
| **ipfw**                             | FreeBSD, macOS (legacy)                  | Older BSD firewall, mostly replaced by PF. Found in FreeBSD (and older macOS versions), BSD license.                            |
| **firewalld**                        | Linux (RHEL/Fedora)                      | Frontend for iptables/nftables, uses zones for simplicity. Developed by Red Hat, GPL.                                           |
| **UFW (Uncomplicated Firewall)**     | Linux (Debian/Ubuntu)                    | Simplified iptables wrapper for beginners, GPL-licensed.                                                                        |
| **Windows Filtering Platform (WFP)** | Windows                                  | Microsoft’s built-in firewall (CLI: `netsh advfirewall`).                                                                       |

***

**BSD-Based Firewalls**

BSD-based firewalls use networking and security tools native to BSD systems. BSD stands for Berkeley Software Distribution, a family of **Unix-like operating systems** derived from the original Berkeley Unix (developed at UC Berkeley).&#x20;

**Key BSD Variants in Firewalling**

| BSD OS             | Firewall Used                          | Notes                                                           |
| ------------------ | -------------------------------------- | --------------------------------------------------------------- |
| **OpenBSD**        | **PF (Packet Filter)**                 | The gold standard for BSD firewalls (used in OPNsense/pfSense). |
| **FreeBSD**        | **PF** or **ipfw**                     | Supports both, but PF is more modern.                           |
| **NetBSD**         | **NPF** or **IPFilter**                | Less common in firewalls.                                       |
| **macOS (Darwin)** | **ipfw (legacy)** / **PF (partially)** | macOS inherited some BSD firewall tools.                        |

**Characteristics of BSD Firewalls**

* **Stability & Security:** OpenBSD is famously secure (used in critical infra).
* **Performance:** PF handles high traffic efficiently (better than iptables in some cases).
* **Features:** Built-in QoS, SYN proxy, and cleaner syntax than iptables.

### Stateful Firewalls: Definition & Open-Source Examples

Stateful firewalls primarily operate at **L3 (Network) and L4 (Transport)**, tracking connections (e.g., TCP/UDP sessions). A stateful firewall tracks the state of active connections (e.g., TCP handshakes, UDP streams) to make dynamic decisions. Unlike stateless filters (which check only individual packets), it understands sessions.

**Open-Source Stateful Firewalls (Open Source)**

| Firewall                                    | OS/Platform         | Notes                                            |
| ------------------------------------------- | ------------------- | ------------------------------------------------ |
| **iptables/nftables**                       | Linux               | Tracks connections via `conntrack`.              |
| **PF (Packet Filter)**                      | OpenBSD/FreeBSD     | Stateful by default (e.g., `keep state`).        |
| **firewalld**                               | Linux (RHEL/Fedora) | Uses nftables/iptables with stateful zones.      |
| **OPNsense/pfSense Community Edition (CE)** | BSD-based           | GUI for PF (stateful rules + IDS/IPS).           |
| **Suricata (IPS mode)**                     | Cross-platform      | Open-source IDS with stateful firewall features. |

**Stateless vs. Stateful (Diagram)**

```
Stateless Firewall:
  [Packet] → [Check Rules] → Allow/Drop

Stateful Firewall:
  [Packet] → [Check State Table] → [Update State] → Allow/Drop
          ↳ (e.g., "Is this a reply to an existing SSH session?")
```

Stateful and stateless firewalls serve different purposes in network security, each with its own advantages. Here’s a comparison highlighting the **advantages of stateful firewalls over stateless firewalls**:

#### **Advantages of Stateful Firewalls:**

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

#### **When Stateless Firewalls Are Better:**

Stateless firewalls (ACLs) are simpler and faster but lack intelligence. They are useful for:

* High-speed networks where performance is critical (e.g., backbone routers).
* Simple packet filtering based on static rules (e.g., IP/port blocking).
* Environments where connection tracking isn’t needed.

#### **Summary:**

* **Use stateful firewalls** when you need **stronger security**, session awareness, and protection against modern threats.
* **Use stateless firewalls** for **raw speed** or when dealing with simple, static filtering.

Most modern firewalls (e.g., NGFW) are stateful by default due to their security advantages.

### Web Application Firewalls (WAFs)

**Characteristics?**

* Scope: Inspects payloads (e.g., "Block HTTP requests with SQLi").
* L7 Awareness: Understands HTTP, DNS, etc. (deep packet inspection)
* Performance Impact: High (parses full packets).

**Are WAFs Host-Based or Network-Based?**

WAFs can be **host-based and network-based**, depending on deployment:

| Type                  | Example Tools                         | Deployment                                                      |
| --------------------- | ------------------------------------- | --------------------------------------------------------------- |
| **Host-Based WAF**    | ModSecurity (Apache/Nginx plugin)     | Runs on the web server (e.g., as a module).                     |
| **Network-Based WAF** | Cloudflare WAF, HAProxy + ModSecurity | Standalone appliance/cloud service (protects multiple servers). |

**Key Difference**

* **Host WAF:** Protects a single service (e.g., one NGINX instance).
* **Network WAF:** Protects all traffic before it reaches servers (e.g., a reverse proxy).

***

**Roots of Common Packet-Filtering Firewalls (Table + Diagram)**

**Lineage of Firewall Technologies**

```
Linux Kernel:
  └─ Netfilter (Framework)
      ├─ iptables (Legacy)
      └─ nftables (Modern Replacement)

BSD Kernel:
  └─ PF (OpenBSD) → Used in OPNsense/pfSense
  └─ ipfw (FreeBSD) → Legacy

Windows:
  └─ Windows Filtering Platform (WFP)
```

**Underlying Systems Table**

| Firewall     | Underlying System | OS Family       | Notes                             |
| ------------ | ----------------- | --------------- | --------------------------------- |
| **iptables** | Netfilter (Linux) | Linux           | Legacy, replaced by nftables.     |
| **nftables** | Netfilter (Linux) | Linux           | Unifies IPv4/IPv6, better syntax. |
| **PF**       | BSD Kernel        | OpenBSD/FreeBSD | Powers OPNsense/pfSense.          |
| **ipfw**     | BSD Kernel        | FreeBSD/macOS   | Older, simpler than PF.           |
| **WFP**      | Windows Kernel    | Windows         | Native firewall for Windows.      |

**Diagram: Firewall Tech Tree**

```
Netfilter (Linux)
├─ iptables → firewalld/UFW (Frontends)
└─ nftables (Future-proof)

BSD Kernel
├─ PF → OPNsense/pfSense
└─ ipfw (Legacy)

Windows
└─ WFP (Integrated)
```

***

**Summary**

1. **Stateful Firewalls:** Open-source examples include iptables/nftables (Linux), PF (BSD), and OPNsense.
2. **WAFs:** Can be host-based (ModSecurity) or network-based (Cloudflare WAF).
3. **Firewall Roots:** Linux uses Netfilter (iptables/nftables), BSD uses PF/ipfw, Windows uses WFP.
