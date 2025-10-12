# Firewalls

### Core packet-filtering firewall technologies

Packet-filtering firewall technologies such as iptables and pfilter (PF) operate at the network level (Layer 3/4). These tools allow network administrators to define rules for allowing, blocking, or modifying traffic based on IPs, ports, protocols, and connection states.

**Core Packet-Filtering Firewall Technologies (Open Source Except WFP)**

| Firewall                             | OS/Platform                              | Notes                                                                                                                                                                   |
| ------------------------------------ | ---------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **iptables**                         | Linux                                    | Predecessor to nftables. Part of the Linux kernel (Netfilter project), licensed under GPL.                                                                              |
| **nftables**                         | Linux (replaces iptables)                | Modern successor to iptables, more flexible syntax. Also part of Linux (Netfilter), GPL-licensed.                                                                       |
| **PF (Packet Filter)**               | BSD (OpenBSD, FreeBSD, OPNsense/pfSense) | More advanced than iptables, used in BSD-based firewalls. Originally from OpenBSD, now also in FreeBSD and others, BSD license. CLI based macOS built-in Unix firewall. |
| **ipfw**                             | FreeBSD, macOS (legacy)                  | Older BSD firewall, mostly replaced by PF. Found in FreeBSD (and older macOS versions), BSD license.                                                                    |
| **firewalld**                        | Linux (RHEL/Fedora)                      | Frontend for iptables/nftables, uses zones for simplicity. Developed by Red Hat, GPL.                                                                                   |
| **UFW (Uncomplicated Firewall)**     | Linux (Debian/Ubuntu)                    | Simplified iptables wrapper for beginners, GPL-licensed.                                                                                                                |
| **Windows Filtering Platform (WFP)** | Windows                                  | Microsoft’s built-in firewall (CLI: `netsh advfirewall`).                                                                                                               |

**BSD-Based Firewalls**

BSD-based firewalls use networking and security tools native to BSD systems. BSD stands for Berkeley Software Distribution, a family of **Unix-like operating systems** derived from the original Berkeley Unix (developed at UC Berkeley).

**Key BSD Variants in Firewalling**

| BSD OS             | Firewall Used                          | Notes                                                           |
| ------------------ | -------------------------------------- | --------------------------------------------------------------- |
| **OpenBSD**        | **PF (Packet Filter)**                 | The gold standard for BSD firewalls (used in OPNsense/pfSense). |
| **FreeBSD**        | **PF** or **ipfw**                     | Supports both, but PF is more modern.                           |
| **NetBSD**         | **NPF** or **IPFilter**                | Less common in firewalls.                                       |
| **macOS (Darwin)** | **ipfw (legacy)** / **PF (partially)** | macOS inherited some BSD firewall tools.                        |

**Characteristics of BSD Firewalls**

* **Stability & Security:** OpenBSD is famously secure (used in critical infrastructure).
* **Performance:** PF handles high traffic efficiently (better than iptables in some cases).
* **Features:** Built-in QoS, SYN proxy, and cleaner syntax than iptables.

### Stateful firewalls: Definition and open source examples

Stateful firewalls primarily operate at **L3 (Network) and L4 (Transport)**, tracking connections (e.g., TCP/UDP sessions). A stateful firewall tracks the state of active connections (e.g., TCP handshakes, UDP streams) to make dynamic decisions. Unlike stateless filters (which check only individual packets), it understands sessions.

**Open-Source Stateful Firewalls (Open Source)**

| Firewall                                    | OS/Platform         | Notes                                                     |
| ------------------------------------------- | ------------------- | --------------------------------------------------------- |
| **iptables/nftables**                       | Linux               | Tracks connections via `conntrack` (connection tracking). |
| **PF (Packet Filter)**                      | OpenBSD/FreeBSD     | Stateful by default (e.g., `keep state`).                 |
| **firewalld**                               | Linux (RHEL/Fedora) | Uses nftables/iptables with stateful zones.               |
| **OPNsense/pfSense Community Edition (CE)** | BSD-based           | GUI for PF (stateful rules + IDS/IPS).                    |
| **Suricata (IPS mode)**                     | Cross-platform      | Open-source IDS with stateful firewall features.          |

**Clarifying Notes:**

**1. Stateless firewall**: Filters packets individually (no memory of past packets). Example: Traditional ACLs.

**2. Stateful firewall**: Tracks connections and makes decisions based on the full session state (auto-allows valid follow-up traffic). Example: PF, iptables (with conntrack).

**3. Connection Tracking (`conntrack`)**

* **Definition:** `conntrack` (connection tracking) is a subsystem in the Linux kernel (part of Netfilter) that monitors and records the state of network connections (e.g., TCP, UDP, ICMP).
* **Purpose:** It allows iptables/nftables to make decisions based on the **state** of a connection rather than just individual packets.

**How It Works**

* When a packet arrives, `conntrack` checks if it belongs to an **existing connection** (e.g., an ongoing TCP session).
* If it's a **new connection**, it gets logged in a connection tracking table (`/proc/net/nf_conntrack`).
* Subsequent packets are matched against this table to determine if they are part of an established, related, or invalid connection.

**Common States in `conntrack`**

| State           | Meaning                                                                          |
| --------------- | -------------------------------------------------------------------------------- |
| **NEW**         | First packet of a new connection (e.g., TCP SYN).                                |
| **ESTABLISHED** | Packets belonging to an already-seen connection (e.g., TCP handshake completed). |
| **RELATED**     | Packets related to an existing connection (e.g., FTP data connection).           |
| **INVALID**     | Malformed or suspicious packets (e.g., TCP RST without prior connection).        |

**Example Rule (iptables)**

sh

```
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
```

This rule **allows** packets that are part of an existing or related connection.

**4. keep state in PF (OpenBSD Packet Filter)**

**`keep state` (PF) or `--ctstate` (iptables)** = Enables stateful filtering.

*   When PF sees a rule like:

    sh

    ```
    pass in proto tcp from any to 192.168.1.1 port 22 keep state
    ```

    * It **allows** the initial packet (e.g., TCP SYN).
    * Then, it **automatically permits** subsequent packets in the same flow (ACKs, data, etc.) without requiring additional rules.
    * It also **blocks** packets that don’t match a known state (e.g., unsolicited responses).

**Why Stateful Filtering is Useful**

✅ **Simpler Rules**: No need to manually allow reply traffic.\
✅ **Security**: Blocks unsolicited/invalid packets (e.g., spoofed ACKs).\
✅ **Performance**: Faster than checking every packet against all rules.

### Stateless vs stateful firewalls

**Stateless vs. Stateful Diagram**

```
Stateless Firewall:
  [Packet] → [Check Rules] → Allow/Drop

Stateful Firewall:
  [Packet] → [Check State Table] → [Update State] → Allow/Drop
          ↳ (e.g., "Is this a reply to an existing SSH session?")
```

Stateful and stateless firewalls serve different purposes in network security, each with its own advantages. Here’s a comparison highlighting the **advantages of stateful firewalls over stateless firewalls**:

#### **Advantages of Stateful Firewalls:**

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

#### **When Stateless Firewalls Are Better:**

Stateless firewalls (ACLs) are simpler and faster but lack intelligence. They are useful for:

* High-speed networks where performance is critical (e.g., backbone routers).
* Simple packet filtering based on static rules (e.g., IP/port blocking).
* Environments where connection tracking isn’t needed.

#### **Summary:**

* **Use stateful firewalls** when you need **stronger security**, session awareness, and protection against modern threats.
* **Use stateless firewalls** for **raw speed** or when dealing with simple, static filtering.

**Roots of Common Packet-Filtering Firewalls (Table + Diagram)**

**Lineage of Firewall Technologies**

```
Linux Kernel:
  └─ Netfilter (Framework)
      ├─ iptables → firewalld/UFW (Frontends) (Legacy)
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

**Summary**

1. **Stateful Firewalls:** Open-source examples include iptables/nftables (Linux), PF (BSD), and OPNsense.
2. **WAFs:** Can be host-based (ModSecurity) or network-based (Cloudflare WAF).
3. **Firewall Roots:** Linux uses Netfilter (iptables/nftables), BSD uses PF/ipfw, Windows uses WFP.

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

**Key Difference**

* **Host WAF:** Protects a single service (e.g., one NGINX instance).
* **Network WAF:** Protects all traffic before it reaches servers (e.g., a reverse proxy).

### Host-based, network-based, and hybrid firewalls

While host firewalls are ideal for endpoints (e.g., blocking malware on your laptop), network firewalls protect multiple devices (e.g., home/router security). Hybrid tools like Suricata are flexible but require manual setup to act as both.

The following firewall technologies (except WFP) are open source: iptables, nftables, ufw, PF (Packet Filter), ipfw, firewalld, OPNsense, and pfSense (CE), Snort, Suricata, Zeek, Windows Filtering Platform (WFP).

**1. Host-Based Firewalls**

_(Run on individual systems to filter traffic to/from that host.)_

| **Firewall**                                                 | **Key Characteristics**                                                                                   |
| ------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------- |
| **iptables**                                                 | Traditional Linux packet filtering/NAT, uses Netfilter hooks, rule-based.                                 |
| **nftables**                                                 | Successor to iptables, unified syntax, supports sets/maps, more efficient.                                |
| **ufw**                                                      | User-friendly frontend for iptables/nftables (Ubuntu default).                                            |
| **ipfw**                                                     | FreeBSD firewall, supports stateful filtering, NAT, and traffic shaping.                                  |
| **PF (Packet Filter)**                                       | OpenBSD’s firewall, powerful syntax, supports ALTQ for QoS, used in macOS.                                |
| **firewalld**                                                | Dynamic daemon for Linux with zones/services, uses iptables/nftables backend.                             |
| **Windows Filtering Platform (WFP) (Microsoft proprietary)** | Operates at multiple network layers (Layer 2–7) via filtering layers (e.g., packet, stream, application). |

**2. Network-Based Firewalls**

_(Designed to protect entire networks, often running on dedicated hardware/appliances.)_

| **Firewall**     | **Key Characteristics**                                                         |
| ---------------- | ------------------------------------------------------------------------------- |
| **OPNsense**     | FreeBSD-based, fork of pfSense, focuses on usability & plugins (e.g., IDS/IPS). |
| **pfSense (CE)** | FreeBSD-based, derived from m0n0wall, GUI, VPN, traffic shaping.                |
| **Snort**        | Primarily an IDS/IPS, but can do inline blocking (network-level).               |
| **Suricata**     | Modern IDS/IPS with firewall capabilities (e.g., NFQUEUE integration).          |

**3. Hybrid Firewalls**

_(Can function as both host or network firewalls, or have multi-purpose roles.)_

| **Firewall**           | **Key Characteristics**                                                                                         |
| ---------------------- | --------------------------------------------------------------------------------------------------------------- |
| **Suricata**           | Primarily an IDS/IPS, but can enforce host _or_ network-level rules via integration with `pf`/`nftables`.       |
| **Zeek (Bro)**         | Primarily a network monitor/IDS, but can enforce policies (trigger host-level scripts), e.g., block IPs via PF. |
| **PF (Packet Filter)** | Can be used on both hosts (OpenBSD/macOS) and gateways (network).                                               |

**Notes:**

* **Snort/Suricata/Zeek** are primarily IDS/IPS tools but can act like firewalls in specific setups.
* **PF** and **ipfw** are flexible (used in both host and network contexts).
* **OPNsense/pfSense** are full firewall distros (network-focused but can run as VMs).

**Typical Deployment Scenarios**

| **Type**    | **Scope**               | **Typical Use Case**  | **Example**                               |
| ----------- | ----------------------- | --------------------- | ----------------------------------------- |
| **Host**    | Single machine          | Laptops, workstations | macOS PF, LuLu, UFW                       |
| **Network** | Entire subnet           | Routers, gateways     | OPNsense, OpenWRT                         |
| **Hybrid**  | Both (config-dependent) | Security appliances   | Suricata (if integrated with PF/nftables) |
