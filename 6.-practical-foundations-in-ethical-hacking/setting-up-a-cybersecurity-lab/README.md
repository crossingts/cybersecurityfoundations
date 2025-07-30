---
hidden: true
---

# Setting up a cybersecurity lab

This exercise will guide you through setting up a fully functional cybersecurity virtual lab using exclusively open source technologies.&#x20;

## Setting up a cybersecurity lab steps

* Design the lab - choose a design pipeline&#x20;
* Choose a virtualization environment/tool
* Choose a project documentation platform/method
* Build the lab&#x20;
  * Configure subnet interfaces and verify connectivity
  * Configure and verify the firewall
  * Configure and verify the IDS/IPS
  * Configure and verify a web server (e.g., nginx, Apache) and/or a database server (MySQL)
  * Configure and verify SIEM/EDR (e.g., Wazuh)
  * Configure and verify Kali Linux
* Launch attacks from Kali Linux and document the project

### Design the lab - choose a design pipeline&#x20;

**Design pipeline 1 (AMD64):**&#x20;

OPNsense (firewall) + Suricata (IDS/IPS) + Wazuh (SIEM/XDR) + Kali Linux

OPNsense is a full-featured, open-source firewall and routing platform based on FreeBSD. It is highly customizable with plugins. It is suitable for protecting entire networks with features like IDS/IPS (via Suricata or Zeek), and VPN (OpenVPN, WireGuard).

OPNsense has a web-based interface and can be used on the x86-64 platform. Along with acting as a firewall, it has traffic shaping, load balancing, captive portal and virtual private network capabilities, and others can be added via plugins. The software also offers next-generation firewall capabilities utilizing Zenarmor, a NGFW plugin developed by OPNsense partner Sunny Valley Networks. (Wikipedia)

**Design pipeline 2 (AMD64):**&#x20;

pfSense (firewall) + Snort (IDS/IPS) + Wazuh (SIEM/XDR) + Kali Linux

**Design pipeline 3 (ARM64):**&#x20;

nftables (firewall) + Suricata (IDS/IPS) + Wazuh (SIEM/XDR) + Kali Linux

Inspiration: YouTube playlist (16 videos +150,000 views)

[Virtual Cyber Security Lab Building Series by LS111 Cyber Security Education](https://www.youtube.com/playlist?list=PLjjkJroii8DDb0QZpWLo978VXcLp8-xW3)

<figure><img src="../../.gitbook/assets/image (16).png" alt=""><figcaption><p>Cybersecurity virtual lab design (courtesy of LS111 Cyber Security Education)</p></figcaption></figure>

Choose a virtualization environment/tool

Choose a project documentation platform/method

Build the lab: Configure subnet interfaces and verify connectivity

Build the lab: Configure and verify the firewall

#### **Open-Source Firewall & IDS/IPS Compatibility Table**

_(✅ = Native Support | ⚠️ = Partial/Workaround | ❌ = Not Supported | VM = Virtual Machine Only)_

**🔥 Firewalls**

| Technology    | Linux (x86/ARM) | Windows (x86) | macOS (Intel) | macOS (ARM) | Notes                                       |
| ------------- | --------------- | ------------- | ------------- | ----------- | ------------------------------------------- |
| **OPNsense**  | ✅ (x86)         | ❌             | ✅ (VM)        | ❌           | FreeBSD-based; no ARM or Windows support.   |
| **pfSense**   | ✅ (x86)         | ❌             | ✅ (VM)        | ❌           | FreeBSD-based; same as OPNsense.            |
| **OpenWRT**   | ✅ (x86/ARM)     | ❌             | ✅ (VM)        | ✅ (ARM VM)  | Linux-based; best for ARM routers.          |
| **IPTables**  | ✅ (x86/ARM)     | ❌             | ❌             | ❌           | Linux kernel firewall.                      |
| **nftables**  | ✅ (x86/ARM)     | ❌             | ❌             | ❌           | Modern Linux firewall (replaces IPTables).  |
| **Firewalld** | ✅ (x86/ARM)     | ❌             | ❌             | ❌           | RHEL/CentOS frontend for IPTables/nftables. |
| **UFW**       | ✅ (x86/ARM)     | ❌             | ❌             | ❌           | Simplified Linux firewall (Ubuntu).         |
| **macOS PF**  | ❌               | ❌             | ✅ (Native)    | ✅ (Native)  | Built-in BSD `pf` firewall (CLI-only).      |
| **LuLu**      | ❌               | ❌             | ✅             | ✅           | GUI firewall for macOS (blocks outbound).   |

**🛡️ IDS/IPS Compatibiity Table**

| Technology     | Linux (x86/ARM) | Windows (x86) | macOS (Intel) | macOS (ARM) | Notes                             |
| -------------- | --------------- | ------------- | ------------- | ----------- | --------------------------------- |
| **Suricata**   | ✅               | ⚠️ (WSL)      | ✅             | ✅ (Slow)    | Real-time IDS/IPS; best on Linux. |
| **Zeek (Bro)** | ✅               | ⚠️ (WSL)      | ✅             | ✅           | Network analysis (not blocking).  |
| **Snort**      | ✅               | ⚠️ (WSL)      | ✅             | ✅           | Legacy but stable IDS/IPS.        |

**Clarifications**

* **Windows Subsystem for Linux (WSL)**
  * Lets you run Linux binaries natively on Windows.
  * Relevance: Suricata/Zeek/Snort can run in WSL, but:
    * ⚠️ No IPS mode (can’t block traffic at kernel level).
    * ⚠️ Limited networking (WSL2 uses a virtual NIC).
* **x86-64**&#x20;
  * Most firewalls/routers use x86-64 for performance and driver compatibility.&#x20;
  * x86-64 is also known as x64, x86\_64, AMD64, and Intel 64.
  * x86-64 is a CPU architecture (not an OS). It is used by:
    * Windows (e.g., Windows 10/11 x64).
      * Linux (x86-64 distributions).
      * FreeBSD (OPNsense’s base).
      * macOS (Intel Macs).

***

**Firewalls categorized by their primary use case (host vs. network vs. hybrid):**

#### **1. Host Firewalls**

_(Protect a single machine; filter traffic to/from that host only)_

| Firewall                      | OS Compatibility  | Notes                                                                     |
| ----------------------------- | ----------------- | ------------------------------------------------------------------------- |
| **macOS PF**                  | macOS (Intel/ARM) | Built-in BSD `pf` (CLI-only). Configures rules for the local machine.     |
| **LuLu**                      | macOS (Intel/ARM) | GUI-based, blocks outbound connections (like Little Snitch).              |
| **IPTables**                  | Linux (x86/ARM)   | Kernel-level firewall for individual Linux systems.                       |
| **nftables**                  | Linux (x86/ARM)   | Modern replacement for IPTables (per-host rules).                         |
| **UFW**                       | Linux (x86/ARM)   | Simplified frontend for IPTables/nftables (Ubuntu).                       |
| **Firewalld**                 | Linux (x86/ARM)   | Dynamic firewall manager for RHEL/CentOS (host-focused).                  |
| **Windows Defender Firewall** | Windows (x86)     | Built-in host firewall (not open-source, but mentioned for completeness). |

**2. Network Firewalls**

_(Protect entire networks; route/filter traffic between devices)_

| Firewall     | OS Compatibility               | Notes                                                          |
| ------------ | ------------------------------ | -------------------------------------------------------------- |
| **OPNsense** | Bare-metal x86-64 / x86-64 VMs | FreeBSD-based, full-featured router/firewall OS.               |
| **pfSense**  | Bare-metal x86-64 / x86-64 VMs | FreeBSD-based (similar to OPNsense).                           |
| **OpenWRT**  | Bare-metal x86/ARM / VMs       | Lightweight Linux-based router OS (often used on ARM devices). |

**3. Hybrid Firewalls**

_(Can function as both host and network firewalls, depending on configuration)_

| Firewall       | OS Compatibility          | Notes                                                                                                     |
| -------------- | ------------------------- | --------------------------------------------------------------------------------------------------------- |
| **Suricata**   | Linux/macOS/Windows (WSL) | Primarily an IDS/IPS, but can enforce host _or_ network-level rules via integration with `pf`/`nftables`. |
| **Zeek (Bro)** | Linux/macOS/Windows (WSL) | Network analysis tool, but can trigger host-level scripts (e.g., block IPs via PF).                       |

**Key Differences**

| **Type**    | **Scope**               | **Typical Use Case**  | **Example**                               |
| ----------- | ----------------------- | --------------------- | ----------------------------------------- |
| **Host**    | Single machine          | Laptops, workstations | macOS PF, LuLu, UFW                       |
| **Network** | Entire subnet           | Routers, gateways     | OPNsense, OpenWRT                         |
| **Hybrid**  | Both (config-dependent) | Security appliances   | Suricata (if integrated with PF/nftables) |

***

#### **Why the Distinction Matters**

* **Host firewalls** are ideal for endpoints (e.g., blocking malware on your laptop).
* **Network firewalls** protect multiple devices (e.g., home/router security).
* **Hybrid tools** like Suricata are flexible but require manual setup to act as both.
