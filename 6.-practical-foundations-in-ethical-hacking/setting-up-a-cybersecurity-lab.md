---
hidden: true
---

# Setting up a cybersecurity lab

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

**🛡️ IDS/IPS Technologies**

| Technology     | Linux (x86/ARM) | Windows (x86) | macOS (Intel) | macOS (ARM) | Notes                             |
| -------------- | --------------- | ------------- | ------------- | ----------- | --------------------------------- |
| **Suricata**   | ✅               | ⚠️ (WSL)      | ✅             | ✅ (Slow)    | Real-time IDS/IPS; best on Linux. |
| **Zeek (Bro)** | ✅               | ⚠️ (WSL)      | ✅             | ✅           | Network analysis (not blocking).  |
| **Snort**      | ✅               | ⚠️ (WSL)      | ✅             | ✅           | Legacy but stable IDS/IPS.        |

**What’s WSL?**

* **Windows Subsystem for Linux (WSL)**: Lets you run Linux binaries natively on Windows.
* **Relevance**: Suricata/Zeek/Snort can run in WSL, but:
  * ⚠️ **No IPS mode** (can’t block traffic at kernel level).
  * ⚠️ **Limited networking** (WSL2 uses a virtual NIC).

***

Most firewalls/routers use x86-64 for performance and driver compatibility.

* **x86-64 is a CPU architecture**, not an OS. It is used by:
  * Windows (e.g., Windows 10/11 x64).
  * Linux (x86-64 distributions).
  * FreeBSD (OPNsense’s base).
  * macOS (Intel Macs).

***

**Firewalls discussed, categorized by their primary use case (host vs. network vs. hybrid):**

***

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

***

#### **2. Network Firewalls**

_(Protect entire networks; route/filter traffic between devices)_

| Firewall     | OS Compatibility               | Notes                                                          |
| ------------ | ------------------------------ | -------------------------------------------------------------- |
| **OPNsense** | Bare-metal x86-64 / x86-64 VMs | FreeBSD-based, full-featured router/firewall OS.               |
| **pfSense**  | Bare-metal x86-64 / x86-64 VMs | FreeBSD-based (similar to OPNsense).                           |
| **OpenWRT**  | Bare-metal x86/ARM / VMs       | Lightweight Linux-based router OS (often used on ARM devices). |

***

#### **3. Hybrid Firewalls**

_(Can function as both host and network firewalls, depending on configuration)_

| Firewall       | OS Compatibility          | Notes                                                                                                     |
| -------------- | ------------------------- | --------------------------------------------------------------------------------------------------------- |
| **Suricata**   | Linux/macOS/Windows (WSL) | Primarily an IDS/IPS, but can enforce host _or_ network-level rules via integration with `pf`/`nftables`. |
| **Zeek (Bro)** | Linux/macOS/Windows (WSL) | Network analysis tool, but can trigger host-level scripts (e.g., block IPs via PF).                       |

***

#### **Key Differences**

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
