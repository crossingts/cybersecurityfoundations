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

**Design pipeline 1 (ARM64):**&#x20;

nftables (firewall) + Suricata (IDS/IPS) + web server (Apache) + database server (MySQL) + Wazuh (SIEM/XDR) + Kali Linux

Cybersecurity virtual lab in VMware Fusion on M1 Mac

* [Lab design and configuring interfaces](https://drive.proton.me/urls/TM4PKAVGM4#48yHrBXTk0nA)
* [Testing/troubleshooting network connectivity](https://drive.proton.me/urls/VRKY3A12FC#Vjc5DoAfwaHh)
* [Configuring nftables on the Debian firewall](https://drive.proton.me/urls/6CWHJ0269M#Se4xqwyz4UNv)
* [Configuring Suricata on the Debian IDS/IPS](https://drive.proton.me/urls/NH9SG0ZZW4#QOf2lieJuOTS)
* [Setting up Apache HTTP Server on Ubuntu](https://drive.proton.me/urls/9NJRE0HBNR#V6Lb057YQUeF)
* [Setting up MySQL Server on Ubuntu](https://drive.proton.me/urls/XG01TWTEX0#R4dutVB8XUq5)
* [Setting up Wazuh (SIEM/XDR) on Ubuntu server](https://drive.proton.me/urls/R74XWK7XSW#7x1OsbPmpCmr)
* Setting up Kali Linux for security testing

**Design pipeline 2 (AMD64):**&#x20;

OPNsense (firewall) + Suricata (IDS/IPS) + web server (Apache) and/or database server (MySQL) + Wazuh (SIEM/XDR) + Kali Linux

Inspiration/example set up: YouTube playlist (16 videos +150,000 views)

[Virtual Cyber Security Lab Building Series by LS111 Cyber Security Education](https://www.youtube.com/playlist?list=PLjjkJroii8DDb0QZpWLo978VXcLp8-xW3)

<figure><img src="../../.gitbook/assets/image (16).png" alt=""><figcaption><p>Cybersecurity virtual lab design (courtesy of LS111 Cyber Security Education)</p></figcaption></figure>

**Design pipeline 3 (AMD64):**&#x20;

pfSense (firewall) + Snort (IDS/IPS) + web server (Apache) and/or database server (MySQL) + Wazuh (SIEM/XDR) + Kali Linux

**🔥 Open Source Firewall Compatibility Table**

**Key:** ✔ = Supported | ✕ = Not Supported | _Bare Metal = replaces host OS_

| Firewall      | Linux Host (x86/ARM) | Windows Host (x86) | macOS Host (Intel) | macOS Host (ARM) | Notes                                                              |
| ------------- | -------------------- | ------------------ | ------------------ | ---------------- | ------------------------------------------------------------------ |
| **OPNsense**  | ✔ (VM)               | ✔ (VM)             | ✔ (VM)             | ✕                | FreeBSD-based. Bare metal requires wiping host OS. No ARM support. |
| **pfSense**   | ✔ (VM)               | ✔ (VM)             | ✔ (VM)             | ✕                | FreeBSD-based, same as OPNsense.                                   |
| **IPTables**  | ✔ (Native)           | ✕                  | ✕                  | ✕                | Legacy Linux kernel firewall.                                      |
| **nftables**  | ✔ (Native)           | ✕                  | ✕                  | ✕                | Modern Linux firewall (replaces IPTables).                         |
| **UFW**       | ✔ (Native)           | ✕                  | ✕                  | ✕                | Ubuntu/Debian simplified firewall.                                 |
| **Firewalld** | ✔ (Native)           | ✕                  | ✕                  | ✕                | RHEL/CentOS frontend for IPTables/nftables.                        |
| **macOS PF**  | ✕                    | ✕                  | ✔ (Native)         | ✔ (Native)       | Built-in BSD `pf` firewall (CLI-only).                             |

**Clarifications:**

1. **OPNsense/pfSense:**
   * **VM Support:** Works on x86 hosts (Linux/Windows/Intel macOS).
   * **macOS ARM:** ✕ No VM support (FreeBSD lacks ARM virtualization drivers).
   * **Bare Metal:** x86 only (wipes host OS).
2. **Linux Firewalls (IPTables/nftables/UFW/Firewalld):**
   * **Native to Linux** (no VM or cross-platform support).
3. **macOS PF:**
   * Native on both Intel/ARM Macs (CLI-only).

**🛡️ Open Source IDS/IPS Compatibility Table**

**Key:** ✔ = Supported | ✕ = Not Supported | ⚠ = Partial/Experimental

| Technology     | Linux Host (x86/ARM) | Windows Host (x86) | macOS Host (Intel/ARM) | Notes                                                                   |
| -------------- | -------------------- | ------------------ | ---------------------- | ----------------------------------------------------------------------- |
| **Suricata**   | ✔ (Native/VM)        | ✔ (Native/WSL2)    | ✔ (Native/VM)          | Multi-threaded, supports inline IPS. ARM64 works on Raspberry Pi 4+.    |
| **Zeek (Bro)** | ✔ (Native)           | ⚠ (WSL2/Cygwin)    | ✔ (Native)             | Network analysis, not real-time IPS. ARM64 supported via source builds. |
| **Snort**      | ✔ (Native)           | ✔ (Native)         | ✔ (Native)             | Legacy IDS/IPS. ARM support limited.                                    |

**Clarifications**

* **Windows Subsystem for Linux (WSL)**
  * Lets you run Linux binaries natively on Windows.
  * ⚠️ Limited networking (WSL2 uses a virtual NIC).
* **x86-64**&#x20;
  * x86-64 is also known as x64, x86\_64, AMD64, and Intel 64.
  * x86-64 is a CPU architecture. It is used by:
    * Windows (e.g., Windows 10/11 x64).
    * Linux (x86-64 distributions).
    * FreeBSD (OPNsense’s base).
    * macOS (Intel Macs).

***

### Choose a virtualization environment/tool

Choose a project documentation platform/method

Build the lab: Configure subnet interfaces and verify connectivity

Build the lab: Configure and verify the firewall
