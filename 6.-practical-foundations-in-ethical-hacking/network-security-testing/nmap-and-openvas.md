---
hidden: true
---

# Nmap and OpenVAS

**Topics covered in this section**

Technology focus: Nmap

Technology focus: OpenVAS

Using Nmap and OpenVAS in vulnerability assessment and penetration testing

### Technology focus: Nmap

Nmap is highly versatile tool used for port scanning and network enumeration. Nmap also looks for services that are running on hosts by scanning TCP and UDP ports. Nmap is an integral part of every network security professional's tool kit (Deveriya, 2005).

Some of the routine (and cumbersome) netadmin tasks that Nmap can do are as follows:

* Verify unused IP addresses in a network&#x20;
* Verify available hosts in a network&#x20;
* Verify services running on a host in a network&#x20;
* Verify the firewall security configurations&#x20;
* Verify the OS running on a remote host&#x20;

Nmap uses Internet Control Message Protocol (ICMP) ping scans for network discovery as well as other scanning techniques using TCP and UDP packets. These techniques enable network scanning even if ICMP traffic is blocked in a network.

**Nmap** is best described as a **network scanning tool**, but it also functions as a **network security auditing and reconnaissance tool**. Here's why:

#### 1. **Primarily a Network Scanner**

* Nmap's core functionality is **host discovery, port scanning, and service/OS detection**.
* It excels at mapping networks, identifying live hosts, and determining what services are running.
* Example commands like `nmap -sS 192.168.1.1` highlight its scanning nature.

#### 2. **Security Testing & Auditing Capabilities**

* While not solely a security tool, Nmap is widely used for **vulnerability assessment and penetration testing**.
* Features like **NSE (Nmap Scripting Engine)** allow security-focused scans (e.g., detecting vulnerabilities with `nmap --script vuln`).
* It helps auditors check for misconfigurations (e.g., open ports, outdated services).

#### 3. **Beyond Just Scanning**

* Nmap can also perform **network inventory, monitoring, and troubleshooting**.
* Advanced uses include **firewall evasion, IDS testing, and raw packet manipulation**.

#### **Why Not Just a "Security Tool"?**

* While used heavily in cybersecurity, Nmap is also employed by **sysadmins for routine network management**, making "scanner" a more universal label.
* It doesn’t exploit vulnerabilities (like Metasploit) but provides data for further analysis.

**Best Description:** _Nmap is a powerful open-source network scanner used for discovery, security auditing, and network diagnostics._ This covers its primary role (scanning) while acknowledging its importance in security and administration.

### Technology focus: OpenVAS

OpenVAS (Open Vulnerability Assessment System) is a powerful open-source vulnerability scanner designed to detect and assess security weaknesses in networks, servers, and applications. Unlike general-purpose network scanners such as Nmap, which primarily focus on discovering hosts, services, and open ports, OpenVAS specializes in deep vulnerability analysis by leveraging a comprehensive database of known security flaws. It performs authenticated and unauthenticated scans, checks for outdated software, misconfigurations, and missing patches, and provides detailed risk assessments with remediation guidance. This makes OpenVAS particularly valuable for penetration testers and security teams prioritizing vulnerability management over basic reconnaissance.

While Nmap excels at fast, efficient network mapping and service enumeration, OpenVAS goes further by analyzing the identified services for specific vulnerabilities. Nmap’s scripting engine (NSE) can perform limited vulnerability checks, but OpenVAS offers a more systematic approach with regularly updated vulnerability tests (NVTs). Additionally, OpenVAS provides a centralized web interface for managing scans and reports, whereas Nmap is typically command-line driven and requires additional tools for in-depth vulnerability analysis. Together, they complement each other—Nmap for initial discovery and OpenVAS for thorough security assessment—but OpenVAS stands out as a dedicated solution for vulnerability scanning and compliance auditing.

### Using Nmap and OpenVAS in vulnerability assessment and penetration testing

Nmap and OpenVAS serve different but complementary roles in **vulnerability assessment (VA) and penetration testing (PT)**. Here’s a detailed comparison:

***

#### **1. Core Functionality**

| **Feature**                 | **Nmap**                                               | **OpenVAS (now Greenbone Vulnerability Management - GVM)**   |
| --------------------------- | ------------------------------------------------------ | ------------------------------------------------------------ |
| **Primary Purpose**         | Network discovery, port scanning, service/OS detection | Full vulnerability scanning and management                   |
| **Vulnerability Detection** | Basic (via NSE scripts)                                | Deep, using a constantly updated database (CVE, OVAL, etc.)  |
| **Automated Exploitation**  | No (only detection)                                    | No (but identifies exploitable vulnerabilities)              |
| **Reporting**               | Basic (text/XML)                                       | Advanced (HTML, PDF, with risk scoring and remediation tips) |

***

#### **2. Vulnerability Assessment (VA)**

**Nmap**

* **Strengths**:
  * Fast network reconnaissance (host discovery, open ports).
  * Can detect **potential vulnerabilities** using **NSE scripts** (e.g., `--script vuln`).
  * Useful for **initial scanning** before deeper VA.
* **Limitations**:
  * No built-in CVE database (relies on manual scripting).
  * Limited to **known service vulnerabilities** (e.g., outdated FTP/SSH versions).

**OpenVAS/GVM**

* **Strengths**:
  * **Comprehensive vulnerability database** (updated daily via NVT feeds).
  * Tests for **thousands of CVEs** (e.g., SQLi, XSS, misconfigurations).
  * Provides **risk scores (CVSS)** and remediation advice.
* **Limitations**:
  * Slower (performs deep scans).
  * Requires more resources (best for scheduled scans).

**Example Use Case**:

* **Nmap**: Quickly find open ports (`nmap -sV 192.168.1.0/24`).
* **OpenVAS**: Scan for **CVE-2023-1234** in a web app (`openvas-cli --target=192.168.1.10`).

***

#### **3. Penetration Testing (PT)**

**Nmap in PT**

* Used for **reconnaissance** (finding attack surfaces).
* Helps with **firewall evasion** (`-f`, `--script firewall-bypass`).
* Can feed data into **Metasploit** (e.g., `db_nmap`).

**OpenVAS in PT**

* **Not an exploitation tool**, but identifies **exploitable weaknesses**.
* Often used **before Metasploit** to find targets.

**PT Workflow Example**:

1. **Nmap** → Find open ports (`nmap -A -T4 target.com`).
2. **OpenVAS** → Deep scan for vulnerabilities (`openvas-scan target.com`).
3. **Metasploit** → Exploit flaws (e.g., `use exploit/multi/http/struts2_code_exec`).

***

#### **4. When to Use Each**

| **Scenario**            | **Nmap**  | **OpenVAS**        |
| ----------------------- | --------- | ------------------ |
| Quick network mapping   | ✅ Best    | ❌ Overkill         |
| Finding live hosts      | ✅ Fast    | ❌ Slow             |
| Deep vulnerability scan | ❌ Basic   | ✅ Best             |
| Compliance auditing     | ❌ Limited | ✅ (PCI-DSS, HIPAA) |
| Pre-exploitation recon  | ✅ Good    | ✅ Best             |

***

#### **5. Integration**

* **Nmap + OpenVAS**:
  * Use Nmap for **initial scanning**, then OpenVAS for **deep VA**.
  *   Example:

      bash

      ```
      nmap -Pn -p- --open 192.168.1.1-254 -oX targets.xml  
      openvas-cli --import-targets targets.xml  
      ```

***

#### **Final Verdict**

* **Nmap** = **Network scanner + light VA** (best for recon).
* **OpenVAS** = **Full vulnerability assessment** (best for compliance/PT prep).
* **For PT**: Use **both** (Nmap → OpenVAS → Metasploit/Burp Suite).
* Nmap finds the doors; OpenVAS checks if they’re unlocked.&#x20;
