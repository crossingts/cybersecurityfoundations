# Nmap and OpenVAS

Nmap and OpenVAS are two popular and complementary open source network scanners—Nmap identifies live hosts, open ports, and what services are running and OpenVAS automatically scans those hosts, ports, and services for known vulnerabilities.

### Technology focus: Nmap

Nmap is highly versatile tool for scanning and enumerating networks. Nmap also looks for services that are running on hosts by scanning TCP and UDP ports. Often referred to as the Swiss army knife of security tools, Nmap is an integral part of every network security professional's tool kit. (Deveriya, 2005, p. 366)

Netadmins routinely use Nmap to perform the following tasks:

* Verify unused IP addresses in a network 
* Verify available hosts in a network 
* Verify services running on a host in a network 
* Verify the firewall security configurations 
* Verify the OS running on a remote host 

Nmap uses Internet Control Message Protocol (ICMP) ping scans for network discovery as well as other scanning techniques using TCP and UDP packets. These techniques enable network scanning even if ICMP traffic is blocked in a network.

Nmap is a powerful open-source network scanner used for discovery, security auditing, reconnaissance, and diagnostics. While used heavily in cybersecurity, Nmap is also employed by sysadmins for routine network management.

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

### Technology focus: OpenVAS

OpenVAS (Open Vulnerability Assessment System) is a powerful open-source vulnerability scanner designed to detect and assess security weaknesses in networks, servers, and applications. Unlike general-purpose network scanners such as Nmap, which primarily focus on discovering hosts, services, and open ports, OpenVAS specializes in deep vulnerability analysis by leveraging a comprehensive database of known security flaws. It performs **authenticated and unauthenticated scans**, checks for outdated software, misconfigurations, and missing patches, and provides detailed risk assessments with remediation guidance. This makes OpenVAS particularly valuable for penetration testers and security teams prioritizing vulnerability management over basic reconnaissance.

While Nmap excels at fast, efficient network mapping and service enumeration, OpenVAS goes further by analyzing the identified services for specific vulnerabilities. Nmap’s scripting engine (NSE) can perform limited vulnerability checks, but OpenVAS offers a more systematic approach with regularly updated vulnerability tests (NVTs). Additionally, OpenVAS provides a centralized web interface for managing scans and reports, whereas Nmap is typically command-line driven and requires additional tools for in-depth vulnerability analysis. Together, they complement each other—Nmap for initial discovery and OpenVAS for thorough security assessment—but OpenVAS stands out as a dedicated solution for vulnerability scanning and compliance auditing.

**OpenVAS scans hosts, open ports, and services for vulnerabilities**

1. **Hosts**: OpenVAS can scan entire hosts (systems) for vulnerabilities, including OS-level flaws or misconfigurations.
2. **Open ports**: It checks which ports are open (as identified by Nmap or its own port-scanning) and analyzes them for vulnerabilities.
3. **Services**: It examines the services running on those ports (e.g., Apache, SSH, SMB) for known vulnerabilities.

### Using Nmap and OpenVAS in vulnerability assessment and penetration testing

Nmap and OpenVAS serve complementary roles in **vulnerability assessment (VA) and penetration testing (PT)**. Here’s a detailed comparison:

**1. Core Functionality**

| **Feature**                 | **Nmap**                                               | **OpenVAS (now Greenbone Vulnerability Management - GVM)**   |
| --------------------------- | ------------------------------------------------------ | ------------------------------------------------------------ |
| **Primary Purpose**         | Network discovery, port scanning, service/OS detection | Full vulnerability scanning and management                   |
| **Vulnerability Detection** | Basic (via NSE scripts)                                | Deep, using a constantly updated database (CVE, OVAL, etc.)  |
| **Automated Exploitation**  | No (only detection)                                    | No (but identifies exploitable vulnerabilities)              |
| **Reporting**               | Basic (text/XML)                                       | Advanced (HTML, PDF, with risk scoring and remediation tips) |

**2. Vulnerability Assessment (VA)**

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

- **Nmap:** Quickly find open ports (`nmap -sV 192.168.1.0/24`).
- **OpenVAS:** Scan for a specific vulnerability like **CVE-2021-44228 (Log4Shell)** in a web app. This is a critical Remote Code Execution vulnerability in the Apache Log4j library.

The CVE (Common Vulnerabilities and Exposures) Database is managed by MITRE Corporation. You can browse it at [https://cve.mitre.org/](https://cve.mitre.org/). The U.S. National Institute of Standards and Technology (NIST) provides the National Vulnerability Database (NVD), which enriches CVE entries with severity scores and patch information: [https://nvd.nist.gov/](https://nvd.nist.gov/). OpenVAS/GVM uses these sources to update its own database.

**3. Penetration Testing (PT)**

**Nmap in PT**

* Used for **reconnaissance** (finding attack surfaces).
* Helps with **firewall evasion** (`-f`, `--script firewall-bypass`).
* Can feed data into **Metasploit** (e.g., `db_nmap`).

**OpenVAS in PT**

- Not an exploitation tool, but identifies exploitable weaknesses.
- Often used before Metasploit to find high-value targets.
- OpenVAS does not feed data directly into Metasploit in the same automated way as Nmap's `db_nmap`. However, its reports are crucial for manually selecting and configuring exploits in Metasploit. A tester reads the OpenVAS report to find a confirmed vulnerability and then manually launches the corresponding Metasploit module.

**PT Workflow Example**:

1. **Nmap** → Find open ports (`nmap -A -T4 target.com`).
2. **OpenVAS** → Deep scan for vulnerabilities, identifying a specific exploitable CVE.
3. **Metasploit** → Manually select and launch the exploit based on the OpenVAS finding (e.g., `use exploit/multi/http/struts2_code_exec`).

**4. Comparison of Roles in VA vs PT**

The following table clarifies how these tools are typically used in each phase:

|Phase|Nmap Role|OpenVAS Role|
|---|---|---|
|**Vulnerability Assessment (VA)**|Initial discovery and network mapping. Lightweight, script-based vulnerability checks.|**Primary Tool.** Comprehensive, credentialed scanning to identify and report on known vulnerabilities for patching and compliance.|
|**Penetration Testing (PT)**|**Reconnaissance.** Discovers targets and identifies potential attack vectors (open ports, services).|**Vulnerability Identification.** Pinpoints specific, exploitable vulnerabilities to guide the exploitation phase.|

**5. Integration**

- **Nmap + OpenVAS:**
    - Use Nmap for initial scanning, then OpenVAS for deep VA. Use Nmap to find live hosts with open ports. Import the Nmap results into OpenVAS for a targeted vulnerability scan.
    - Example:
      bash

      ```
      nmap -Pn -p- --open 192.168.1.1-254 -oX targets.xml  
      openvas-cli --import-targets targets.xml  
      ```

**Conclusion**

- **Nmap** = Network scanner + light VA (best for recon).
- **OpenVAS** = Full vulnerability assessment (best for compliance/PT prep).
- For PT: Use both (Nmap → OpenVAS → Metasploit/Burp Suite).
- **Nmap** finds the doors; **OpenVAS** checks which ones are unlocked and reports on the weak locks; **Metasploit** picks the locks.
