---
description: This section discusses major open source penetration testing technologies
---

# Penetration testing technologies

## Learning objectives <a href="#learning-objectives" id="learning-objectives"></a>

* Become familiar with major open source penetration testing technologies

This section discusses major open source penetration testing technologies, specifically, Nmap, OpenVAS, tcpdump, Metasploit, and Burp Suite/OWASP ZAP.

## Topics covered in this section <a href="#topics-covered-in-this-section" id="topics-covered-in-this-section"></a>

* **Penetration testing technologies: Core tools and their roles**
* **Nmap**
* **OpenVAS**
* **tcpdump**
* **Metasploit**
* **Burp Suite/OWASP ZAP**

### Penetration testing technologies: Core tools and their roles

Penetration testing relies on a suite of specialized tools to identify vulnerabilities, exploit weaknesses, and validate security postures. Among these, **Nmap**, **OpenVAS**, **tcpdump**, **Metasploit**, and **Burp Suite/OWASP ZAP** serve as foundational technologies, each addressing distinct phases of the penetration test—from reconnaissance to exploitation and post-exploitation.

**Nmap: Network Reconnaissance and Enumeration**

Nmap (_Network Mapper_) is the de facto standard for **host discovery**, **port scanning**, and **service enumeration**. Using techniques like SYN scans (`-sS`), OS fingerprinting (`-O`), and version detection (`-sV`), Nmap provides a detailed map of network assets. For example, during the **initial reconnaissance phase**, a pentester might use `nmap -A -T4 192.168.1.0/24` to aggressively scan a subnet, identifying open ports (e.g., SSH on 22, HTTP on 80) and potential attack vectors. Its scripting engine (`--script`) further automates tasks like vulnerability detection (e.g., `http-vuln-cve2021-44228` for Log4j).

**OpenVAS: Vulnerability Assessment**

While Nmap identifies live hosts and services, **OpenVAS** (Greenbone Vulnerability Management) specializes in **deep vulnerability scanning**. It leverages a continuously updated database of **CVEs** and **misconfigurations** to detect weaknesses like unpatched software (e.g., outdated Apache versions), default credentials, or SSL/TLS flaws. For instance, an OpenVAS scan might reveal a Windows host missing MS17-010 patches (EternalBlue), prompting further exploitation with Metasploit. Unlike Nmap’s lightweight scripts, OpenVAS performs **authenticated scans** (the vulnerability scanner logs into the target system using user credentials, e.g., a Windows domain account or local Linux user) for higher accuracy and deeper access, making it critical for compliance audits (e.g., PCI-DSS).

**Nmap vs OpenVAS: Functionality/capability comparison** 

Both Nmap and OpenVAS perform authenticated and unauthenticated scans.
But Nmap performs authenticated scans in a more limited, script-driven capacity.
Nmap's authenticated scanning is an extension of its scripting engine, not its core purpose, used for targeted information gathering.
Many of the advanced scripts of the Nmap Scripting Engine (NSE) can perform authenticated checks. For example, scripts can use provided credentials to log into a service (e.g., SSH, SMB, or HTTP) to gather more detailed information like system users, shared folders, or application configurations.


Both Nmap and OpenVAS use scripts, but OpenVAS's scripts are more comprehensive than Nmap's.
OpenVAS uses a system of Network Vulnerability Tests (NVTs). Think of NVTs as highly specialized, powerful scripts, each designed to check for a specific vulnerability (CVE), misconfiguration, or compliance policy. Its entire scanning engine is built upon executing these tens of thousands of NVTs from its continuously updated database.

**Nmap and OpenVAS Functionality/Capability Summary Table**

While Nmap excels at discovering live hosts and mapping network services, OpenVAS specializes in deep vulnerability assessment.

|Feature|Nmap|OpenVAS (GVM)|
|---|---|---|
|**Primary Purpose**|Network discovery, port scanning, service fingerprinting.|In-depth vulnerability detection and management.|
|**Scan Types**|Primarily **unauthenticated**. Supports limited **authenticated** checks via its scripting engine.|Comprehensive **unauthenticated** and **authenticated** scanning.|
|**"Scripting"**|Uses the **Nmap Scripting Engine (NSE)** for targeted tasks like banner grabbing or basic auth checks.|Uses **Network Vulnerability Tests (NVTs)**—a massive database of scripts for specific CVEs and misconfigurations.|
|**Example Finding**|"Port 443/https is open on host 192.168.1.10."|"Host 192.168.1.10 is vulnerable to CVE-2017-0144 (EternalBlue) due to a missing MS17-010 patch."|
|**Typical Use Case**|Initial reconnaissance, network inventory, security auditing.|Vulnerability management, compliance auditing (e.g., PCI-DSS), and penetration testing.|

In a typical workflow, a security professional might use Nmap first to find active hosts and open ports, and then use OpenVAS to perform a deep vulnerability scan against those discovered targets.

**tcpdump: Traffic Analysis and Forensics**

**tcpdump** provides **packet-level visibility** into network traffic, essential for **debugging attacks** or **monitoring suspicious activity**. During a penetration test, a tester might use `tcpdump -i eth0 port 80 -w http.pcap` to capture HTTP traffic for analysis (e.g., finding cleartext passwords). It’s also invaluable for **MITM (Man-in-the-Middle) attacks**—filtering ARP spoofing traffic (`tcpdump arp`) or extracting DNS queries (`port 53`). Unlike GUI tools like Wireshark, tcpdump is lightweight and scriptable, ideal for remote servers or stealthy operations.

**Metasploit: Exploitation and Post-Exploitation**

The **Metasploit Framework** automates exploitation and **post-exploitation workflows**. Its modular design includes **exploits** (e.g., `multi/handler` for reverse shells), **payloads** (e.g., Meterpreter), and **auxiliary modules** (e.g., SMB brute-forcing). For example, after identifying an unpatched SMB service via Nmap, a pentester could deploy `exploit/windows/smb/ms17_010_eternalblue` to gain a shell. Metasploit’s **post-modules** (e.g., `hashdump`, `mimikatz`) enable lateral movement, privilege escalation, and data exfiltration, simulating advanced persistent threats (APTs).

**Burp Suite: Web Application Testing**

**Burp Suite** dominates **web app penetration testing**, offering tools like:

* **Proxy** for intercepting/modifying requests (e.g., bypassing client-side validation).
* **Scanner** (Pro) to automate detection of SQLi, XSS, and CSRF.
* **Intruder** for brute-forcing logins or fuzzing endpoints.
* **Repeater** to manually test API vulnerabilities (e.g., insecure direct object references).

For example, Burp can intercept a JWT token, decode it in **Decoder**, and test for algorithm-switching attacks. Its **Collaborator** feature (Pro) helps detect blind SSRF or out-of-band (OOB) vulnerabilities.

**Burp Suite Professional vs. Community Edition**

Burp Suite is available in two versions: Burp Suite Professional (paid) and Community Edition. The key differences pertain to the following features:

- **Automated Scanning:** The core differentiator. **Pro has an automated active vulnerability scanner; Community does not.**
- **Manual Testing Tools:** **Pro offers unlimited use** of Intruder (fuzzing) and Repeater; Community's versions are rate-limited and lack advanced features.
- **Out-of-Band Testing:** **Pro includes Burp Collaborator** for detecting blind vulnerabilities; Community has no equivalent.
- **Workflow & Reporting:** **Pro has advanced workflow features** (task scheduler, saved configurations) and detailed reporting; Community's workflow is entirely manual.
- **Use Case:** **Pro is for professional, efficient testing;** Community is for learning, simple tasks, or manual-only testing.

**OWASP ZAP: Web Application Testing**

**OWASP ZAP** (Zed Attack Proxy) is a leading open-source web application security scanner, maintained under the **Open Web Application Security Project (OWASP)** umbrella. It is designed to be a comprehensive and accessible tool for finding vulnerabilities in web applications during both development and testing phases. Key features include an **intercepting proxy** for manual testing, **automated scanners** for passive and active vulnerability detection, and a suite of tools for fuzzing and spidering. For example, its **AJAX Spider** can effectively crawl modern, dynamic applications, while the **active scanner** can automatically test for flaws like SQL Injection and Cross-Site Scripting (XSS). ZAP's "heads-up display" (HUD) introduces a novel, integrated approach by providing security information and testing capabilities directly within the browser. Its open-source nature and strong community support make it a popular alternative to commercial scanners, especially for automated security testing in CI/CD pipelines.

**Comparison of Web Application Testing Tools**

| Feature/Capability                                   | Burp Suite Professional                                                                      | Burp Suite Community                    | OWASP ZAP                                                                                    |
| ---------------------------------------------------- | -------------------------------------------------------------------------------------------- | --------------------------------------- | -------------------------------------------------------------------------------------------- |
| **Licensing & Cost**                                 | Commercial (Paid)                                                                            | Free (Feature-Limited)                  | Fully Open-Source and Free                                                                   |
| **Primary Use Case**                                 | Professional, efficient manual & automated testing                                           | Learning and manual-only testing        | Manual testing, automated scanning, and CI/CD                                                |
| **Automated Scanning**                               | Yes (Advanced and configurable)                                                              | No                                      | Built-in automated (active & passive) scanner is fully featured                              |
| **Manual Testing Tools (Proxy, Repeater, Intruder)** | Full-Featured & Unlimited                                                                    | Basic & Rate-Limited (e.g., Intruder)   | Full-Featured & Unlimited (Comparable functionality)                                         |
| **Vulnerability Detection (e.g., SQLi, XSS)**        | Yes (Automated via Scanner)                                                                  | Manual discovery only                   | Yes (Automated via Scanner)                                                                  |
| **Out-of-Band Testing**                              | Yes (Burp Collaborator)                                                                      | No                                      | Via community scripts or external tools                                                      |
| **Extensibility**                                    | Extensive BApp Store for community-developed extensions                                      | BApp Store                              | Strong support for scripts and add-ons via a vibrant community marketplace                   |
| **CI/CD Integration**                                | Yes (Powerful APIs and scheduling)                                                           | Limited                                 | Yes (Strong native support for automation and CI/CD pipelines due to its open-source nature) |
| **Unique Features**                                  | Collaborator for detecting out-of-band vulnerabilities; Sequencer for session token analysis | Entry-point to Burp's core manual tools | Integrated HUD for in-browser testing; Traditional and AJAX Spidering combined               |

**Integration of the core tools in a Penetration Test**

The integration of these tools forms a **kill chain**:

1. **Nmap** scouts the network.
2. **OpenVAS** pinpoints vulnerabilities.
3. **tcpdump** monitors traffic during exploits.
4. **Metasploit** delivers payloads.
5. **Burp Suite/OWASP ZAP** tests web apps.

For instance, a tester might:

* Use Nmap to find an exposed WordPress site (`port 80`).
* Run OpenVAS to detect CVE-2022-3590 (SQLi in a plugin).
* Craft an exploit with **Metasploit’s** `wp_admin_shell_upload`.
* Capture session cookies via **Burp Proxy** to hijack an admin account.

Mastering these tools requires understanding their **strengths** and **limitations**. Nmap and OpenVAS excel at discovery, while Metasploit and Burp Suite drive exploitation. tcpdump provides low-level insights for advanced attacks. Together, they enable comprehensive security assessments, from **external network scans** to **web app hijacking**, aligning with **CEH** and **OSCP** methodologies.

### Key takeaways

* A skilled pentester chains these tools strategically, simulating real-world attacks to harden defenses.

### References

Stuttard, D., & Pinto, M. (2011). _The Web Application Hacker's Handbook: Finding and Exploiting Security Flaws_ (2nd ed.). Wiley.
