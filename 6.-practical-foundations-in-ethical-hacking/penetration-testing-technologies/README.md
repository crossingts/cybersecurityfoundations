---
description: This section discusses major open source penetration testing technologies
---

# Penetration testing technologies

## Learning objectives <a href="#learning-objectives" id="learning-objectives"></a>

- Become familiar with core features and primary use cases of major open source penetration testing technologies
- Differentiate between the functionalities of key tools, such as network mapping (Nmap) and vulnerability scanning (OpenVAS)
- Understand how these technologies integrate to form a comprehensive penetration testing kill chain

This section provides a comprehensive overview of the major open source technologies that form the backbone of modern penetration testing. We explore the core features and practical applications of essential tools, including Nmap for network discovery, OpenVAS for vulnerability scanning, tcpdump for traffic analysis, Metasploit for exploitation, and Burp Suite/OWASP ZAP for web application security. Understanding the distinct role of each tool as well as how tools complement each other is fundamental to executing a systematic and effective security assessment.

## Topics covered in this section <a href="#topics-covered-in-this-section" id="topics-covered-in-this-section"></a>

* **Introduction**
* **Nmap: Network reconnaissance and enumeration**
* **OpenVAS: Vulnerability assessment**
* **tcpdump: Traffic analysis and forensics**
* **Metasploit: Exploitation and post-exploitation**
* **Burp Suite**
* **OWASP ZAP**

### Introduction

Penetration testing relies on a suite of specialized tools to systematically identify vulnerabilities, exploit weaknesses, and validate an organization's security posture. This process, often conceptualized as a "kill chain", involves "sequential" phases such as reconnaissance, scanning and enumeration, gaining access, and maintaining access. Among the vast array of available utilities, Nmap, OpenVAS, tcpdump, Metasploit, and Burp Suite/OWASP ZAP serve as core technologies, each addressing distinct phases of the penetration test lifecycle. Mastering this toolkit is not just about learning individual commands but understanding how to strategically chain these tools together to simulate sophisticated attacks and provide actionable insights for hardening defenses.

### Nmap: Network reconnaissance and enumeration

Nmap (Network Mapper) is the de facto standard for host discovery, port scanning, and service enumeration. Using techniques like SYN scans (`-sS`), OS fingerprinting (`-O`), and version detection (`-sV`), Nmap provides a detailed map of network assets. For example, during the initial reconnaissance phase, a pentester might use `nmap -A -T4 192.168.1.0/24` to aggressively scan a subnet, identifying open ports (e.g., SSH on 22, HTTP on 80) and potential attack vectors. Its scripting engine (`--script`) further automates tasks like vulnerability detection (e.g., `http-vuln-cve2021-44228` for Log4j).

Beyond its core scanning capabilities, the Nmap Scripting Engine (NSE) vastly extends its functionality for more targeted reconnaissance. Hundreds of scripts are available for tasks such as checking for common misconfigurations, brute-forcing credentials, and even exploiting specific vulnerabilities. For instance, the `http-enum` script can discover hidden web directories, while the `smb-os-discovery` script can extract detailed information from Windows hosts without authentication. This makes Nmap not just a mapper, but a versatile tool for initial vulnerability probing and data gathering, often providing the critical first pieces of information needed to launch further attacks.

### OpenVAS: Vulnerability assessment

While Nmap identifies live hosts and services, OpenVAS specializes in deep vulnerability scanning. It leverages a continuously updated database of CVEs and misconfigurations to detect weaknesses like unpatched software (e.g., outdated Apache versions), default credentials, or SSL/TLS flaws. For instance, an OpenVAS scan might reveal a Windows host missing MS17-010 patches (EternalBlue), prompting further exploitation with Metasploit. OpenVAS can perform authenticated scans (the vulnerability scanner logs into the target system using user credentials, e.g., a Windows domain account or local Linux user) for deeper access, making it critical for compliance audits (e.g., PCI-DSS).

A key strength of OpenVAS is its structured approach to vulnerability management. Scan results are prioritized by severity (Critical, High, Medium, Low), providing a clear roadmap for remediation efforts. OpenVAS provides detailed information for each finding, including the associated CVE, a description of the vulnerability, its potential impact, and often a solution for patching or mitigation. This transforms raw scan data into an actionable report, enabling security teams to focus on the most critical risks first. This comprehensive and auditable process is essential for meeting regulatory requirements and maintaining a strong security posture over time.

#### Nmap vs OpenVAS: Functionality/capability comparison 

Both Nmap and OpenVAS perform authenticated and unauthenticated scans. But Nmap performs authenticated scans in a more limited, script-driven capacity. Nmap's authenticated scanning is an extension of its scripting engine, not its core purpose. Many advanced scripts of the Nmap Scripting Engine (NSE) can perform authenticated checks, used for targeted information gathering. For example, scripts can use provided credentials to log into a service (e.g., SSH, SMB, or HTTP) to gather more detailed information such as system users, shared folders, or application configurations.

The majority of OpenVAS's checks are performed remotely without credentials. This includes testing for unpatched services (e.g., an outdated Apache version), checking for default credentials on network services, and identifying SSL/TLS flaws. OpenVAS can also be configured with credentials to perform deeper, targeted checks. This is a separate, powerful feature that allows it to find vulnerabilities like missing software patches (e.g., the MS17-010 EternalBlue patch) by checking the system's internal version data, rather than relying on external probes alone.

Both Nmap and OpenVAS use scripts, but OpenVAS's scripts are more comprehensive than Nmap's. OpenVAS uses a system of Network Vulnerability Tests (NVTs). Think of NVTs as specialized scripts each designed to check for a specific vulnerability (CVE), misconfiguration, or compliance policy. OpenVAS's entire scanning engine is built upon executing these tens of thousands of NVTs from its continuously updated database.

**Nmap's Two-Layer Capabilities**

To understand Nmap's capabilities, it's helpful to think of it as consisting of two layers:

1. **The Core Engine**: This is Nmap's fundamental functionality for unauthenticated scanning:
- Host Discovery (`-sn`)
- Port Scanning (`-sS`, `-sT`, etc.)
- Service & Version Detection (`-sV`)
- OS Fingerprinting (`-O`)

2. **The Nmap Scripting Engine (NSE)**: This is an add-on system that extends the core engine. It allows users to run scripts for more advanced, specific tasks. The NSE is where Nmap's authenticated scanning happens.

**How NSE Enables Authenticated Scans**

The NSE provides a framework where scripts can be passed credentials (usernames/passwords/keys) via command-line arguments. These scripts then use those credentials to log into services and perform deeper checks.

**Examples of NSE scripts doing authenticated scanning:**

- **`smb-brute`**: Takes a list of usernames and passwords to brute-force SMB (Windows file sharing) logins.
- **`http-auth-finder`**: Can use provided credentials to access protected web pages and look for authentication forms.
- **`ssh-auth-methods`**: Can use an SSH key to log in and check which authentication methods are supported.

**Nmap and OpenVAS Functionality/Capability Summary Table**

While Nmap excels at discovering live hosts and mapping network services, OpenVAS specializes in deep vulnerability assessment.

| Feature              | Nmap                                                                                               | OpenVAS                                                                                                        |
| -------------------- | -------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- |
| **Primary Purpose**  | Network discovery, port scanning, service fingerprinting.                                          | In-depth vulnerability detection and management.                                                               |
| **Scan Types**       | Primarily unauthenticated. Supports limited authenticated checks via its scripting engine.         | Comprehensive unauthenticated and authenticated scanning.                                                      |
| **Scripting**        | Uses the Nmap Scripting Engine (NSE) for targeted tasks like banner grabbing or basic auth checks. | Uses Network Vulnerability Tests (NVTs)—a massive database of scripts for specific CVEs and misconfigurations. |
| **Example Finding**  | "Port 443/https is open on host 192.168.1.10."                                                     | "Host 192.168.1.10 is vulnerable to CVE-2017-0144 (EternalBlue) due to a missing MS17-010 patch."              |
| **Typical Use Case** | Initial reconnaissance, network inventory, security auditing.                                      | Vulnerability management, compliance auditing (e.g., PCI-DSS), and penetration testing.                        |

**When to Use Each**

| **Scenario**            | **Nmap**  | **OpenVAS**        |
| ----------------------- | --------- | ------------------ |
| Quick network mapping   | ✅ Best    | ❌ Overkill         |
| Finding live hosts      | ✅ Fast    | ❌ Slow             |
| Deep vulnerability scan | ❌ Basic   | ✅ Best             |
| Compliance auditing     | ❌ Limited | ✅ (PCI-DSS, HIPAA) |
| Pre-exploitation recon  | ✅ Good    | ✅ Best             |

In a typical workflow, a security professional might use Nmap first to find active hosts and open ports, and then use OpenVAS to perform a deep vulnerability scan against those discovered targets.

### tcpdump: Traffic analysis and forensics

tcpdump provides packet-level visibility into network traffic, essential for debugging attacks or monitoring suspicious activity. During a penetration test, a tester might use `tcpdump -i eth0 port 80 -w http.pcap` to capture HTTP traffic for analysis (e.g., finding cleartext passwords). It’s also invaluable for MITM (Man-in-the-Middle) attacks—filtering ARP spoofing traffic (`tcpdump arp`) or extracting DNS queries (`port 53`). Unlike GUI tools like Wireshark, tcpdump is lightweight and scriptable, ideal for remote servers or stealthy operations.

The true power of tcpdump lies in its sophisticated filtering capabilities, which allow a tester to isolate specific traffic patterns from a high-volume data stream. Filters can be built using Boolean logic and primitives for hosts, networks, protocols, and port numbers. For example, the command `tcpdump -i any 'host 192.168.1.5 and tcp port 443'` would capture only encrypted web traffic to or from the specific target, reducing noise. To detect potential network scanning, a filter like `tcpdump 'tcp[13] & 2!=0'` (`tcpdump 'tcp[tcpflags] == tcp-syn'`) captures only TCP SYN packets, which often indicate a port scan in progress. Mastering these filters is critical for efficient evidence collection and real-time threat detection during an engagement.

Furthermore, tcpdump is indispensable for forensic analysis and validating exploit delivery. After an attack vector is exploited, a penetration tester can use tcpdump to capture the exact network packets exchanged, providing proof of a vulnerability. For instance, while launching a reverse shell payload from Metasploit, running tcpdump on the target network can capture the outgoing connection attempt back to the attacker's machine. This packet capture (pcap) file can be analyzed to see the raw shellcode transmission or to extract files transferred over the network, such as exfiltrated data or uploaded tools. This ability to record and review the precise sequence of network events makes it an essential tool for both attack simulation and incident response.

### Metasploit: Exploitation and post-exploitation

The Metasploit Framework automates exploitation and post-exploitation workflows. Its modular design includes exploits (e.g., `multi/handler` for reverse shells), payloads (e.g., Meterpreter), and auxiliary modules (e.g., SMB brute-forcing). For example, after identifying an unpatched SMB service via Nmap, a pentester could deploy `exploit/windows/smb/ms17_010_eternalblue` to gain a shell. Metasploit’s post-modules (e.g., `hashdump`, `mimikatz`) enable lateral movement, privilege escalation, and data exfiltration, simulating advanced persistent threats (APTs).

A typical exploitation workflow within Metasploit follows a structured sequence. A tester begins by selecting an exploit (`use exploit/windows/smb/ms17_010_eternalblue`), then configures the required options such as the target host (`set RHOSTS 192.168.1.10`) and port (`set RPORT 445`). Next, a payload is chosen and configured (`set PAYLOAD windows/x64/meterpreter/reverse_tcp` and `set LHOST 192.168.1.5`). Upon executing the `exploit` command, if successful, the framework delivers the payload and establishes a session, providing the tester with remote access to the target machine. This streamlined process turns a known vulnerability into a concrete access point with minimal manual effort.

Beyond initial access, Metasploit's true power is its extensive post-exploitation capabilities, largely delivered through the Meterpreter payload. Meterpreter provides a robust, in-memory command-and-control agent that avoids writing to the disk, reducing the chance of detection. From a Meterpreter session, a tester can perform a wide array of actions, such as keylogging, taking screenshots, pivoting to other networks, and maintaining persistence. Furthermore, the `load` command within Meterpreter can extend its functionality on-the-fly, for instance by loading the `kiwi` module to interface with the Mimikatz tool for credential dumping directly from memory. This makes Metasploit an all-in-one platform for not just breaking in, but for thoroughly exploring what an attacker can accomplish once inside a network.

### Burp Suite

Burp Suite is available in two versions: Burp Suite Professional (paid) and Burp Suite Community Edition. 

Burp Suite dominates web app penetration testing, offering tools like:

* **Proxy** for intercepting/modifying requests (e.g., bypassing client-side validation).
* **Scanner** (Pro) to automate detection of SQLi, XSS, and CSRF.
* **Intruder** for brute-forcing logins or fuzzing endpoints.
* **Repeater** to manually test API vulnerabilities (e.g., insecure direct object references).
* **Collaborator** (Pro) for detecting blind SSRF or out-of-band (OOB) vulnerabilities.

For example, Burp can intercept a JWT token, decode it in Decoder, and test for algorithm-switching attacks. 

#### Burp Suite Professional vs. Community Edition

The key differences between Burp Suite Professional and Burp Suite Community Edition pertain to the following features:

- **Automated Scanning:** The core differentiator. Pro has an automated active vulnerability scanner; Community does not.
- **Manual Testing Tools:** **Pro offers unlimited use** of Intruder (fuzzing) and Repeater; Community's versions are rate-limited and lack advanced features.
- **Out-of-Band Testing:** **Pro includes Burp Collaborator** for detecting blind SSRF or out-of-band (OOB) vulnerabilities; Community has no equivalent.
- **Workflow & Reporting:** **Pro has advanced workflow features** (task scheduler, saved configurations) and detailed reporting; Community's workflow is entirely manual.
- **Use Case:** **Pro is for professional, efficient testing;** Community is for learning, simple tasks, or manual-only testing.

### OWASP ZAP

OWASP ZAP (Zed Attack Proxy) is a leading open-source web application security scanner, maintained under the Open Web Application Security Project (OWASP) umbrella. It is designed to be a comprehensive and accessible tool for finding vulnerabilities in web applications during both development and testing phases. Key features include an intercepting proxy for manual testing, automated scanners for passive and active vulnerability detection, and a suite of tools for fuzzing and spidering. For example, its AJAX Spider can effectively crawl modern, dynamic applications, while the active scanner can automatically test for flaws like SQL Injection and Cross-Site Scripting (XSS). ZAP's "heads-up display" (HUD) introduces a novel, integrated approach by providing security information and testing capabilities directly within the browser. Its open-source nature and strong community support make it a popular alternative to commercial scanners, especially for automated security testing in CI/CD pipelines.

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

The integration of these core tools in a penetration test forms a kill chain:

1. **Nmap** scouts the network.
2. **OpenVAS** pinpoints vulnerabilities.
3. **tcpdump** monitors traffic during exploits.
4. **Metasploit** delivers payloads.
5. **Burp Suite/OWASP ZAP** tests web apps.

For instance, a tester might:

* Use Nmap to find an exposed WordPress site (`port 80`).
* Run OpenVAS to detect CVE-2022-3590 (SQLi in a plugin).
* Craft an exploit with Metasploit’s `wp_admin_shell_upload`.
* Capture session cookies via Burp Proxy to hijack an admin account.

Mastering these tools requires understanding their strengths and limitations. Nmap and OpenVAS excel at discovery, while Metasploit and Burp Suite/ZAP drive exploitation. tcpdump provides low-level insights for advanced attacks. Together, they enable comprehensive security assessments, from external network scans to web app hijacking, aligning with CEH and OSCP methodologies.

### Key takeaways

* A skilled pentester chains testing tools strategically, simulating real-world attacks to harden defenses.

### References

Stuttard, D., & Pinto, M. (2011). _The Web Application Hacker's Handbook: Finding and Exploiting Security Flaws_ (2nd ed.). Wiley.
