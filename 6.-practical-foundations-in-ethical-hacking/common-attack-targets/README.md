---
description: This section explores common cyber attack targets—vulnerability categories and weaknesses that attackers exploit—and associated attack vectors
---

# Common attack targets

## Learning objectives

- Compare historical and modern vulnerability taxonomies, including NIST SP 800-115, OWASP Top 10, and CWE
- Analyze common vulnerability categories, their attack vectors, and real-world exploits
- Distinguish between the roles of CWE, CVE, and NVD in categorizing and tracking vulnerabilities
- Prioritize vulnerabilities based on CVSS severity, exploitability, and potential impact
- Identify key tools for detecting, exploiting, and mitigating prioritized vulnerabilities
- Develop a structured response playbook for addressing critical security flaws

This section explores the most common and critical cybersecurity attack targets and associated attack vectors—where "targets" refers to vulnerability categories and weaknesses that attackers exploit, rather than specific asset types like servers or databases. We begin by examining the historical foundation of NIST SP 800-115's vulnerability categories, then transition to modern, community-driven frameworks that define today's attack landscape: the OWASP Top 10 for web application risks, the Common Weakness Enumeration (CWE) for root-cause flaws, and the Common Vulnerabilities and Exposures (CVE) system alongside the National Vulnerability Database (NVD) for tracking specific instances. By understanding the evolution and current state of these frameworks, you will learn to prioritize vulnerabilities based on severity and exploitability, and develop practical strategies for their detection, exploitation, and mitigation.

## Topics covered in this section

* **Introduction**
* **NIST SP 800-115's attack categories**
* **OWASP Top 10**
* **Common Weakness Enumeration (CWE™)**
* **Common Vulnerabilities and Exposures (CVE®) & NVD**
* **Prioritized attack categories**
* **Detection, exploitation, and mitigation of prioritized vulnerabilities**

### Introduction

When it comes to categorizing common vulnerabilities targeted by malicious hackers and penetration testers, the NIST SP 800-115: Technical Guide to Information Security Testing and Assessment (Scarfone et al., 2008) categories of vulnerabilities are a logical starting point. While the high-level principles and methodology of penetration testing in NIST SP 800-115 are still sound, the taxonomy of vulnerabilities is significantly outdated. The attack landscape has evolved, primarily towards web applications, identity-based attacks, APIs, and cloud services.

A modern, practical taxonomy of attack categories can be anchored in the following three frameworks:

* **OWASP Top 10:** The de facto standard for categorizing critical risks in web applications.
* **Common Weakness Enumeration (CWE):** The authoritative list for classifying the root cause of software vulnerabilities.
* **Common Vulnerabilities and Exposures (CVE) & the National Vulnerability Database (NVD):** The systems for tracking specific instances of vulnerabilities in software products.

These three frameworks reflect an evolving attack landscape prioritizing the following categories of vulnerabilities:

* **Web Application Flaws:** Injection (SQLi, OS Command), XSS, Broken Access Control (IDOR).
* **Security Misconfigurations:** Cloud storage (S3) buckets, default credentials, unnecessary services.
* **Identity and Access Issues:** Weak passwords, lack of multi-factor authentication, privilege escalation.
* **Outdated Software:** Unpatched systems with known CVEs.

### NIST SP 800-115's attack categories

The majority of vulnerabilities exploited during penetration testing fall into the following categories (Scarfone et al., 2008, pp. 5-4-5-5):

* Misconfigurations. Misconfigured security settings, particularly insecure default settings, are usually easily exploitable.
* Kernel Flaws. Kernel code is the core of an OS, and enforces the overall security model for the system—so any security flaw in the kernel puts the entire system in danger.
* Buffer Overflows. A buffer overflow occurs when programs do not adequately check input for appropriate length. When this occurs, arbitrary code can be introduced into the system and executed with the privileges—often at the administrative level—of the running program.
* Insufficient Input Validation. Many applications fail to fully validate the input they receive from users. An example is a Web application that embeds a value from a user in a database query. If the user enters SQL commands instead of or in addition to the requested value, and the Web application does not filter the SQL commands, the query may be run with malicious changes that the user requested—causing what is known as a SQL injection attack.
* Symbolic Links. A symbolic link (symlink) is a file that points to another file. Operating systems include programs that can change the permissions granted to a file. If these programs run with privileged permissions, a user could strategically create symlinks to trick these programs into modifying or listing critical system files.
* File Descriptor Attacks. File descriptors are numbers used by the system to keep track of files in lieu of filenames. Specific types of file descriptors have implied uses. When a privileged program assigns an inappropriate file descriptor, it exposes that file to compromise.
* Race Conditions. Race conditions can occur during the time a program or process has entered into a privileged mode. A user can time an attack to take advantage of elevated privileges while the program or process is still in the privileged mode.
* Incorrect File and Directory Permissions. File and directory permissions control the access assigned to users and processes. Poor permissions could allow many types of attacks, including the reading or writing of password files or additions to the list of trusted remote hosts.

**NIST SP 800-115 Vulnerabilities Mapped to Their Typical Attack Targets**

| **Vulnerability Category**                | **Attack Target**                                       | **Attack Vector**                                                                           | **Example Exploit**                                                                                                                               |
| ----------------------------------------- | ------------------------------------------------------- | ------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Security Misconfigurations**            | Cloud, Servers, Containers, OS, Databases, Applications | Exposed admin interfaces, verbose errors, insecure settings                                 | **Kubernetes dashboard exposed** (CVE-2018-18264), **Jenkins RCE** (misconfigured scripts), Accessing admin panels with `admin:admin` credentials |
| **Misconfigurations (Insecure Defaults)** | Servers, Cloud, IoT, APIs, Network Devices              | Default credentials, open ports, exposed interfaces, insecure default settings              | **Mirai botnet** (exploited default IoT passwords), **AWS S3 bucket leaks** (public-by-default)                                                   |
| **Kernel Flaws**                          | OS (Linux/Windows/macOS), Operating System              | Privilege escalation via kernel bugs, kernel exploits                                       | **Dirty Pipe** (CVE-2022-0847) for root access, **Dirty COW** (CVE-2016-5195)                                                                     |
| **Buffer Overflows**                      | Applications, OS, Services                              | Crafted input overflowing memory, overflowing memory to execute shellcode                   | **EternalBlue** (MS17-010), **Code Red worm** (IIS buffer overflow), Stack-based overflow in legacy FTP servers                                   |
| **Insufficient Input Validation**         | Web apps, APIs, Databases                               | SQLi, XSS, Command Injection                                                                | **Equifax breach** (SQLi, CVE-2017-5638), **Log4Shell** (CVE-2021-44228), Bypassing login forms with `' OR 1=1 --`                                |
| **Symbolic Links (Symlink)**              | File systems, Privileged apps                           | Tricking apps into writing to sensitive files, tricking privileged processes to write files | **Docker symlink escape** (CVE-2018-15664), Symlink attacks in `/tmp` directories                                                                 |
| **File Descriptor Issues**                | OS, Applications, Running Processes                     | Exploiting unclosed file handles, accessing sensitive files left open                       | **Heartbleed** (CVE-2014-0160) via OpenSSL file descriptor leaks, Reading `/etc/passwd` from a crashed service                                    |
| **Race Conditions (TOCTOU)**              | OS, Applications, Concurrent Systems                    | Timing attacks to bypass checks, TOCTOU (Time-of-Check to Time-of-Use) attacks              | Linux `ptrace` race condition (CVE-2019-13272), Changing file permissions between check and use                                                   |
| **Incorrect File/Directory Permissions**  | OS, Databases, Apps, File Systems                       | Unauthorized access/modification, reading/writing restricted files                          | **MongoDB ransomware attacks** (exposed databases with weak permissions), `chmod 777` exposing SSH private keys                                   |

### OWASP Top 10

The Open Worldwide Application Security Project (OWASP) is a non-profit foundation that works to improve the security of software through community-led open-source projects. Its flagship project is the OWASP Top 10, a regularly updated document that catalogues the most critical security risks to web applications.

While NIST SP 800-115 offers a general, system-level view of vulnerabilities, the OWASP Top 10 provides a specialized, application-centric focus. First published in 2003, the OWASP Top 10 is based on real-world data from thousands of applications and vulnerabilities. The OWASP Top 10 serves as a vital benchmark for developers, auditors, and penetration testers, and is referenced by many standards, including the Payment Card Industry Data Security Standard (PCI DSS) and U.S. government frameworks.

For penetration testers, the OWASP Top 10 provides a prioritized checklist of what to look for. This is operationalized through the OWASP Web Security Testing Guide (WSTG), a comprehensive manual that outlines how to test for each category of vulnerability. The testing methodology in the WSTG mirrors a real-world engagement, starting with information gathering and configuration management testing, then moving into deep assessments of authentication, authorization, and business logic, with dedicated sections for testing each Top 10 risk.

Both the OWASP Top 10 and NIST SP 800-115 frameworks share several core themes, notably:
 
* **Input Validation:** NIST's "Insufficient Input Validation" category is directly reflected in OWASP's A03:2021-Injection.
* **Misconfigurations:** NIST's "Misconfigurations" are a primary focus of OWASP A05:2021-Security Misconfiguration.
* **Access Control:** The principle behind NIST's "Incorrect File and Directory Permissions" is expanded in the web context by OWASP A01:2021-Broken Access Control.

### Common Weakness Enumeration (CWE™)

NIST itself now primarily uses the CWE list as the authoritative source for types of software weaknesses. This is a much more granular and detailed community-developed list of common software and hardware security weaknesses which serves as a common language for describing vulnerabilities. MITRE maintains and hosts the official CWE list (on cwe.mitre.org). It owns the intellectual property and is responsible for its structure and integrity.

Penetration testers use the CWE to classify the root cause of the flaws they find. The CWE Top 25 Most Dangerous Software Weaknesses is the spiritual successor to NIST's 2008 list and it is updated regularly based on real-world data.

**Mapping NIST's 2008 List to the 2023 CWE Top 25**

| 2008 Category (NIST SP 800-115)   | Modern Equivalent (CWE Top 25, 2023)                                                                                                                                                                                                                                                                                                                                                                      | Why it's Updated / Refined                                         |
| --------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| **Insufficient Input Validation** | [**CWE-79: Improper Neutralization of Input During Web Page Generation (XSS)**](https://cwe.mitre.org/data/definitions/79.html)                                                                                                                                                                                                                                                                           | This is more specific. "Input Validation" is too broad.            |
| **Buffer Overflows**              | [**CWE-787: Out-of-bounds Write**](https://cwe.mitre.org/data/definitions/787.html) & [**CWE-125: Out-of-bounds Read**](https://cwe.mitre.org/data/definitions/125.html)                                                                                                                                                                                                                                  | The modern, more precise terminology for memory safety violations. |
| **Misconfigurations**             | <p><a href="https://cwe.mitre.org/data/definitions/16.html"><strong>CWE-16: Configuration</strong></a> (parent category). More specifically:<br>- <a href="https://cwe.mitre.org/data/definitions/798.html"><strong>[CWE-798] Use of Hard-coded Credentials</strong></a><br>- <a href="https://cwe.mitre.org/data/definitions/942.html"><strong>[CWE-942] Permissive Cross-domain Policy</strong></a></p> | This is broken into many specific, common misconfigurations.       |
| _(Not well covered in 2008)_      | [**\[CWE-89\] SQL Injection**](https://cwe.mitre.org/data/definitions/89.html)                                                                                                                                                                                                                                                                                                                            | Was an example in 2008; now a top-tier category of its own.        |
| _(Not well covered in 2008)_      | [**\[CWE-22\] Improper Limitation of a Pathname to a Restricted Directory (Path Traversal)**](https://cwe.mitre.org/data/definitions/22.html)                                                                                                                                                                                                                                                             | A classic flaw that's still very common.                           |
| _(Not well covered in 2008)_      | [**\[CWE-78\] Improper Neutralization of Special Elements used in an OS Command (OS Command Injection)**](https://cwe.mitre.org/data/definitions/78.html)                                                                                                                                                                                                                                                 | Another critical web app flaw.                                     |
| **Incorrect File Permissions**    | [**CWE-732: Incorrect Permission Assignment for Critical Resource**](https://cwe.mitre.org/data/definitions/732.html)                                                                                                                                                                                                                                                                                     | The modern, broader classification.                                |

NIST's 2008 list is very OS and application-centric. The modern CWE Top 25 includes critical weaknesses that, while absent from NIST's 2008 list, are dominant today, such as:

* [**\[CWE-352\] Cross-Site Request Forgery (CSRF)**](https://cwe.mitre.org/data/definitions/352.html)
* [**\[CWE-434\] Unrestricted Upload of File with Dangerous Type**](https://cwe.mitre.org/data/definitions/434.html)
* [**\[CWE-862\] Missing Authorization**](https://cwe.mitre.org/data/definitions/862.html) (a big part of modern API testing)

When a penetration tester exploits a vulnerability (e.g., a CWE), he then uses techniques mapped in ATT\&CK (e.g., Credential Dumping \[T1003], Lateral Movement \[TA0008]). MITRE ATT\&CK is a framework that describes the tactics and techniques adversaries use during an attack.

### Common Vulnerabilities and Exposures (CVE®) & NVD

While CWE is about the type of flaw, CVE Records are about specific instances of flaws in specific products. Penetration testers use this resource to find and exploit known vulnerabilities (e.g., using a scanner like Nessus or OpenVAS which cross-references findings with the CVE list).

For the penetration tester, the CVE system and the enriched NVD database are fundamental to the "low-hanging fruit" phase of an assessment. During reconnaissance and initial scanning, tools automatically fingerprint operating systems, software versions, and services. These fingerprints are matched against the CVE database to identify known, unpatched vulnerabilities on the target. A single CVE ID, such as CVE-2021-44228 (Log4Shell), provides a precise target for exploitation, complete with known attack vectors, proof-of-concept code, and patch information. This transforms a broad system scan into a prioritized list of actionable, exploitable entry points.

Furthermore, the NVD's role in enriching CVE records with **CVSS scores** and **CWE mappings** is critical for professional testing and reporting. A CVSS score helps a tester quickly triage findings—prioritizing a critical 9.8 vulnerability over a medium 5.0 one during a time-limited engagement. Mapping a CVE to a CWE (e.g., linking a specific buffer overflow CVE to CWE-787) allows the tester to report not just the _what_, but the underlying _why_, informing the client of systemic development or configuration issues. In essence, CVE/NVD provides the catalog of known weaponry, while NVD's analysis offers the intelligence on each weapon's range and impact, enabling efficient and effective attacks during a penetration test.

**Note:**

- The **CVE List** (a simple catalog of IDs and brief descriptions) is managed by MITRE under contract from the U.S. Cybersecurity and Infrastructure Security Agency (CISA).
- The **National Vulnerability Database (NVD)**, managed by NIST, is the U.S. government repository that analyzes and enriches CVE records with severity scores, impact details, and patch links.

### Prioritized attack categories

The following table provides a comprehensive overview of prioritized vulnerabilities contextualized within attack targets, attack vectors, risk scoring, and mitigation strategies - serving as a practical guide for vulnerability prioritization and management. The vulnerability scores are based on exploitability (ease of attack) and impact (potential damage), using CVSS v3.0 scores (where applicable) and real-world prevalence.

**Prioritized Vulnerability Table With Mitigation Strategies**

| **Vulnerability**                         | **CVSS**       | **Exploitability** | **Attack Target**                          | **Attack Vector**                                          | **Example Exploit**                                                                                              | **Mitigation Strategies**                                                                                |
| ----------------------------------------- | -------------- | ------------------ | ------------------------------------------ | ---------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------- |
| **Buffer Overflows**                      | 9.8 (Critical) | Moderate-High      | Applications, OS, Services                 | Crafted input overflowing memory, executing shellcode      | EternalBlue (WannaCry)                                                                                           | ▶ Use memory-safe languages (Rust, Go).  <br>▶ Enable DEP/ASLR.  <br>▶ Patch OS/libc regularly.          |
| **SQL Injection (SQLi)**                  | 9.8 (Critical) | High               | Web apps, APIs, Databases                  | SQL injection via user input fields                        | Heartland Payment Systems (2008 SQLi)                                                                            | ▶ Parameterized queries.  <br>▶ Input sanitization.  <br>▶ WAF rules (e.g., ModSecurity).                |
| **Cross-Site Scripting (XSS)**            | 7.5 (High)     | Very High          | Web apps, APIs                             | Cross-site scripting (reflected/stored/DOM)                | Tesla infotainment XSS                                                                                           | ▶ CSP headers.  <br>▶ Output encoding (OWASP ESAPI).  <br>▶ DOM sanitization.                            |
| **Misconfigurations (Insecure Defaults)** | 9.0 (High)     | Very High          | Servers, Cloud, IoT, APIs, Network Devices | Default credentials, open ports, exposed interfaces        | AWS S3 leaks, Jenkins RCE                                                                                        | ▶ Automated scanning (Chef, Ansible).  <br>▶ Least-privilege access.  <br>▶ Disable default credentials. |
| **Kernel Flaws**                          | 8.8 (High)     | Moderate           | OS (Linux/Windows/macOS)                   | Privilege escalation via kernel bugs, exploits             | Dirty Pipe (CVE-2022-0847)                                                                                       | ▶ Immediate kernel patching.  <br>▶ Restrict root access.  <br>▶ Use SELinux/AppArmor.                   |
| **Vulnerable Components**                 | 9.1 (Critical) | Very High          | Libraries, Frameworks                      | Exploiting known CVEs in dependencies                      | Log4Shell, Struts (Equifax)                                                                                      | ▶ SBOM (Software Bill of Materials).  <br>▶ Automated dependency updates (Dependabot).                   |
| **Security Misconfigurations**            | 8.5 (High)     | High               | Cloud, Servers, Containers                 | Exposed admin interfaces, verbose errors                   | Kubernetes API exposure                                                                                          | ▶ CIS benchmarks.  <br>▶ Regular audits with OpenSCAP.  <br>▶ Disable debug modes.                       |
| **Broken Authentication**                 | 8.8 (High)     | High               | Web apps, APIs                             | Credential stuffing, session hijacking                     | Facebook token hijacking, OAuth misconfigurations                                                                | ▶ MFA enforcement.  <br>▶ Rate-limiting login attempts.  <br>▶ OAuth 2.0 hardening.                      |
| **SSRF**                                  | 8.7 (High)     | Moderate-High      | Cloud, Internal Networks                   | Forging requests from the server                           | Capital One breach, AWS metadata theft                                                                           | ▶ Network segmentation.  <br>▶ Block internal IPs in requests.  <br>▶ Use allowlists for URLs.           |
| **Insufficient Input Validation**         | 8.1 (High)     | High               | Web apps, APIs, Databases                  | SQLi, XSS, Command Injection                               | Apache Struts RCE (CVE-2017-5638)                                                                                | ▶ Input length/type checks.  <br>▶ Fuzz testing (AFL).  <br>▶ Zero-trust input models.                   |
| **Race Conditions**                       | 7.5 (High)     | Hard               | OS, Applications, Concurrent Systems       | TOCTOU (Time-of-Check to Time-of-Use) attacks              | Dirty COW (Linux)                                                                                                | ▶ Atomic operations.  <br>▶ File-locking mechanisms.  <br>▶ TOCTOU checks.                               |
| **Unrestricted File Uploads**             | 8.0 (High)     | Moderate           | Web apps                                   | Uploading malicious executables                            | WordPress malware uploads, Web shell uploads                                                                     | ▶ File type verification (magic numbers).  <br>▶ Store uploads outside webroot.  <br>▶ Scan with ClamAV. |
| **Symbolic Links**                        | 7.1 (High)     | Moderate           | File systems, Privileged apps              | Tricking apps into writing to sensitive files              | Docker breakout                                                                                                  | ▶ Disable symlink following.  <br>▶ chroot/jail environments.  <br>▶ Use `openat()` safely.              |
| **Weak Credentials**                      | 7.5 (High)     | Very High          | IoT, Web apps, Systems                     | Default/weak password exploitation                         | Mirai botnet (IoT)                                                                                               | ▶ Password policies (12+ chars).  <br>▶ Block common passwords.  <br>▶ Certificate-based auth.           |
| **Incorrect File Permissions**            | 7.8 (High)     | Moderate           | OS, Databases, Apps, File Systems          | Unauthorized access/modification, reading restricted files | MongoDB ransomware                                                                                               | ▶ `chmod 600` for sensitive files.  <br>▶ Regular `auditd` checks.  <br>▶ Principle of least privilege.  |
| **Insecure Direct Object Refs.**          | 6.5 (Medium)   | High               | Web apps, APIs                             | Manipulating object references                             | Accessing other users' data via ID parameter tampering                                                           | ▶ Implement indirect reference maps, enforce authorization checks on every request.                      |
| **File Descriptor Leaks**                 | 6.5 (Medium)   | Low                | OS, Applications, Running Processes        | Exploiting unclosed file handles                           | Heartbleed (buffer over-read from missing bounds check—a form of input validation failure at the protocol level) | ▶ Secure coding (close handles).  <br>▶ Static analysis (Coverity).  <br>▶ Memory-safe languages.        |
| **Missing Encryption**                    | 6.8 (Medium)   | Low                | Databases, Networks                        | Sniffing plaintext data                                    | FTP credentials intercepted, unencrypted medical records                                                         | ▶ TLS 1.3+ enforcement.  <br>▶ Encrypt data at rest (AES-256).  <br>▶ HSM for keys.                      |

**High-risk focus areas:**

* **Critical (9.0+ CVSS)**: Patch buffer overflows/injection flaws within 24hrs of CVE disclosure.
* **High (7.0–8.9 CVSS)**: Automate scans for misconfigurations/weak credentials weekly.
* **Medium (5.0–6.9 CVSS)**: Enforce encryption/MFA by policy.

### Detection, exploitation, and mitigation of prioritized vulnerabilities

The following table presents a consolidated toolkit and response playbook for each vulnerability category, combining the practical tools and high-level response steps security professionals use.

**Vulnerability Response Toolkit and Playbook**

| **Vulnerability**                         | **Detection Tools**                                                                                                                     | **Exploitation Tools**                                                                                            | **Response Playbook**                                                                                                                                                                                                 |
| ----------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Buffer Overflows**                      | ▶ **Nessus/OpenVAS** (CVE scanning)  <br>▶ **AFL/LibFuzzer** (fuzzing)  <br>▶ **Static Analysis** (Coverity, CodeQL)                    | ▶ **Metasploit** (exploit modules)  <br>▶ **GDB/PEDA** (debugging/crafting)  <br>▶ Public PoCs (Exploit-DB)       | **1. CONTAIN:** Isolate affected system. **2. ERADICATE:** Apply patches; enable DEP/ASLR. **3. RECOVER:** Test hardening with `checksec`; redeploy from known-good images.                                           |
| **SQL Injection (SQLi)**                  | ▶ **Burp Suite / OWASP ZAP** (intercepting proxy)  <br>▶ **SQLMap** (automated detection)  <br>▶ **Semgrep** (code analysis)            | ▶ **SQLMap** (automated exploitation)  <br>▶ **Burp Suite Repeater** (manual testing)  <br>▶ Custom scripts       | **1. CONTAIN:** Deploy virtual patch (WAF like ModSecurity). **2. ERADICATE:** Fix code: parameterized queries. **3. RECOVER:** Audit logs for stolen data; rotate exposed credentials.                               |
| **Cross-Site Scripting (XSS)**            | ▶ **Burp Suite / OWASP ZAP** (automated scanner)  <br>▶ **Manual testing** with payload lists  <br>▶ **DAST** tools                     | ▶ **BeEF** (hook browser)  <br>▶ **XSS Hunter** (blind XSS)  <br>▶ Crafted payload delivery                       | **1. CONTAIN:** Deploy CSP headers. **2. ERADICATE:** Implement context-aware output encoding. **3. RECOVER:** Conduct post-remediation penetration testing.                                                          |
| **Misconfigurations (Insecure Defaults)** | ▶ **Nmap** (service/version scan)  <br>▶ **Shodan/Censys** (internet exposure)  <br>▶ **OpenSCAP** (compliance scanning)                | ▶ **Metasploit** (auxiliary modules)  <br>▶ Manual login with default credentials  <br>▶ **Custom scripts**       | **1. CONTAIN:** Remove system from untrusted networks. **2. ERADICATE:** Apply CIS benchmarks; disable defaults. **3. RECOVER:** Reconfigure with IaC (Ansible/Terraform); re-deploy.                                 |
| **Kernel Flaws**                          | ▶ **Lynis** (system audit)  <br>▶ **KernelPatchCheck** scripts  <br>▶ Vulnerability scanners (Nessus)                                   | ▶ Public **PoC exploits** (e.g., DirtyPipe)  <br>▶ **Metasploit** (privilege escalation modules)                  | **1. CONTAIN:** Restrict SSH/root access. **2. ERADICATE:** Patch kernel immediately. **3. RECOVER:** Harden with SELinux/AppArmor; monitor `/proc/self/mem` access.                                                  |
| **Vulnerable Components**                 | ▶ **Dependency-Check / Snyk / Trivy** (SCA)  <br>▶ **Software Bill of Materials (SBOM)** analysis                                       | ▶ **Metasploit** (exploit modules)  <br>▶ **Searchsploit / Exploit-DB**                                           | **1. CONTAIN:** Isolate service; deploy WAF virtual patch. **2. ERADICATE:** Update/library patch via dependency manager. **3. RECOVER:** Implement automated SCA (Dependabot/Renovate).                              |
| **Security Misconfigurations**            | ▶ **Cloud-native tools** (AWS Config, GCP Security Scanner)  <br>▶ **Kube-bench** (Kubernetes)  <br>▶ **TruffleHog** (secret scanning)  | ▶ **Cloud metadata API** queries  <br>▶ **Kubectl** commands against exposed API                                  | **1. CONTAIN:** Disable public access; restrict IAM roles. **2. ERADICATE:** Apply least-privilege configs; disable debug modes. **3. RECOVER:** Enforce configuration drift detection.                               |
| **Broken Authentication**                 | ▶ **Burp Suite** (Intruder for brute-force testing)  <br>▶ **OWASP ZAP** (auth testing)  <br>▶ Custom credential stuffing scripts       | ▶ **Hydra / Medusa** (brute-force)  <br>▶ **Burp Suite** (session hijacking)  <br>▶ **OAuth tester** tools        | **1. CONTAIN:** Block attacking IPs; enforce rate limiting. **2. ERADICATE:** Enforce MFA; fix session management. **3. RECOVER:** Reset compromised credentials; audit logs.                                         |
| **SSRF**                                  | ▶ **Burp Suite** (manual testing with Collaborator)  <br>▶ **SSRFmap** (automated testing)  <br>▶ Code review for URL fetching          | ▶ **Gopherus** (payload crafting)  <br>▶ **Burp Collaborator** (to confirm)                                       | **1. CONTAIN:** Block outbound traffic to internal IPs. **2. ERADICATE:** Implement allowlists for fetched URLs; use network segmentation. **3. RECOVER:** Audit all outbound requests from app servers.              |
| **Insufficient Input Validation**         | ▶ **Fuzzing** (AFL, Burp Intruder)  <br>▶ **Static Application Security Testing (SAST)**  <br>▶ Manual code review                      | ▶ **Burp Suite Repeater** (manual exploitation)  <br>▶ **FFUF / Wfuzz** (parameter fuzzing)                       | **1. CONTAIN:** Input sanitization/WAF. **2. ERADICATE:** Implement strict whitelist validation. **3. RECOVER:** Integrate fuzz testing into CI/CD.                                                                   |
| **Race Conditions**                       | ▶ **Custom timing scripts**  <br>▶ **Code review** for TOCTOU patterns  <br>▶ **AFL** (fuzzing with timing)                             | ▶ **Custom exploit scripts**  <br>▶ Public **PoC** exploits                                                       | **1. CONTAIN:** Implement file locking. **2. ERADICATE:** Refactor code to use atomic operations. **3. RECOVER:** Audit temp file usage and `/tmp` directory.                                                         |
| **Unrestricted File Uploads**             | ▶ **Manual testing** (Burp)  <br>▶ **ClamAV** (malware scanning post-upload)  <br>▶ **Static Analysis** for file handling code          | ▶ Upload **web shells** (.jsp, .php, .aspx)  <br>▶ **Metasploit** (payload generation)                            | **1. CONTAIN:** Quarantine uploaded files; disable upload feature. **2. ERADICATE:** Implement strict file type verification (magic numbers). **3. RECOVER:** Store files outside webroot; scan all uploads.          |
| **Symbolic Links**                        | ▶ **Manual audit** (`find / -type l -perm -o=w`)  <br>▶ **Code review** for file operations  <br>▶ **Lynis** (file system audits)       | ▶ **Symlink race condition** exploits  <br>▶ **Docker breakout** PoCs                                             | **1. CONTAIN:** Disable symlink following in config. **2. ERADICATE:** Use secure functions (`openat()`); implement chroot/jails. **3. RECOVER:** Audit `/tmp` and world-writable directories.                        |
| **Weak Credentials**                      | ▶ **Nmap** scripts (`ssh-brute`, `http-auth-finder`)  <br>▶ **Hydra** (targeted testing)  <br>▶ **Breached password lists**             | ▶ **Hydra / Medusa** (brute-force)  <br>▶ **John the Ripper** (hash cracking)  <br>▶ **CrackMapExec** (SMB/WinRM) | **1. CONTAIN:** Block IP after failed attempts; lock account. **2. ERADICATE:** Enforce strong password policy; implement MFA. **3. RECOVER:** Reset passwords; monitor for credential stuffing.                      |
| **Incorrect File Permissions**            | ▶ **Linux:** `find / -perm -o=w`  <br>▶ **Windows:** AccessChk (Sysinternals)  <br>▶ **Lynis / OpenSCAP** (auditing)                    | ▶ Manual file access/overwrite  <br>▶ **Custom scripts** to exploit writable paths                                | **1. CONTAIN:** Restrict access (`chmod 600`, `icacls`). **2. ERADICATE:** Apply principle of least privilege. **3. RECOVER:** Implement regular permission audits with `auditd` or equivalent.                       |
| **Insecure Direct Object Refs.**          | ▶ **Manual testing** (Burp Suite)  <br>▶ **OWASP ZAP** (active scan)  <br>▶ Code review for direct object references                    | ▶ **Burp Repeater** (parameter manipulation)  <br>▶ **Custom enumeration scripts**                                | **1. CONTAIN:** Implement access control checks on all object references. **2. ERADICATE:** Use indirect reference maps (e.g., session-based keys). **3. RECOVER:** Audit logs for unauthorized data access attempts. |
| **File Descriptor Leaks**                 | ▶ **Static Analysis** (Coverity, CodeQL)  <br>▶ **Valgrind / AddressSanitizer** (runtime)  <br>▶ Code review                            | ▶ Difficult to directly exploit; often leads to info disclosure (Heartbleed)                                      | **1. CONTAIN:** Restart affected service. **2. ERADICATE:** Fix code to properly close handles. **3. RECOVER:** Integrate static analysis into CI/CD; use memory-safe languages.                                      |
| **Missing Encryption**                    | ▶ **Wireshark / tcpdump** (traffic analysis)  <br>▶ **Nmap** scripts (`ssl-cert`, `ssh2-enum-algos`)  <br>▶ **Manual audit** of configs | ▶ **Packet sniffing**  <br>▶ **Man-in-the-Middle (MitM)** tools (ettercap)                                        | **1. CONTAIN:** Enforce TLS (e.g., HSTS). **2. ERADICATE:** Encrypt data in transit (TLS 1.3+) and at rest (AES-256). **3. RECOVER:** Implement key management (HSMs, vaults); rotate exposed keys.                   |

#### Key Tools by Function

**Detection and Scanning**

| **Tool**       | **Purpose**                        | **Vulnerability Focus**              |
| -------------- | ---------------------------------- | ------------------------------------ |
| **Nessus**     | CVE scanning                       | Buffer overflows, misconfigurations  |
| **Burp Suite** | Web app testing                    | SQLi, XSS, SSRF                      |
| **OpenVAS**    | Open-source vulnerability scanning | Misconfigurations, weak creds        |
| **Lynis**      | Linux hardening audits             | Kernel flaws, file permissions       |
| **Shodan**     | Internet-exposed device search     | Misconfigurations (e.g., open Redis) |

**Exploitation and Testing**

| **Tool**       | **Purpose**                   | **Example Command**                   |
| -------------- | ----------------------------- | ------------------------------------- |
| **Metasploit** | Exploit development/framework | `use exploit/windows/smb/ms17_010`    |
| **SQLmap**     | Automated SQLi testing        | `sqlmap -u "http://site.com?id=1"`    |
| **Hydra**      | Brute-force credentials       | `hydra -l admin -P pass.txt ssh://IP` |
| **BeEF**       | XSS exploitation              | Hook browsers via `<script>`          |
| **Gopherus**   | SSRF exploit crafting         | Generate malicious Gopher payloads    |

**Mitigation and Hardening**

| **Tool**        | **Purpose**             | **Command/Use Case**             |
| --------------- | ----------------------- | -------------------------------- |
| **Ansible**     | Config hardening        | CIS benchmark playbooks          |
| **ModSecurity** | WAF for injection flaws | Block SQLi/XSS patterns          |
| **SELinux**     | Linux MAC enforcement   | `setenforce 1` (enforcing mode)  |
| **ClamAV**      | Malware scanning        | `clamscan /var/www/uploads`      |
| **Dependabot**  | Dependency updates      | Auto-PR for vulnerable libraries |

### Key takeaways

- Modern vulnerability frameworks have evolved beyond older system-centric models. While foundational, historical taxonomies like NIST SP 800-115 are outdated. The current landscape is defined by specialized, community-driven frameworks: the OWASP Top 10 for web application risks, CWE for root-cause software weaknesses, and CVE/NVD for tracking specific vulnerabilities.
- Vulnerabilities are categorized and tracked through complementary systems. CWE classifies the general type of software flaw (the "why"), CVE identifies a specific instance in a product (the "what"), and the NVD enriches CVEs with severity scores and remediation details to enable prioritization.
- Prioritization is critical and is guided by exploitability and impact. Vulnerabilities are evaluated and ranked using metrics like CVSS scores, prevalence, and potential business impact. This allows security teams to focus on addressing critical risks, such as Injection flaws or Buffer Overflows, first.
- Each major vulnerability category has associated tools for detection, exploitation, and mitigation. A practical security workflow involves using specific tools (e.g., Burp Suite for detection, Metasploit for exploitation, WAFs for mitigation) tailored to the vulnerability type, forming a structured response cycle.
- Developing a structured response playbook is essential for handling critical flaws. For each prioritized vulnerability category, a standardized response process—following phases like Contain, Eradicate, and Recover—ensures efficient and effective mitigation of security incidents.

### References

NIST. National Vulnerability Database. https://nvd.nist.gov/

Scarfone, K., Souppaya, M., Cody, A., & Orebaugh, A. (2008). _Technical guide to information security testing and assessment_ (NIST Special Publication 800-115). National Institute of Standards and Technology. [http://csrc.nist.gov/publications/nistpubs/800-115/SP800-115.pdf](http://csrc.nist.gov/publications/nistpubs/800-115/SP800-115.pdf)

The MITRE Corporation (MITRE). (2025). Common Weakness Enumeration (CWE™). https://cwe.mitre.org/index.html

The MITRE Corporation (MITRE). (2025). MITRE ATT\&CK. https://attack.mitre.org/

The OWASP® Foundation. OWASP Top Ten. https://owasp.org/www-project-top-ten/
