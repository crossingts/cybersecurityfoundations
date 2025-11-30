---
description: >-
  This section explores common cyber attack targets and associated attack
  vectors and vulnerabilities
hidden: true
---

# Copy of Common attack targets-2

## Learning objectives <a href="#learning-objectives" id="learning-objectives"></a>

* Become familiar with common cyber attack targets and associated attack vectors and vulnerabilities

This section explores common cyber attack targets and associated attack vectors and vulnerabilities.

## Topics covered in this section

* Introduction
* NIST SP 800-115's attack categories
* OWASP Top 10
* Common Weakness Enumeration (CWE™)
* Common Vulnerabilities and Exposures (CVE®) & NVD
* Prioritized attack categories 
* Detection, exploitation, and mitigation of prioritized vulnerabilities 

### Introduction

When it comes to categorizing common vulnerabilities targeted by penetration testers (and malicious hackers), NIST's 2008 categories of vulnerabilities (attack targets) is a logical starting point.

NIST SP 800-115, "Technical Guide to Information Security Testing and Assessment", was published in 2008 but has not been formally updated. 
While the high-level principles and methodology of penetration testing in this guide are still sound, the taxonomy of vulnerabilities is significantly outdated.

The attack landscape has evolved dramatically, primarily towards web applications, identity-based attacks, APIs, and cloud services.

A modern, practical taxonomy of attack categories can be anchored in the following two/three frameworks:

- **CWE Top 25:** This is now the standard for categorizing the root cause of a vulnerability.
- **CVE/NVD:** This is how we track specific instances of vulnerabilities in software (what is exploited).
/
- **OWASP Top 10**

These two/three frameworks reflect an evolving attack landscape pointing to the following categories of vulnerabilities:

- **Web Application Flaws:** Injection (SQLi, OS Command), XSS, Broken Access Control (IDOR).
- **Security Misconfigurations:** Cloud storage (S3) buckets, default credentials, unnecessary services.
- **Identity & Access Issues:** Weak passwords, lack of multi-factor authentication, privilege escalation.
- **Outdated Software:** Unpatched systems with known CVEs.
- **Network-Level Attacks:** VLAN hopping, switch spoofing, insecure network device management (SNMP, Telnet).

### NIST SP 800-115's attack categories

The majority of vulnerabilities exploited by penetration testing fall into the following categories (NIST SP 800-115, 2008, pp. 5-4-5-5):

**verbatim:**

* Misconfigurations. Misconfigured security settings, particularly insecure default settings, are usually easily exploitable.
* Kernel Flaws. Kernel code is the core of an OS, and enforces the overall security model for the system—so any security flaw in the kernel puts the entire system in danger.
* Buffer Overflows. A buffer overflow occurs when programs do not adequately check input for appropriate length. When this occurs, arbitrary code can be introduced into the system and executed with the privileges—often at the administrative level—of the running program.
* Insufficient Input Validation. Many applications fail to fully validate the input they receive from users. An example is a Web application that embeds a value from a user in a database query. If the user enters SQL commands instead of or in addition to the requested value, and the Web application does not filter the SQL commands, the query may be run with malicious changes that the user requested—causing what is known as a SQL injection attack.
* Symbolic Links. A symbolic link (symlink) is a file that points to another file. Operating systems include programs that can change the permissions granted to a file. If these programs run with privileged permissions, a user could strategically create symlinks to trick these programs into modifying or listing critical system files.
* File Descriptor Attacks. File descriptors are numbers used by the system to keep track of files in lieu of filenames. Specific types of file descriptors have implied uses. When a privileged program assigns an inappropriate file descriptor, it exposes that file to compromise.
* Race Conditions. Race conditions can occur during the time a program or process has entered into a privileged mode. A user can time an attack to take advantage of elevated privileges while the program or process is still in the privileged mode.
* Incorrect File and Directory Permissions. File and directory permissions control the access assigned to users and processes. Poor permissions could allow many types of attacks, including the reading or writing of password files or additions to the list of trusted remote hosts.

**NIST SP 800-115 vulnerabilities mapped to their typical attack targets, vectors, and exploits:**

| **Vulnerability (NIST SP 800-115)** | **Attack Target**                                   | **Attack Vector**                                               | **Example Exploit**                                   |
| ----------------------------------- | --------------------------------------------------- | --------------------------------------------------------------- | ----------------------------------------------------- |
| **Misconfigurations**               | OS, Cloud, Network Devices, Databases, Applications | Exploiting insecure default credentials/settings and open ports | Accessing admin panels with `admin:admin` credentials |
| **Kernel Flaws**                    | Operating System                                    | Privilege escalation via kernel exploits                        | Dirty Pipe (CVE-2022-0847) for root access            |
| **Buffer Overflows**                | Applications, Services                              | Overflowing memory to execute shellcode                         | Stack-based overflow in legacy FTP servers            |
| **Insufficient Input Validation**   | Web Applications                                    | SQLi, XSS, Command Injection                                    | Bypassing login forms with `' OR 1=1 --`              |
| **Symbolic Link (Symlink) Issues**  | File Systems                                        | Tricking privileged processes to write files                    | Symlink attacks in `/tmp` directories                 |
| **File Descriptor Leaks**           | Running Processes                                   | Accessing sensitive files left open                             | Reading `/etc/passwd` from a crashed service          |
| **Race Conditions**                 | Concurrent Systems                                  | TOCTOU (Time-of-Check to Time-of-Use) attacks                   | Changing file permissions between check and use       |
| **Incorrect File/Directory Perms**  | File Systems                                        | Reading/writing restricted files                                | `chmod 777` exposing SSH private keys                 |

merge:

| **Vulnerability Category**                | **Attack Target**             | **Attack Vector**                                   | **Example Exploit**                                                                             |
| ----------------------------------------- | ----------------------------- | --------------------------------------------------- | ----------------------------------------------------------------------------------------------- |
| **Security Misconfigurations**            | Cloud, Servers, Containers    | Exposed admin interfaces, verbose errors            | **Kubernetes dashboard exposed** (CVE-2018-18264), **Jenkins RCE** (misconfigured scripts)      |
| **Misconfigurations (Insecure Defaults)** | Servers, Cloud, IoT, APIs     | Default credentials, open ports, exposed interfaces | **Mirai botnet** (exploited default IoT passwords), **AWS S3 bucket leaks** (public-by-default) |
| **Kernel Flaws**                          | OS (Linux/Windows/macOS)      | Privilege escalation via kernel bugs                | **Dirty Pipe** (CVE-2022-0847), **Dirty COW** (CVE-2016-5195)                                   |
| **Buffer Overflows**                      | Applications, OS, Services    | Crafted input overflowing memory                    | **EternalBlue** (MS17-010), **Code Red worm** (IIS buffer overflow)                             |
| **Insufficient Input Validation**         | Web apps, APIs, Databases     | SQLi, XSS, Command Injection                        | **Equifax breach** (SQLi, CVE-2017-5638), **Log4Shell** (CVE-2021-44228)                        |
| **Symbolic Links (Symlink)**              | File systems, Privileged apps | Tricking apps into writing to sensitive files       | **Docker symlink escape** (CVE-2018-15664)                                                      |
| **File Descriptor Issues**                | OS, Applications              | Exploiting unclosed file handles                    | **Heartbleed** (CVE-2014-0160) via OpenSSL file descriptor leaks                                |
| **Race Conditions (TOCTOU)**              | OS, Applications              | Timing attacks to bypass checks                     | Linux `ptrace` race condition (CVE-2019-13272)                                                  |
| **Incorrect File/Directory Permissions**  | OS, Databases, Apps           | Unauthorized access/modification                    | **MongoDB ransomware attacks** (exposed databases with weak permissions)                        |

### OWASP Top 10

OWASP Testing Guide (Web Security Testing Guide)

"The guide is structured to mirror the phases of a typical application penetration test. It begins with preliminary steps like information gathering and configuration management testing, then moves into a thorough examination of identity management, authentication, and session management controls. The core of the WSTG is its extensive coverage of specific vulnerability classes, most notably the OWASP Top 10 risks such as SQL Injection (SQLi), Cross-Site Scripting (XSS), and Cross-Site Request Forgery (CSRF). For each testing area, the guide provides a clear objective, descriptions of how to test for weaknesses, and guidance on how to interpret the results."

OWASP Top 10 emphasizes web-specific risks.

**Comparison of Frameworks / Shared themes**

Shared themes: 
* Input validation, misconfigurations appear in both OWASP Top 10 and NIST SP 800-115.

### Common Weakness Enumeration (CWE™)

NIST itself now primarily uses the **CWE List** as the authoritative source for types of software weaknesses. This is a much more granular and detailed community-developed list of common software and hardware security weaknesses which serves as a common language for describing vulnerabilities. Penetration testers use the CWE to classify the root cause of the flaws they find. The **CWE Top 25 Most Dangerous Software Weaknesses** is the spiritual successor to NIST's 2008 list and it is updated regularly based on real-world data.

**Mapping the 2008 List to the 2023 CWE Top 25**

| 2008 Category (NIST SP 800-115)   | Modern Equivalent (CWE Top 25, 2023)                                                                                                                                                                                                                                                                                           | Why it's Updated / Refined                                         |
| --------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------ |
| **Insufficient Input Validation** | **[CWE-79: Improper Neutralization of Input During Web Page Generation (XSS)](https://cwe.mitre.org/data/definitions/79.html)**                                                                                                                                                                                                | This is more specific. "Input Validation" is too broad.            |
| **Buffer Overflows**              | **[CWE-787: Out-of-bounds Write](https://cwe.mitre.org/data/definitions/787.html)** & **[CWE-125: Out-of-bounds Read](https://cwe.mitre.org/data/definitions/125.html)**                                                                                                                                                       | The modern, more precise terminology for memory safety violations. |
| **Misconfigurations**             | **[CWE-16: Configuration](https://cwe.mitre.org/data/definitions/16.html)** (parent category). More specifically:  <br>- **[[CWE-798] Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)**  <br>- **[[CWE-942] Permissive Cross-domain Policy](https://cwe.mitre.org/data/definitions/942.html)** | This is broken into many specific, common misconfigurations.       |
| _(Not well covered in 2008)_      | **[[CWE-89] SQL Injection](https://cwe.mitre.org/data/definitions/89.html)**                                                                                                                                                                                                                                                   | Was an example in 2008; now a top-tier category of its own.        |
| _(Not well covered in 2008)_      | **[[CWE-22] Improper Limitation of a Pathname to a Restricted Directory (Path Traversal)](https://cwe.mitre.org/data/definitions/22.html)**                                                                                                                                                                                    | A classic flaw that's still very common.                           |
| _(Not well covered in 2008)_      | **[[CWE-78] Improper Neutralization of Special Elements used in an OS Command (OS Command Injection)](https://cwe.mitre.org/data/definitions/78.html)**                                                                                                                                                                        | Another critical web app flaw.                                     |
| **Incorrect File Permissions**    | **[CWE-732: Incorrect Permission Assignment for Critical Resource](https://cwe.mitre.org/data/definitions/732.html)**                                                                                                                                                                                                          | The modern, broader classification.                                |

NIST's 2008 list is very OS and application-centric. The modern CWE Top 25 includes critical weaknesses that, while absent from NIST's 2008 list, are dominant today, such as:

- **[[CWE-352] Cross-Site Request Forgery (CSRF)](https://cwe.mitre.org/data/definitions/352.html)**
- **[[CWE-434] Unrestricted Upload of File with Dangerous Type](https://cwe.mitre.org/data/definitions/434.html)**
- **[[CWE-862] Missing Authorization](https://cwe.mitre.org/data/definitions/862.html)** (a big part of modern API testing)

### Common Vulnerabilities and Exposures (CVE®) & NVD

While CWE is about the type of flaw, CVE Records are about specific instances of flaws in specific products.

- The **National Vulnerability Database (NVD)**, run by NIST, is the U.S. government repository of CVE records.
- Penetration testers use this database to find and exploit known vulnerabilities (e.g., using a scanner like Nessus or OpenVAS which cross-references findings with the CVE list).

When a penetration tester exploits a vulnerability (e.g., a CWE), he then use techniques mapped in ATT&CK (e.g., Credential Dumping [T1003], Lateral Movement [TA0008]). MITRE ATT&CK is a framework that describes the tactics and techniques adversaries use during an attack.

### Prioritized attack categories 

**Vulnerability table** based on **exploitability (ease of attack)** and **impact (potential damage)**, using **CVSS v3.0 scores** (where applicable) and real-world prevalence.

#### Prioritized Vulnerability Table With Mitigation Strategies

merge:

| **Vulnerability Category**             | **Attack Target**        | **Attack Vector**                      | **Example Exploit**                                              |
| -------------------------------------- | ------------------------ | -------------------------------------- | ---------------------------------------------------------------- |
| **Broken Authentication**              | Web apps, APIs           | Credential stuffing, session hijacking | **Facebook token hijacking** (2018), **OAuth misconfigurations** |
| **Use of Vulnerable Components**       | Libraries, Frameworks    | Exploiting known CVEs in dependencies  | **Apache Struts** (Equifax breach), **Log4j** (Log4Shell)        |
| **Insecure Direct Object Refs.**       | Web apps, APIs           | Manipulating object references         | **Accessing other users’ data** via ID parameter tampering       |
| **Server-Side Request Forgery (SSRF)** | Cloud, Internal Networks | Forging requests from the server       | **Capital One breach** (CVE-2019-19781), **AWS metadata theft**  |
| **Unrestricted File Uploads**          | Web apps                 | Uploading malicious executables        | **Web shell uploads** (e.g., PHP shells in CMS plugins)          |
| **Missing Encryption**                 | Databases, Networks      | Sniffing plaintext data                | **FTP credentials intercepted**, **unencrypted medical records** |

| **Vulnerability**                 | **CVSS**       | **Exploitability** | **Impact** | **Example Exploit**         | **Mitigation Strategies**                                                                                                        |
| --------------------------------- | -------------- | ------------------ | ---------- | --------------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| **Buffer Overflows**              | 9.8 (Critical) | Moderate-High      | Critical   | EternalBlue (WannaCry)      | <p>▶ Use memory-safe languages (Rust, Go).<br>▶ Enable DEP/ASLR.<br>▶ Patch OS/libc regularly.</p>                               |
| **Injection Flaws** (SQLi, XSS)   | 9.8 (Critical) | High               | Critical   | Equifax (SQLi), Log4Shell   | <p>▶ Parameterized queries.<br>▶ Input sanitization.<br>▶ WAF rules (e.g., ModSecurity).</p>                                     |
| **Misconfigurations**             | 9.0 (High)     | **Very High**      | High       | AWS S3 leaks, Jenkins RCE   | <p>▶ Automated scanning (Chef, Ansible).<br>▶ Least-privilege access.<br>▶ Disable default credentials.</p>                      |
| **Kernel Flaws**                  | 8.8 (High)     | Moderate           | Critical   | Dirty Pipe (CVE-2022-0847)  | <p>▶ Immediate kernel patching.<br>▶ Restrict root access.<br>▶ Use SELinux/AppArmor.</p>                                        |
| **Vulnerable Components**         | 9.1 (Critical) | **Very High**      | Critical   | Log4Shell, Struts (Equifax) | <p>▶ SBOM (Software Bill of Materials).<br>▶ Automated dependency updates (Dependabot).</p>                                      |
| **Security Misconfigurations**    | 8.5 (High)     | High               | High       | Kubernetes API exposure     | <p>▶ CIS benchmarks.<br>▶ Regular audits with OpenSCAP.<br>▶ Disable debug modes.</p>                                            |
| **Broken Authentication**         | 8.8 (High)     | High               | High       | Facebook token hijacking    | <p>▶ MFA enforcement.<br>▶ Rate-limiting login attempts.<br>▶ OAuth 2.0 hardening.</p>                                           |
| **SSRF**                          | 8.7 (High)     | Moderate-High      | High       | Capital One breach          | <p>▶ Network segmentation.<br>▶ Block internal IPs in requests.<br>▶ Use allowlists for URLs.</p>                                |
| **Insufficient Input Validation** | 8.1 (High)     | High               | High       | Heartbleed (OpenSSL)        | <p>▶ Input length/type checks.<br>▶ Fuzz testing (AFL).<br>▶ Zero-trust input models.</p>                                        |
| **Race Conditions**               | 7.5 (High)     | Hard               | High       | Dirty COW (Linux)           | <p>▶ Atomic operations.<br>▶ File-locking mechanisms.<br>▶ TOCTOU checks.</p>                                                    |
| **Unrestricted File Uploads**     | 8.0 (High)     | Moderate           | High       | WordPress malware uploads   | <p>▶ File type verification (magic numbers).<br>▶ Store uploads outside webroot.<br>▶ Scan with ClamAV.</p>                      |
| **XSS**                           | 7.5 (High)     | **Very High**      | Moderate   | Tesla infotainment XSS      | <p>▶ CSP headers.<br>▶ Output encoding (OWASP ESAPI).<br>▶ DOM sanitization.</p>                                                 |
| **Symbolic Links**                | 7.1 (High)     | Moderate           | High       | Docker breakout             | <p>▶ Disable symlink following.<br>▶ chroot/jail environments.<br>▶ Use <code>openat()</code> safely.</p>                        |
| **Weak Credentials**              | 7.5 (High)     | **Very High**      | High       | Mirai botnet (IoT)          | <p>▶ Password policies (12+ chars).<br>▶ Block common passwords.<br>▶ Certificate-based auth.</p>                                |
| **Incorrect File Permissions**    | 7.8 (High)     | Moderate           | High       | MongoDB ransomware          | <p>▶ <code>chmod 600</code> for sensitive files.<br>▶ Regular <code>auditd</code> checks.<br>▶ Principle of least privilege.</p> |
| **File Descriptor Leaks**         | 6.5 (Medium)   | Low                | High       | Heartbleed                  | <p>▶ Secure coding (close handles).<br>▶ Static analysis (Coverity).<br>▶ Memory-safe languages.</p>                             |
| **Missing Encryption**            | 6.8 (Medium)   | Low                | High       | HIPAA violations            | <p>▶ TLS 1.3+ enforcement.<br>▶ Encrypt data at rest (AES-256).<br>▶ HSM for keys.</p>                                           |

**High-Risk Focus Areas:**

* **Critical (9.0+ CVSS)**: Patch buffers/injection flaws within 24hrs of CVE disclosure.
* **High (7.0–8.9 CVSS)**: Automate scans for misconfigurations/weak credentials weekly.
* **Medium (5.0–6.9 CVSS)**: Enforce encryption/MFA by policy.

### Detection, exploitation, and mitigation of prioritized vulnerabilities 

**Response playbook / mitigation of prioritized vulnerabilities**

A consolidated toolkit and response playbook for each vulnerability category, combining automated tools and manual testing techniques. 

**merge section/content "Key Tools by Function" below into the following table**

#### Vulnerability Response Toolkit & Playbook

| **Vulnerability**         | **Detection Tools**                                 | **Exploitation Tools**                                        | **Response Playbook**                                                                                                                                   |
| ------------------------- | --------------------------------------------------- | ------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Buffer Overflows**      | <p>▶ Nessus (CVE scans)<br>▶ AFL (fuzzing)</p>      | <p>▶ Metasploit (EternalBlue module)<br>▶ GDB (debugging)</p> | <p><strong>1.</strong> Apply patches.<br><strong>2.</strong> Enable DEP/ASLR.<br><strong>3.</strong> Test with <code>checksec</code>.</p>               |
| **SQLi/XSS**              | <p>▶ Burp Suite<br>▶ OWASP ZAP</p>                  | <p>▶ SQLmap<br>▶ BeEF (XSS)</p>                               | <p><strong>1.</strong> Sanitize inputs.<br><strong>2.</strong> Deploy WAF (ModSecurity).<br><strong>3.</strong> Revoke stolen sessions.</p>             |
| **Misconfigurations**     | <p>▶ AWS Config<br>▶ OpenVAS</p>                    | <p>▶ Nmap (service scanning)<br>▶ Shodan</p>                  | <p><strong>1.</strong> Apply CIS benchmarks.<br><strong>2.</strong> Disable default creds.<br><strong>3.</strong> Isolate exposed systems.</p>          |
| **Kernel Flaws**          | <p>▶ Lynis (Linux audits)<br>▶ KernelPatchCheck</p> | ▶ DirtyPipe exploit (PoC)                                     | <p><strong>1.</strong> Patch kernel.<br><strong>2.</strong> Restrict root.<br><strong>3.</strong> Monitor <code>/proc/self/mem</code> access.</p>       |
| **Vulnerable Components** | <p>▶ Dependency-Check<br>▶ Snyk</p>                 | ▶ Exploit-DB (search CVEs)                                    | <p><strong>1.</strong> Update libraries.<br><strong>2.</strong> Use virtual patching (WAF).<br><strong>3.</strong> Isolate affected systems.</p>        |
| **SSRF**                  | <p>▶ Burp Collaborator<br>▶ SSRFmap</p>             | ▶ Gopherus (exploit crafting)                                 | <p><strong>1.</strong> Block internal IPs.<br><strong>2.</strong> Use allowlists.<br><strong>3.</strong> Audit outbound traffic.</p>                    |
| **Weak Credentials**      | <p>▶ Hydra (brute-force)<br>▶ CrackMapExec</p>      | ▶ John the Ripper                                             | <p><strong>1.</strong> Enforce MFA.<br><strong>2.</strong> Reset passwords.<br><strong>3.</strong> Monitor auth logs.</p>                               |
| **Race Conditions**       | <p>▶ TimeCheck (custom scripts)<br>▶ AFL</p>        | ▶ TOCTOU exploits (PoC)                                       | <p><strong>1.</strong> Use atomic operations.<br><strong>2.</strong> Lock files.<br><strong>3.</strong> Audit temp file usage.</p>                      |
| **Unrestricted Uploads**  | <p>▶ ClamAV (malware scan)<br>▶ Metasploit</p>      | ▶ Web shells (e.g., JSP/PHP)                                  | <p><strong>1.</strong> Validate file types.<br><strong>2.</strong> Store outside webroot.<br><strong>3.</strong> Scan uploaded files.</p>               |
| **Symbolic Links**        | ▶ `find / -type l` (manual check)                   | ▶ Symlink race exploits                                       | <p><strong>1.</strong> Disable symlink following.<br><strong>2.</strong> Use <code>openat()</code>.<br><strong>3.</strong> Audit <code>/tmp</code>.</p> |

#### Key Mitigation Themes:

1. **Automation**
   * Use tools like **Terraform for configs**, **Dependabot for dependencies**, and **OpenSCAP for audits**.
2. **Secure Defaults**
   * **CIS benchmarks** for OS/apps, **disable debug modes**, and **least-privilege access**.
3. **Zero-Trust Principles**
   * **Input validation**, **output encoding**, and **network segmentation** for SSRF/XSS.
4. **Patch Management**
   * Prioritize **kernel/libc updates** and **vulnerable component patches** (e.g., Log4j).

**Mitigation Examples**:
   * **Patch management** (kernel flaws, buffer overflows).
   * **Least privilege access** (permissions, file descriptors).
   * **Input sanitization** (SQLi/XSS prevention).

#### Key Tools by Function

**Detection & Scanning**

| **Tool**       | **Purpose**                        | **Vulnerability Focus**              |
| -------------- | ---------------------------------- | ------------------------------------ |
| **Nessus**     | CVE scanning                       | Buffer overflows, misconfigurations  |
| **Burp Suite** | Web app testing                    | SQLi, XSS, SSRF                      |
| **OpenVAS**    | Open-source vulnerability scanning | Misconfigurations, weak creds        |
| **Lynis**      | Linux hardening audits             | Kernel flaws, file permissions       |
| **Shodan**     | Internet-exposed device search     | Misconfigurations (e.g., open Redis) |

**Exploitation & Testing**

| **Tool**       | **Purpose**                   | **Example Command**                   |
| -------------- | ----------------------------- | ------------------------------------- |
| **Metasploit** | Exploit development/framework | `use exploit/windows/smb/ms17_010`    |
| **SQLmap**     | Automated SQLi testing        | `sqlmap -u "http://site.com?id=1"`    |
| **Hydra**      | Brute-force credentials       | `hydra -l admin -P pass.txt ssh://IP` |
| **BeEF**       | XSS exploitation              | Hook browsers via `<script>`          |
| **Gopherus**   | SSRF exploit crafting         | Generate malicious Gopher payloads    |

**Mitigation & Hardening**

| **Tool**        | **Purpose**             | **Command/Use Case**             |
| --------------- | ----------------------- | -------------------------------- |
| **Ansible**     | Config hardening        | CIS benchmark playbooks          |
| **ModSecurity** | WAF for injection flaws | Block SQLi/XSS patterns          |
| **SELinux**     | Linux MAC enforcement   | `setenforce 1` (enforcing mode)  |
| **ClamAV**      | Malware scanning        | `clamscan /var/www/uploads`      |
| **Dependabot**  | Dependency updates      | Auto-PR for vulnerable libraries |

### References

NIST Special Publication 800-115: Technical Guide to Information Security Testing and Assessment (NIST 800-115). Retrieved January 21, 2020, from http://csrc.nist.gov/publications/nistpubs/800-115/SP800-115.pdf
