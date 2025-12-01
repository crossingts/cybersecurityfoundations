---
description: >-
  This section explores common cyber attack targets and associated attack
  vectors and vulnerabilities
hidden: true
---

# Common attack targets-2

## Learning objectives <a href="#learning-objectives" id="learning-objectives"></a>

* Become familiar with common cyber attack targets and associated attack vectors and vulnerabilities

This section explores common cyber attack targets and associated attack vectors and vulnerabilities.

## Topics covered in this section

* **Introduction**
* **NIST SP 800-115's attack categories**
* **OWASP Top 10**
* **Common Weakness Enumeration (CWE™)**
* **Common Vulnerabilities and Exposures (CVE®) & NVD**
* **Prioritized attack categories** 
* **Detection, exploitation, and mitigation of prioritized vulnerabilities** 

### Introduction

When it comes to categorizing common vulnerabilities targeted by penetration testers (and malicious hackers), NIST's 2008 categories of vulnerabilities (attack targets) is a logical starting point. NIST SP 800-115 (Technical Guide to Information Security Testing and Assessment) was published in 2008 but it has not been formally updated. While the high-level principles and methodology of penetration testing in the guide are still sound, the taxonomy of vulnerabilities is significantly outdated. The attack landscape has evolved dramatically, primarily towards web applications, identity-based attacks, APIs, and cloud services. 

A modern, practical taxonomy of attack categories can be anchored in the following three frameworks:

- **OWASP Top 10:** The de facto standard for categorizing critical risks in web applications.
- **Common Weakness Enumeration (CWE):** The authoritative list for classifying the root cause of software vulnerabilities.
- **Common Vulnerabilities and Exposures (CVE) & the National Vulnerability Database (NVD):** The systems for tracking specific, instances of vulnerabilities in software products.

These three frameworks reflect an evolving attack landscape prioritizing the following categories of vulnerabilities:

- **Web Application Flaws:** Injection (SQLi, OS Command), XSS, Broken Access Control (IDOR).
- **Security Misconfigurations:** Cloud storage (S3) buckets, default credentials, unnecessary services.
- **Identity & Access Issues:** Weak passwords, lack of multi-factor authentication, privilege escalation.
- **Outdated Software:** Unpatched systems with known CVEs.

### NIST SP 800-115's attack categories

The majority of vulnerabilities exploited by penetration testing fall into the following categories (NIST SP 800-115, 2008, pp. 5-4-5-5):

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
| **Buffer Overflows**                      | Applications, OS, Services, Applications, Services      | Crafted input overflowing memory, overflowing memory to execute shellcode                   | **EternalBlue** (MS17-010), **Code Red worm** (IIS buffer overflow), Stack-based overflow in legacy FTP servers                                   |
| **Insufficient Input Validation**         | Web apps, APIs, Databases, Web Applications             | SQLi, XSS, Command Injection                                                                | **Equifax breach** (SQLi, CVE-2017-5638), **Log4Shell** (CVE-2021-44228), Bypassing login forms with `' OR 1=1 --`                                |
| **Symbolic Links (Symlink)**              | File systems, Privileged apps, File Systems             | Tricking apps into writing to sensitive files, tricking privileged processes to write files | **Docker symlink escape** (CVE-2018-15664), Symlink attacks in `/tmp` directories                                                                 |
| **File Descriptor Issues**                | OS, Applications, Running Processes                     | Exploiting unclosed file handles, accessing sensitive files left open                       | **Heartbleed** (CVE-2014-0160) via OpenSSL file descriptor leaks, Reading `/etc/passwd` from a crashed service                                    |
| **Race Conditions (TOCTOU)**              | OS, Applications, Concurrent Systems                    | Timing attacks to bypass checks, TOCTOU (Time-of-Check to Time-of-Use) attacks              | Linux `ptrace` race condition (CVE-2019-13272), Changing file permissions between check and use                                                   |
| **Incorrect File/Directory Permissions**  | OS, Databases, Apps, File Systems                       | Unauthorized access/modification, reading/writing restricted files                          | **MongoDB ransomware attacks** (exposed databases with weak permissions), `chmod 777` exposing SSH private keys                                   |

### OWASP Top 10

The **Open Worldwide Application Security Project (OWASP)** is a non-profit foundation that works to improve the security of software through community-led open-source projects. Its flagship project is the **OWASP Top 10**, a regularly updated document that raises awareness about the most critical security risks to web applications.

While NIST SP 800-115 offers a general, system-level view of vulnerabilities, the OWASP Top 10 provides a specialized, application-centric focus. First published in 2003, the OWASP Top 10 is based on real-world data from thousands of applications and vulnerabilities. The OWASP Top 10 serves as a vital benchmark for developers, auditors, and penetration testers, and is referenced by many standards, including the Payment Card Industry Data Security Standard (PCI DSS) and U.S. government frameworks.

For penetration testers, the OWASP Top 10 provides a prioritized checklist of what to look for. This is operationalized through the **OWASP Web Security Testing Guide (WSTG)**, a comprehensive manual that outlines how to test for each category of vulnerability. The testing methodology in the WSTG mirrors a real-world engagement, starting with information gathering and configuration management testing, then moving into deep assessments of authentication, authorization, and business logic, with dedicated sections for testing each Top 10 risk.

Both the OWASP Top 10 and NIST SP 800-115 frameworks share several core themes, notably,

- **Input Validation:** NIST's "Insufficient Input Validation" category is directly reflected in OWASP's A03:2021-Injection and A03:2021-Server-Side Request Forgery (SSRF).
- **Misconfigurations:** NIST's "Misconfigurations" are a primary focus of OWASP A05:2021-Security Misconfiguration.
- **Access Control:** The principle behind NIST's "Incorrect File and Directory Permissions" is expanded in the web context by OWASP A01:2021-Broken Access Control.

### Common Weakness Enumeration (CWE™)

NIST itself now primarily uses the **CWE List** as the authoritative source for types of software weaknesses. This is a much more granular and detailed community-developed list of common software and hardware security weaknesses which serves as a common language for describing vulnerabilities. Penetration testers use the CWE to classify the root cause of the flaws they find. The **CWE Top 25 Most Dangerous Software Weaknesses** is the spiritual successor to NIST's 2008 list and it is updated regularly based on real-world data.

**Mapping NIST's 2008 List to the 2023 CWE Top 25**

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

Vulnerability table based on exploitability (ease of attack) and impact (potential damage), using CVSS v3.0 scores (where applicable) and real-world prevalence.

The following table provides a comprehensive overview of prioritized vulnerabilities contextualized within attack targets, attack vectors, risk scoring, and mitigation strategies - making it ideal for CCNA/CEH-level instruction on vulnerability prioritization and management.

**Prioritized Vulnerability Table With Mitigation Strategies**

|**Vulnerability**|**Attack Target**|**Attack Vector**|**CVSS**|**Exploitability**|**Impact**|**Example Exploit**|**Mitigation Strategies**|
|---|---|---|---|---|---|---|---|
|**Buffer Overflows**|Applications, OS, Services|Crafted input overflowing memory, executing shellcode|9.8 (Critical)|Moderate-High|Critical|EternalBlue (WannaCry)|<p>▶ Use memory-safe languages (Rust, Go).  <br>▶ Enable DEP/ASLR.  <br>▶ Patch OS/libc regularly.</p>|
|**Injection Flaws** (SQLi, XSS)|Web apps, APIs, Databases|SQLi, XSS, Command Injection|9.8 (Critical)|High|Critical|Equifax (SQLi), Log4Shell|<p>▶ Parameterized queries.  <br>▶ Input sanitization.  <br>▶ WAF rules (e.g., ModSecurity).</p>|
|**Misconfigurations**|Servers, Cloud, IoT, APIs, Network Devices|Default credentials, open ports, exposed interfaces|9.0 (High)|**Very High**|High|AWS S3 leaks, Jenkins RCE|<p>▶ Automated scanning (Chef, Ansible).  <br>▶ Least-privilege access.  <br>▶ Disable default credentials.</p>|
|**Kernel Flaws**|OS (Linux/Windows/macOS)|Privilege escalation via kernel bugs, exploits|8.8 (High)|Moderate|Critical|Dirty Pipe (CVE-2022-0847)|<p>▶ Immediate kernel patching.  <br>▶ Restrict root access.  <br>▶ Use SELinux/AppArmor.</p>|
|**Vulnerable Components**|Libraries, Frameworks|Exploiting known CVEs in dependencies|9.1 (Critical)|**Very High**|Critical|Log4Shell, Struts (Equifax)|<p>▶ SBOM (Software Bill of Materials).  <br>▶ Automated dependency updates (Dependabot).</p>|
|**Security Misconfigurations**|Cloud, Servers, Containers|Exposed admin interfaces, verbose errors|8.5 (High)|High|High|Kubernetes API exposure|<p>▶ CIS benchmarks.  <br>▶ Regular audits with OpenSCAP.  <br>▶ Disable debug modes.</p>|
|**Broken Authentication**|Web apps, APIs|Credential stuffing, session hijacking|8.8 (High)|High|High|Facebook token hijacking, OAuth misconfigurations|<p>▶ MFA enforcement.  <br>▶ Rate-limiting login attempts.  <br>▶ OAuth 2.0 hardening.</p>|
|**SSRF**|Cloud, Internal Networks|Forging requests from the server|8.7 (High)|Moderate-High|High|Capital One breach, AWS metadata theft|<p>▶ Network segmentation.  <br>▶ Block internal IPs in requests.  <br>▶ Use allowlists for URLs.</p>|
|**Insufficient Input Validation**|Web apps, APIs, Databases|SQLi, XSS, Command Injection|8.1 (High)|High|High|Heartbleed (OpenSSL)|<p>▶ Input length/type checks.  <br>▶ Fuzz testing (AFL).  <br>▶ Zero-trust input models.</p>|
|**Race Conditions**|OS, Applications, Concurrent Systems|TOCTOU (Time-of-Check to Time-of-Use) attacks|7.5 (High)|Hard|High|Dirty COW (Linux)|<p>▶ Atomic operations.  <br>▶ File-locking mechanisms.  <br>▶ TOCTOU checks.</p>|
|**Unrestricted File Uploads**|Web apps|Uploading malicious executables|8.0 (High)|Moderate|High|WordPress malware uploads, Web shell uploads|<p>▶ File type verification (magic numbers).  <br>▶ Store uploads outside webroot.  <br>▶ Scan with ClamAV.</p>|
|**XSS**|Web apps, APIs|Cross-site scripting attacks|7.5 (High)|**Very High**|Moderate|Tesla infotainment XSS|<p>▶ CSP headers.  <br>▶ Output encoding (OWASP ESAPI).  <br>▶ DOM sanitization.</p>|
|**Symbolic Links**|File systems, Privileged apps|Tricking apps into writing to sensitive files|7.1 (High)|Moderate|High|Docker breakout|<p>▶ Disable symlink following.  <br>▶ chroot/jail environments.  <br>▶ Use <code>openat()</code> safely.</p>|
|**Weak Credentials**|IoT, Web apps, Systems|Default/weak password exploitation|7.5 (High)|**Very High**|High|Mirai botnet (IoT)|<p>▶ Password policies (12+ chars).  <br>▶ Block common passwords.  <br>▶ Certificate-based auth.</p>|
|**Incorrect File Permissions**|OS, Databases, Apps, File Systems|Unauthorized access/modification, reading restricted files|7.8 (High)|Moderate|High|MongoDB ransomware|<p>▶ <code>chmod 600</code> for sensitive files.  <br>▶ Regular <code>auditd</code> checks.  <br>▶ Principle of least privilege.</p>|
|**Insecure Direct Object Refs.**|Web apps, APIs|Manipulating object references|_Not Rated_|High|High|Accessing other users' data via ID parameter tampering|_Mitigation strategies to be added_|
|**File Descriptor Leaks**|OS, Applications, Running Processes|Exploiting unclosed file handles|6.5 (Medium)|Low|High|Heartbleed|<p>▶ Secure coding (close handles).  <br>▶ Static analysis (Coverity).  <br>▶ Memory-safe languages.</p>|
|**Missing Encryption**|Databases, Networks|Sniffing plaintext data|6.8 (Medium)|Low|High|FTP credentials intercepted, unencrypted medical records|<p>▶ TLS 1.3+ enforcement.  <br>▶ Encrypt data at rest (AES-256).  <br>▶ HSM for keys.</p>|

**High-Risk Focus Areas:**

- **Critical (9.0+ CVSS)**: Patch buffers/injection flaws within 24hrs of CVE disclosure.
- **High (7.0–8.9 CVSS)**: Automate scans for misconfigurations/weak credentials weekly.
- **Medium (5.0–6.9 CVSS)**: Enforce encryption/MFA by policy.

### Detection, exploitation, and mitigation of prioritized vulnerabilities 

A consolidated toolkit and response playbook for each vulnerability category, combining the practical tools and high-level response steps security professionals use.

**Vulnerability Response Toolkit and Playbook**

| **Vulnerability**                 | **Detection Tools**                                                                                                                                | **Exploitation Tools**                                                                                                       | **Response Playbook**                                                                                                                                                                                                                                               |
| --------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Buffer Overflows**              | <p>▶ **Nessus/OpenVAS** (CVE scanning)  <br>▶ **AFL/LibFuzzer** (fuzzing)  <br>▶ **Static Analysis** (Coverity, CodeQL)</p>                        | <p>▶ **Metasploit** (exploit modules)  <br>▶ **GDB/PEDA** (debugging/crafting)  <br>▶ Public PoCs (Exploit-DB)</p>           | <p><strong>1. CONTAIN:</strong> Isolate affected system. <strong>2. ERADICATE:</strong> Apply patches; enable DEP/ASLR. <strong>3. RECOVER:</strong> Test hardening with `checksec`; redeploy from known-good images.</p>                                           |
| **Injection Flaws** (SQLi, XSS)   | <p>▶ **Burp Suite** / **OWASP ZAP** (intercepting proxy)  <br>▶ **SQLMap** (automated detection)  <br>▶ **Semgrep** (code analysis)</p>            | <p>▶ **SQLMap** (automated exploitation)  <br>▶ **BeEF** (XSS hooking)  <br>▶ Custom scripts</p>                             | <p><strong>1. CONTAIN:</strong> Deploy virtual patch (WAF like ModSecurity). <strong>2. ERADICATE:</strong> Fix code: parameterized queries, output encoding. <strong>3. RECOVER:</strong> Audit logs for stolen data; rotate exposed credentials.</p>              |
| **Misconfigurations**             | <p>▶ **Nmap** (service/version scan)  <br>▶ **Shodan/Censys** (internet exposure)  <br>▶ **OpenSCAP** (compliance scanning)</p>                    | <p>▶ **Metasploit** (auxiliary modules)  <br>▶ Manual login with default credentials  <br>▶ **Custom scripts**</p>           | <p><strong>1. CONTAIN:</strong> Remove system from untrusted networks. <strong>2. ERADICATE:</strong> Apply CIS benchmarks; disable defaults. <strong>3. RECOVER:</strong> Reconfigure with IaC (Ansible/Terraform); re-deploy.</p>                                 |
| **Kernel Flaws**                  | <p>▶ **Lynis** (system audit)  <br>▶ **KernelPatchCheck** scripts  <br>▶ Vulnerability scanners (Nessus)</p>                                       | <p>▶ Public **PoC exploits** (e.g., DirtyPipe)  <br>▶ **Metasploit** (privilege escalation modules)</p>                      | <p><strong>1. CONTAIN:</strong> Restrict SSH/root access. <strong>2. ERADICATE:</strong> Patch kernel immediately. <strong>3. RECOVER:</strong> Harden with SELinux/AppArmor; monitor `/proc/self/mem` access.</p>                                                  |
| **Vulnerable Components**         | <p>▶ **Dependency-Check** / **Snyk** / **Trivy** (SCA)  <br>▶ **Software Bill of Materials (SBOM)** analysis</p>                                   | <p>▶ **Metasploit** (exploit modules)  <br>▶ **Searchsploit** / **Exploit-DB**</p>                                           | <p><strong>1. CONTAIN:</strong> Isolate service; deploy WAF virtual patch. <strong>2. ERADICATE:</strong> Update/library patch via dependency manager. <strong>3. RECOVER:</strong> Implement automated SCA (Dependabot/Renovate).</p>                              |
| **Security Misconfigurations**    | <p>▶ **Cloud-native tools** (AWS Config, GCP Security Scanner)  <br>▶ **Kube-bench** (Kubernetes)  <br>▶ **TruffleHog** (secret scanning)</p>      | <p>▶ **Cloud metadata API** queries  <br>▶ **Kubectl** commands against exposed API</p>                                      | <p><strong>1. CONTAIN:</strong> Disable public access; restrict IAM roles. <strong>2. ERADICATE:</strong> Apply least-privilege configs; disable debug modes. <strong>3. RECOVER:</strong> Enforce configuration drift detection.</p>                               |
| **Broken Authentication**         | <p>▶ **Burp Suite** (Intruder for brute-force testing)  <br>▶ **OWASP ZAP** (auth testing)  <br>▶ Custom credential stuffing scripts</p>           | <p>▶ **Hydra** / **Medusa** (brute-force)  <br>▶ **Burp Suite** (session hijacking)  <br>▶ **OAuth tester** tools</p>        | <p><strong>1. CONTAIN:</strong> Block attacking IPs; enforce rate limiting. <strong>2. ERADICATE:</strong> Enforce MFA; fix session management. <strong>3. RECOVER:</strong> Reset compromised credentials; audit logs.</p>                                         |
| **SSRF**                          | <p>▶ **Burp Suite** (manual testing with Collaborator)  <br>▶ **SSRFmap** (automated testing)  <br>▶ Code review for URL fetching</p>              | <p>▶ **Gopherus** (payload crafting)  <br>▶ **Burp Collaborator** (to confirm)</p>                                           | <p><strong>1. CONTAIN:</strong> Block outbound traffic to internal IPs. <strong>2. ERADICATE:</strong> Implement allowlists for fetched URLs; use network segmentation. <strong>3. RECOVER:</strong> Audit all outbound requests from app servers.</p>              |
| **Insufficient Input Validation** | <p>▶ **Fuzzing** (AFL, Burp Intruder)  <br>▶ **Static Application Security Testing (SAST)**  <br>▶ Manual code review</p>                          | <p>▶ **Burp Suite Repeater** (manual exploitation)  <br>▶ **FFUF** / **Wfuzz** (parameter fuzzing)</p>                       | <p><strong>1. CONTAIN:</strong> Input sanitization/WAF. <strong>2. ERADICATE:</strong> Implement strict whitelist validation. <strong>3. RECOVER:</strong> Integrate fuzz testing into CI/CD.</p>                                                                   |
| **Race Conditions**               | <p>▶ **Custom timing scripts**  <br>▶ **Code review** for TOCTOU patterns  <br>▶ **AFL** (fuzzing with timing)</p>                                 | <p>▶ **Custom exploit scripts**  <br>▶ Public **PoC** exploits</p>                                                           | <p><strong>1. CONTAIN:</strong> Implement file locking. <strong>2. ERADICATE:</strong> Refactor code to use atomic operations. <strong>3. RECOVER:</strong> Audit temp file usage and `/tmp` directory.</p>                                                         |
| **Unrestricted File Uploads**     | <p>▶ **Manual testing** (Burp)  <br>▶ **ClamAV** (malware scanning post-upload)  <br>▶ **Static Analysis** for file handling code</p>              | <p>▶ Upload **web shells** (.jsp, .php, .aspx)  <br>▶ **Metasploit** (payload generation)</p>                                | <p><strong>1. CONTAIN:</strong> Quarantine uploaded files; disable upload feature. <strong>2. ERADICATE:</strong> Implement strict file type verification (magic numbers). <strong>3. RECOVER:</strong> Store files outside webroot; scan all uploads.</p>          |
| **XSS**                           | <p>▶ **Burp Suite** / **OWASP ZAP** (automated scanner)  <br>▶ **Manual testing** with payload lists  <br>▶ **DAST** tools</p>                     | <p>▶ **BeEF** (hook browser)  <br>▶ **XSS Hunter** (blind XSS)  <br>▶ Crafted payload delivery</p>                           | <p><strong>1. CONTAIN:</strong> Deploy CSP headers. <strong>2. ERADICATE:</strong> Implement context-aware output encoding. <strong>3. RECOVER:</strong> Conduct post-remediation penetration testing.</p>                                                          |
| **Symbolic Links**                | <p>▶ **Manual audit** (`find / -type l -perm -o=w`)  <br>▶ **Code review** for file operations  <br>▶ **Lynis** (file system audits)</p>           | <p>▶ **Symlink race condition** exploits  <br>▶ **Docker breakout** PoCs</p>                                                 | <p><strong>1. CONTAIN:</strong> Disable symlink following in config. <strong>2. ERADICATE:</strong> Use secure functions (`openat()`); implement chroot/jails. <strong>3. RECOVER:</strong> Audit `/tmp` and world-writable directories.</p>                        |
| **Weak Credentials**              | <p>▶ **Nmap** scripts (`ssh-brute`, `http-auth-finder`)  <br>▶ **Hydra** (targeted testing)  <br>▶ **Breached password lists**</p>                 | <p>▶ **Hydra** / **Medusa** (brute-force)  <br>▶ **John the Ripper** (hash cracking)  <br>▶ **CrackMapExec** (SMB/WinRM)</p> | <p><strong>1. CONTAIN:</strong> Block IP after failed attempts; lock account. <strong>2. ERADICATE:</strong> Enforce strong password policy; implement MFA. <strong>3. RECOVER:</strong> Reset passwords; monitor for credential stuffing.</p>                      |
| **Incorrect File Permissions**    | <p>▶ **Linux:** `find / -perm -o=w`  <br>▶ **Windows:** AccessChk (Sysinternals)  <br>▶ **Lynis** / **OpenSCAP** (auditing)</p>                    | <p>▶ Manual file access/overwrite  <br>▶ **Custom scripts** to exploit writable paths</p>                                    | <p><strong>1. CONTAIN:</strong> Restrict access (`chmod 600`, `icacls`). <strong>2. ERADICATE:</strong> Apply principle of least privilege. <strong>3. RECOVER:</strong> Implement regular permission audits with `auditd` or equivalent.</p>                       |
| **Insecure Direct Object Refs.**  | <p>▶ **Manual testing** (Burp Suite)  <br>▶ **OWASP ZAP** (active scan)  <br>▶ Code review for direct object references</p>                        | <p>▶ **Burp Repeater** (parameter manipulation)  <br>▶ **Custom enumeration scripts**</p>                                    | <p><strong>1. CONTAIN:</strong> Implement access control checks on all object references. <strong>2. ERADICATE:</strong> Use indirect reference maps (e.g., session-based keys). <strong>3. RECOVER:</strong> Audit logs for unauthorized data access attempts.</p> |
| **File Descriptor Leaks**         | <p>▶ **Static Analysis** (Coverity, CodeQL)  <br>▶ **Valgrind** / **AddressSanitizer** (runtime)  <br>▶ Code review</p>                            | <p>▶ Difficult to directly exploit; often leads to info disclosure (Heartbleed)</p>                                          | <p><strong>1. CONTAIN:</strong> Restart affected service. <strong>2. ERADICATE:</strong> Fix code to properly close handles. <strong>3. RECOVER:</strong> Integrate static analysis into CI/CD; use memory-safe languages.</p>                                      |
| **Missing Encryption**            | <p>▶ **Wireshark** / **tcpdump** (traffic analysis)  <br>▶ **Nmap** scripts (`ssl-cert`, `ssh2-enum-algos`)  <br>▶ **Manual audit** of configs</p> | <p>▶ **Packet sniffing**  <br>▶ **Man-in-the-Middle (MitM)** tools (ettercap)</p>                                            | <p><strong>1. CONTAIN:</strong> Enforce TLS (e.g., HSTS). <strong>2. ERADICATE:</strong> Encrypt data in transit (TLS 1.3+) and at rest (AES-256). <strong>3. RECOVER:</strong> Implement key management (HSMs, vaults); rotate exposed keys.</p>                   |

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

https://cwe.mitre.org/index.html

NIST Special Publication 800-115: Technical Guide to Information Security Testing and Assessment (NIST 800-115). Retrieved January 21, 2020, from http://csrc.nist.gov/publications/nistpubs/800-115/SP800-115.pdf

The Mitre Corporation. MITRE ATT&CK. https://x.com/MITREattack

The OWASP® Foundation. OWASP Top Ten. https://owasp.org/www-project-top-ten/
