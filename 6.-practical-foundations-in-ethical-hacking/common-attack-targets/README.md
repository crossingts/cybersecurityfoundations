---
description: >-
  This section explains common cyber attack targets and associated attack
  vectors and vulnerabilities
---

# Common attack targets

• Identify common attack targets, including OS vulnerabilities, shrink-wrap code, misconfigurations and default credentials, and OWASP Top 10 vulnerabilities such as cross-site scripting (XSS) and SQL injection (SQLi).

### Common attack targets

• OS vulnerabilities (unpatched CVE-listed flaws)&#x20;

• Shrink-wrap code

• Misconfigurations (insecure default settings/improperly configured systems or services)

• Default credentials (weak or unchanged default login credentials)

• Web application vulnerabilities (OWASP Top 10)

Cross-Site Scripting (XSS) – Client-side script execution.&#x20;

SQL Injection (SQLi) – Database manipulation.

Here’s a structured **comparison table** separating **Attack Targets**, **Vectors**, and **Vulnerabilities** for common attacks, with additional examples:

| **Attack Target**         | **Attack Vector**                 | **Underlying Vulnerability**                      |
| ------------------------- | --------------------------------- | ------------------------------------------------- |
| **Operating System (OS)** | Exploiting unpatched services     | Unpatched OS vulnerabilities (CVE-listed flaws)   |
|                           | Brute-forcing weak credentials    | Default or weak passwords                         |
| **Web Application**       | SQL Injection (SQLi)              | Improper input sanitization in database queries   |
|                           | Cross-Site Scripting (XSS)        | Lack of output encoding/input validation          |
|                           | CSRF (Cross-Site Request Forgery) | Missing anti-CSRF tokens                          |
| **Network Services**      | Man-in-the-Middle (MITM) attacks  | Unencrypted communications (e.g., plaintext HTTP) |
|                           | DNS spoofing                      | Misconfigured DNS settings                        |
| **Human (User)**          | Phishing emails                   | Lack of security awareness                        |
|                           | Credential stuffing               | Password reuse across accounts                    |
| **IoT Devices**           | Exploiting default credentials    | Factory-set passwords not changed                 |
|                           | Firmware exploitation             | Lack of secure update mechanisms                  |
| **Cloud Services**        | Misconfigured S3 buckets          | Excessive permissions (public access enabled)     |
|                           | API abuse                         | Broken authentication/authorization               |

#### **Key Clarifications**

1. **Target**: The asset being attacked (e.g., OS, user, app).
2. **Vector**: The delivery method (e.g., phishing, SQLi).
3. **Vulnerability**: The weakness enabling the attack (e.g., unpatched software).

#### **Example Flow**

* **Target**: Web Application → **Vector**: XSS → **Vulnerability**: Lack of input sanitization.
* **Target**: User → **Vector**: Phishing → **Vulnerability**: Human error (clicking malicious links).

Most vulnerabilities exploited by penetration testing fall into the following categories: Misconfigurations (particularly, insecure default settings), kernel flaws, buffer overflows, insufficient input validation, symbolic links, file descriptors, race conditions, and incorrect file and directory permissions (NIST SP 800-115, 2008, pp. 5-4-5-5).&#x20;

Here’s a **NIST SP 800-115-aligned table** mapping **vulnerabilities** to their typical **attack targets**, **vectors**, and **exploits**:

| **Vulnerability (NIST SP 800-115)** | **Attack Target**          | **Attack Vector**                             | **Example Exploit**                                   |
| ----------------------------------- | -------------------------- | --------------------------------------------- | ----------------------------------------------------- |
| **Misconfigurations**               | OS, Cloud, Network Devices | Exploiting default credentials/open ports     | Accessing admin panels with `admin:admin` credentials |
| **Insecure Default Settings**       | Databases, Applications    | Using factory-set passwords/weak permissions  | MongoDB exposed to the internet with no password      |
| **Kernel Flaws**                    | Operating System           | Privilege escalation via kernel exploits      | Dirty Pipe (CVE-2022-0847) for root access            |
| **Buffer Overflows**                | Applications, Services     | Overflowing memory to execute shellcode       | Stack-based overflow in legacy FTP servers            |
| **Insufficient Input Validation**   | Web Applications           | SQLi, XSS, Command Injection                  | Bypassing login forms with `' OR 1=1 --`              |
| **Symbolic Link (Symlink) Issues**  | File Systems               | Tricking privileged processes to write files  | Symlink attacks in `/tmp` directories                 |
| **File Descriptor Leaks**           | Running Processes          | Accessing sensitive files left open           | Reading `/etc/passwd` from a crashed service          |
| **Race Conditions**                 | Concurrent Systems         | TOCTOU (Time-of-Check to Time-of-Use) attacks | Changing file permissions between check and use       |
| **Incorrect File/Directory Perms**  | File Systems               | Reading/writing restricted files              | `chmod 777` exposing SSH private keys                 |

***

#### **Key Insights from NIST SP 800-115**

1. **Focus on Exploitability**:
   * These vulnerabilities are prioritized because they’re **frequently exploitable** during pentests (e.g., misconfigurations are low-hanging fruit).
   * Many stem from **poor system hygiene** (defaults, permissions).
2. **Attack Surface Coverage**:
   * **Kernel flaws** → OS-level compromise.
   * **Input validation** → Web app breaches (OWASP Top 10 overlap).
   * **Race conditions/symlinks** → Advanced privilege escalation.
3. **Mitigation Examples**:
   * **Patch management** (kernel flaws, buffer overflows).
   * **Least privilege** (permissions, file descriptors).
   * **Input sanitization** (SQLi/XSS prevention).

***

#### **Comparison to OWASP/Other Frameworks**

* **NIST SP 800-115** focuses on **technical vulnerabilities** (e.g., kernel flaws), while OWASP Top 10 emphasizes **web-specific risks**.
* **Shared themes**: Input validation, misconfigurations appear in both.

***

Network penetration testing and exploitation techniques typically include bypassing firewalls, router testing, IPS/IDS evasion, DNS footprinting, open port scanning and testing, SSH attacks, proxy servers, network vulnerabilities, and application penetration testing (Cipher, n.d.).
