---
description: >-
  This section explains common cyber attack targets and associated attack
  vectors and vulnerabilities
---

# Common attack targets

• Identify common attack targets, including OS vulnerabilities, shrink-wrap code, misconfigurations and default credentials, and OWASP Top 10 vulnerabilities such as cross-site scripting (XSS) and SQL injection (SQLi).

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

**Key Insights from NIST SP 800-115**

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

**Comparison to OWASP/Other Frameworks**

* **NIST SP 800-115** focuses on **technical vulnerabilities** (e.g., kernel flaws), while OWASP Top 10 emphasizes **web-specific risks**.
* **Shared themes**: Input validation, misconfigurations appear in both.
