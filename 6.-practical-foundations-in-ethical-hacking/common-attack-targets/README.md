---
description: >-
  This section explains common cyber attack targets and associated attack
  vectors and vulnerabilities
---

# Common attack targets

## Topics covered in this section

* **NIST SP 800-115's attack categories**
* **Expanded attack categories**

### NIST SP 800-115's attack categories

Most vulnerabilities exploited by penetration testing fall into the following categories (NIST SP 800-115, 2008, pp. 5-4-5-5):

* Misconfigurations. Misconfigured security settings, particularly insecure default settings, are usually easily exploitable.
* Kernel Flaws. Kernel code is the core of an OS, and enforces the overall security model for the system—so any security flaw in the kernel puts the entire system in danger.&#x20;
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

**Comparison to OWASP/Other Frameworks**

* **NIST SP 800-115** focuses on **technical vulnerabilities** (e.g., kernel flaws), while OWASP Top 10 emphasizes **web-specific risks**.
* **Shared themes**: Input validation, misconfigurations appear in both.

### References

NIST Special Publication 800-115: Technical Guide to Information Security Testing and Assessment (NIST 800-115). Retrieved January 21, 2020, from http://csrc.nist.gov/publications/nistpubs/800-115/SP800-115.pdf
