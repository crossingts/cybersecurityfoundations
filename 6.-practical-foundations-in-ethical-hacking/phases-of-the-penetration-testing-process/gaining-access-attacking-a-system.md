# Gaining access (attacking a system)

### Introduction

The magic part of a penetration test is exploiting a vulnerability discovered during the vulnerability assessment phase (Harper et al., 2011; Walker, 2017). A penetration test “is when ethical hackers do their magic. They can test many of the vulnerabilities identified during the vulnerability assessment to quantify the actual threat and risk posed by the vulnerability” (Harper el al., 2011, p. 11).

Next, we start talking about actual system hacking—what to do once you’re at the machine’s front door.&#x20;

### Password Attacks

Most people will make their passwords the exact length of the minimum required. "If the network administrator sets the minimum at eight characters, over 95 percent of the passwords will be only eight characters—very helpful to the password-cracking attacker" (Walker, 2012, p. 157).

ECC defines four main attack types for password cracking: passive online, active online, offline, and non-electronic (social engineering).

• Passive online attack: This essentially boils down to sniffing a wire in an attempt to either intercept a password in clear text or execute a replay attack or a man-in-the-middle (MITM) attack. A password sent in clear text using Telnet, for example, can be easily discovered using a packet analyzer. A password sent hashed or encrypted, can be uncovered by comparing the hash or cipher to a dictionary list or by trying a password cracker on the captured value.&#x20;

During the man-in-the-middle attack, the hacker will attempt to re-send the authentication request to the server for the client, effectively routing all traffic through the attacker’s machine. In a replay attack, however, the entire authentication process is captured and replayed at a later time—the client isn’t even part of the session. (Walker, 2012, p. 158)

Some tools such as Cain and Abel, a Windows-based sniffer/password cracker, can be used to automate passive online password hacking. Cain will capture all the clear-text passwords, along with any hashes. You can then use Cain to execute some offline brute-force or dictionary attacks on the password hashes.&#x20;

• Active online attack: This entails the attacker guessing passwords. This includes dictionary and brute-force attacks, hash injections, phishing, Trojans, spyware, keyloggers, and password guessing. In a hash injection attack, the attacker injects a stolen hash into a local session in hopes of accessing something. Trojans or spyware can be installed on the system to steal passwords.&#x20;

Active online attacks take a much longer time than passive attacks, and are also much easier to detect. These attacks try to take advantage of bad passwords and security practices by individuals on a network. (Walker, 2012, p. 163)

**IPC$ and C$ Shares**

Attackers can exploit weak security practices such as weak credentials, excessive privileges, and enabled NULL sessions on older Windows systems (NT/2000) by targeting the IPC$ share in brute-force or password-guessing attacks. If an attacker finds an old, poorly secured Windows NT/2000 machine, they can attempt to connect to the **IPC$ share** using tools like:

* `net use \\target\IPC$ /u:username password`
* net use \target\ipc$ "" /u: " Sets up a Null session
* Legacy tools like **Legion**, **NetBIOS scanners**, or **SMB brute-forcers**.

Successful authentication via IPC$ can lead to:

* Enumeration of system info (users, shares, services).
* Further exploitation (e.g., dumping SAM database, lateral movement).

**Is the IPC$ vulnerability still relevant today?**

**Yes, but less so on modern systems** due to improvements:

* **Windows defaults**: Later versions (Win7+) disable NULL sessions and enforce stronger authentication (NTLMv2, Kerberos).
* **SMBv1 disabled**: Modern Windows disables SMBv1 (exploited by worms like **WannaCry**).
* **Account lockouts**: Brute-forcing is harder due to lockout policies.

**Where it’s still a threat**:

* Legacy systems (e.g., outdated industrial control systems, unpatched servers).
* Misconfigured networks where SMB is exposed to the internet (shocking, but it happens!)

**Mitigations & Detection**

* **Disable legacy protocols** (NetBIOS, SMBv1) if not needed.
* **Enforce strong passwords** to prevent brute-force attacks.
* **Monitor SMB logs** for repeated failed login attempts.
* **Restrict anonymous access** (e.g., `RestrictAnonymous` in registry).

The **C$ share** is another **hidden administrative share** that grants access to the entire `C:\` drive.

**Why is it a vulnerability?**

* **Default enabled**: Automatically created in Windows for remote admin (but requires admin credentials).
* **Exposes all files**: If compromised, attackers can read/write/delete system files.
* **Often targeted after IPC$ access**: Attackers use IPC$ to brute-force credentials, then access `C$`.

**How is it exploited?**

1. Attacker gains credentials (via IPC$ brute-forcing, phishing, etc.).
2.  Maps the share:

    cmd

    ```
    net use Z: \\target\C$ /u:Administrator P@ssw0rd
    ```
3. Now they can browse/upload files (e.g., plant malware, steal SAM database).

**Is it relevant today?**

* **Yes**, but only if:
  * Credentials are compromised (e.g., via **Pass-the-Hash**, **Mimikatz**).
  * SMB is left exposed (e.g., on a misconfigured server).
* **Mitigations**:
  * Disable unnecessary admin shares via registry (`AutoShareWks`/`AutoShareServer`).
  * Restrict SMB access via firewall rules.
  * Use **LAPS (Local Admin Password Solution)** to randomize local admin passwords.

Note — Passwords on Windows systems are found in the SAM file, located in c:\windows\system32\config (you may also find one in c:\windows\repair folder). Passwords for Linux are found in /etc/shadow.&#x20;

**Keyloggers**

Keyloggers record every keystroke typed—including passwords, messages, and sensitive data. They come in two forms:

* **Hardware keyloggers**: Physical devices plugged between the keyboard and computer (nearly undetectable without manual inspection).
* **Software keyloggers**: Malicious programs running silently in the background (easier to detect with security tools).

**How to Detect & Remove Them**

**1. Software Keyloggers** (Detectable with free tools)

* **Scan with Anti-Malware Tools**:
  * **Malwarebytes** (Free) – Scans for spyware and keyloggers.
  * **Spybot Search & Destroy** (Free) – Specializes in spyware removal.
  * **ClamAV** (Open-source) – Lightweight scanner for Linux/Windows.
* **Check Running Processes**:
  * **Process Explorer** (Free, Microsoft) – Monitors suspicious background apps.
  * **RKill** – Terminates malware processes before scanning.
* **Network Monitoring**:
  * **Wireshark** (Open-source) – Detects unusual outbound traffic (e.g., keystrokes being sent to attackers).

**2. Hardware Keyloggers** (Manual Detection Only)

* **Inspect USB/PS2 Connections**: Physically check for unexpected devices between the keyboard and PC.
* **Use a Virtual Keyboard**: Bypasses hardware keyloggers (Windows has an **On-Screen Keyboard**).

**Prevention Tips**

* **Use Two-Factor Authentication (2FA)** – Makes stolen keystrokes less useful.
* **Encrypt Keystrokes** – Tools like **KeyScrambler** (Free) encrypt typing in real time.
* **Regular Scans** – Schedule weekly checks with **Malwarebytes** or **ClamAV**.

**Final Note**: While software keyloggers can be removed, hardware keyloggers require physical inspection—so always check your ports!

Here’s a table summarizing which free/open-source keylogger detection tools work across **Windows, Linux, and macOS**:

| **Tool**             | **Windows** | **Linux** | **macOS** | **Notes**                                                                |
| -------------------- | ----------- | --------- | --------- | ------------------------------------------------------------------------ |
| **Malwarebytes**     | ✅           | ❌         | ✅         | Free version for Windows/macOS; no Linux support.                        |
| **ClamAV**           | ✅           | ✅         | ✅         | Open-source; cross-platform but requires manual setup on macOS.          |
| **Wireshark**        | ✅           | ✅         | ✅         | Network traffic analyzer; detects exfiltration (not keylogger-specific). |
| **Process Explorer** | ✅           | ❌         | ❌         | Windows-only (Microsoft Sysinternals).                                   |
| **Spybot S\&D**      | ✅           | ❌         | ❌         | Windows-only.                                                            |
| **RKill**            | ✅           | ❌         | ❌         | Windows-only (terminates malware processes).                             |

#### **Key Takeaways**:

* **Cross-Platform Tools**:
  * **ClamAV** (antivirus) and **Wireshark** (network analysis) work on all three OSes.
* **Windows-Only**:
  * Most specialized tools (Spybot, RKill, Process Explorer) are limited to Windows.
* **macOS Options**:
  * **Malwarebytes** (GUI) or **ClamAV** (command-line) for scans.
* **Linux**:
  * Relies on **ClamAV** or manual inspection (e.g., `ps aux`, `netstat`).

• Offline attack: This happens when an attacker steals a password database (like Windows' **SAM file** or a Linux **/etc/shadow**) and cracks it offline on their own system using such tools as Hashcat or John the Ripper—without interacting with the target. When an attacker **"cracks"** a stolen password file, they use computational methods to convert the scrambled (hashed) passwords back into plaintext.&#x20;

There are three main methods of offline password cracking: dictionary attack, hybrid attack, and brute-force attack.&#x20;

1. **Dictionary Attack**\
   Uses a pre-made list of passwords (e.g., common words, leaked passwords). Each entry is hashed and compared to the stolen hash. If matched, the password is cracked.
2. **Hybrid Attack**\
   Enhances dictionary attacks by modifying words—replacing letters with symbols (e.g., `P@ssw0rd`) or appending numbers (e.g., `Password123`). More effective than pure dictionary attacks.
3. **Brute-Force Attack**\
   Tries every possible combination of characters (e.g., `a`, `aa`, `aaa…`). Extremely slow but guaranteed to crack any password—eventually. Best for complex passwords but requires heavy computing power.

**Rainbow Tables**\
Precomputed tables of hashes for quick lookups. Faster than brute-forcing but less effective against _salted_ hashes.

**Popular open source password-cracking tools and their key features**

| **Tool**            | **Platform**  | **Target Passwords**                             | **Attack Methods**                          | **Notes**                                                                                        |
| ------------------- | ------------- | ------------------------------------------------ | ------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| **John the Ripper** | Linux/Windows | Unix, Windows NT, Kerberos, MySQL (with add-ons) | Dictionary, Hybrid, Brute-force             | Highly flexible, supports custom rules & hash formats. "Gold standard" for open-source cracking. |
| **Hashcat**         | Linux/Windows | 300+ hash types (NTLM, SHA, WPA, etc.)           | Dictionary, Hybrid, Brute-force, Rule-based | GPU-accelerated (fastest). Supports rainbow tables & advanced masking.                           |
| **Ophcrack**        | Linux/Windows | Windows LM/NTLM hashes                           | Rainbow tables                              | Specialized for Windows. Free version includes prebuilt tables.                                  |
| **THC Hydra**       | Linux/Windows | Online services (SSH, FTP, RDP, etc.)            | Dictionary, Brute-force                     | Not strictly offline but useful for credential stuffing.                                         |
| **RainbowCrack**    | Linux/Windows | Generic hashes (with rainbow tables)             | Rainbow tables                              | Precomputed hashes for faster cracking. Limited to supported algorithms.                         |

#### **Clarification Notes**

* **Fastest method**: Dictionary attacks (using tools like John or Hashcat).
* **Most thorough**: Brute-force (but slow; Hashcat’s GPU support speeds this up).
* **For Windows**: Ophcrack (rainbow tables) or John the Ripper (NTLM).
* **For versatility**: Hashcat (supports almost every hash type).
* **Not open-source**: Ophcrack (proprietary but free). LC5/L0phtCrack, Cain, KerbCrack, and Legion are proprietary tools.
