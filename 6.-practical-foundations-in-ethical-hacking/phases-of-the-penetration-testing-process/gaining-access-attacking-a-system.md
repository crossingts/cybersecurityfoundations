# Gaining access (attacking a system)

### Introduction

The magic part of a penetration test is exploiting a vulnerability discovered during the vulnerability assessment phase (Harper et al., 2011; Walker, 2017). A penetration test “is when ethical hackers do their magic. They can test many of the vulnerabilities identified during the vulnerability assessment to quantify the actual threat and risk posed by the vulnerability” (Harper el al., 2011, p. 11).

Next, we start talking about actual system hacking. In the enumeration phase, we successfully obtained user account information. Now what?  We’ll go over some of the basics on escalating your current privilege level. If the user account is not an administrator or doesn’t have access to interesting shares, escalating access privileges is necessary. After all, the point of hacking is gaining access to data or services. We'll go over four primary methods to gain administrator (or root) privileges on a system and best practices to maintain access and remain undetected after a successful penetration of a target system.

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
  * **ClamAV** (Open-source) – A lightweight cross platform scanner.
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

**Rainbow Tables**

Precomputed tables of hashes of every password imaginable for quick lookups. Faster than brute-forcing but less effective against _salted_ hashes.

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

#### **Escalating Privileges and Maintaining Stealth**

To gain administrator (or root) privileges on a system, there are four primary methods:

1. **Cracking an Admin/Root Password**
   * This should be your primary focus (especially for the CEH exam).
   * Successfully obtaining the password makes other methods unnecessary.
2. **Exploiting OS or Application Vulnerabilities**
   * Unpatched security flaws can allow privilege escalation.
   * Stay updated on vulnerabilities using security websites and tools like **Nessus**.
   * Proactively identify weaknesses before running automated scans.
3. **Using Exploitation Tools (e.g., Metasploit)**
   * **Metasploit** is a powerful framework for executing exploits and payloads.
     * Input the target’s IP and port, select an exploit, and deploy a payload.
     * Available in a free version (**Metasploit Framework**) and a paid **Metasploit Pro** (more advanced features).
   * Can be used via command line or a web-based GUI.
   * Extensive resources (forums, blogs, guides) are available on [metasploit.com](http://www.metasploit.com/).
   * **GUI Front-End Tools (e.g., Armitage)**
     * Provides a user-friendly interface for Metasploit.
     * Simplifies exploitation with an intuitive design.
     * More info at [fastandeasyhacking.com](http://fastandeasyhacking.com/).
4. **Social Engineering**

You can embed executable code in an e-mail marked "urgent" and ask the target to click it. A malicious PDF exploits a bug in the PDF viewer (not the OS itself). If the viewer is unpatched, opening the PDF can silently run attacker code. Privilege escalation happens afterward if the attacker needs to gain admin rights from a regular user.

**Stealth: Before, During, and After**

After gaining access to a machine, a hacker must remain stealthy. There’s stealth involved in hiding files, covering tracks, and maintaining access on the machine. To operate undetected during a penetration test or malicious attack, adversaries employ various techniques to hide files, evade logging, and cover their tracks.&#x20;

* Hiding Files on Windows Systems
* Data Concealment via Steganography
* Log Manipulation & Anti-Forensics
* Rootkits

**Hiding Files on Windows Systems**

**A. Alternate Data Streams (ADS) in NTFS**

**What it is:**\
Alternate Data Streams (ADS) is a feature of the NTFS file system that allows files to be embedded within other files invisibly. Originally introduced for compatibility with Apple’s HFS, ADS has persisted in Windows from NT through Windows 10/11.

**How it works:**

* An attacker can attach hidden files (text, executables, etc.) to an existing file without altering its visible properties.
*   Example commands:

    cmd

    ```
    echo "Malicious payload" > innocent.txt:secret.txt  
    type malware.exe > report.pdf:hidden.exe  
    ```
* The hidden file does not appear in directory listings (`dir`) or Windows Explorer unless explicitly checked.

Hands on NTFS File Streaming exercise: See Walker (2012, p. 172, Exercise 6-2: NTFS File Streaming). In the first part of this exercise, you want to hide the contents of a file named wanttohide.txt. To do this, you’re going to hide it behind a normal file that anyone browsing the directory would see. In the second part, you’ll hide an executable behind a file.&#x20;

**Detection & Limitations:**

* Modern forensic tools (e.g., **LNS, Sfind, Autopsy**) scan for ADS.
* Windows Vista+ includes `dir /r` to reveal streams.
* Copying files to a FAT32 partition removes ADS (FAT doesn’t support streams).
* Executables run from ADS may still appear in Task Manager under the parent process.

**Defensive Measures:**

* Monitor for suspicious ADS usage with tools like **StreamArmor** or **Sysinternals Streams**.
* Restrict execution of files from unusual locations via **AppLocker** or **SRP**.

**B. Hidden File Attributes**

**What it is:**\
A basic method where files are marked as "hidden" in Windows, preventing them from appearing in normal directory listings.

**How it works:**

* **GUI Method:** Right-click → Properties → Enable "Hidden."
*   **CLI Method:**

    cmd

    ```
    attrib +h secretfile.txt  
    ```

**Limitations:**

* Easily bypassed if "Show hidden files" is enabled in Folder Options.
* Does not protect against forensic analysis.

**Defensive Measures:**

* Configure Group Policy to force "Show hidden files" on critical systems.
* Use PowerShell scripts to scan for hidden files in sensitive directories.

**Data Concealment via Steganography**

**What it is:**\
Steganography hides data inside other files (images, audio, documents) without visibly altering them, making detection difficult.

**Common Tools:**

* **ImageHide, S-Tools, OpenStego** (for hiding data in images).
* **Snow** (hides text in whitespace).
* **Mp3Stego** (embeds data in MP3 files).

**Attack Scenario:**

* An attacker exfiltrates sensitive data by embedding it in a vacation photo (`beach.jpg`) and emailing it externally.
* Network monitoring sees only an image transfer, not the hidden payload.

**Detection & Prevention:**

* **Statistical Analysis Tools** (e.g., **StegExpose, StegDetect**) can identify anomalies.
* Block or scan suspicious file types (e.g., images from untrusted sources).

**Log Manipulation & Anti-Forensics**

**A. Windows Event Logs**

Windows maintains three primary logs:

1. **Application Log** – Records software-specific errors.
2. **System Log** – Tracks OS events (driver failures, reboots).
3. **Security Log** – Stores authentication, file access, and policy changes (if auditing is enabled).

**B. Poor Stealth Tactics (Avoid These)**

* **Deleting Entire Logs:**
  * Obvious red flag—empty logs trigger alerts.
* **Disabling Auditing Temporarily:**
  * Leaves a suspicious gap in logs.

**C. Better Log Evasion Methods**

1. **Selective Log Editing**
   * Remove only entries related to the attack.
   * Example: If brute-forcing a login, delete only failed login attempts.
2. **Log Corruption**
   * Partially corrupting logs may be dismissed as a system glitch.
3. **Relocating Log Files**
   *   Change the default log path via Registry:

       text

       ```
       HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog
       ```
   * Makes forensic analysis harder if logs are not in `%systemroot%\System32\Config`.

**D. Log Manipulation Tools**

*   **Auditpol** – Disables logging on remote machines:

    cmd

    ```
    auditpol \\[TargetIP] /disable  
    ```
* **WinZapper, Evidence Eliminator** – Selective log erasure.
* **Manual Registry Edits** – Modify audit policies to exclude certain events.

**Key points for Attackers & Defenders**

**For Attackers:**

* **ADS** is outdated but still works in some environments.
* **Steganography** is effective for data exfiltration.
* **Log manipulation** requires subtlety—corruption is better than deletion.

**For Defenders:**

* **Monitor ADS usage** with forensic tools.
* **Enable deep log auditing** and store logs in a secure, separate location.
* **Train staff** to recognize steganography and unusual file behavior.

### Key takeaways

Privilege escalation relies on weak credentials, unpatched vulnerabilities, exploitation tools like Metasploit, or social engineering
