# Gaining access (attacking a system)

### Introduction

The magic part of a penetration test is exploiting a vulnerability discovered during the vulnerability assessment phase (Harper et al., 2011; Walker, 2017). A penetration test “is when ethical hackers do their magic. They can test many of the vulnerabilities identified during the vulnerability assessment to quantify the actual threat and risk posed by the vulnerability” (Harper el al., 2011, p. 11).

Next, we start talking about actual system hacking. In the enumeration phase, we successfully obtained user account information. Now what?  We’ll go over some of the basics on escalating your current privilege level. If the user account is not an administrator or doesn’t have access to interesting shares, escalating access privileges is necessary. After all, the point of hacking is gaining access to data or services. We'll go over four primary methods to gain administrator (or root) privileges on a system and best practices to maintain access and remain undetected after a successful penetration of a target system.

### Password Attacks

Most people will make their passwords the exact length of the minimum required. "If the network administrator sets the minimum at eight characters, over 95 percent of the passwords will be only eight characters—very helpful to the password-cracking attacker" (Walker, 2012, p. 157). Password attacks are often considered the first line of exploitation.

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

**Keyloggers and Screen Capture**

Keyloggers and screen capture tools are two common methods attackers use to steal sensitive information from target systems.

**Keyloggers**

Keyloggers record every keystroke typed—including passwords, messages, and other confidential data. They come in two forms:

* **Hardware Keyloggers:**
  * Physical devices plugged between the keyboard and computer.
  * Nearly undetectable without manual inspection.
* **Software Keyloggers:**
  * Malicious programs running silently in the background.
  * Easier to detect with antivirus and anti-malware tools.

**Screen Capture Tools**

Screen capture malware takes periodic or real-time screenshots of a victim’s desktop, allowing attackers to:

* Steal login credentials entered via on-screen keyboards.
* Capture sensitive documents, emails, or application data.
* Monitor user activity for further exploitation. Some advanced variants even record screen activity as video.

**How to Detect & Remove Them**

**1. Software Keyloggers & Screen Capture Malware (Detectable with Tools)**

* **Scan with Anti-Malware Tools:**
  * **Malwarebytes (Free)** – Detects spyware, keyloggers, and screen capture malware.
  * **Spybot Search & Destroy (Free)** – Specializes in spyware removal.
  * **ClamAV (Open-source)** – Lightweight cross-platform scanner.
* **Check Running Processes:**
  * **Process Explorer (Microsoft)** – Monitors suspicious background apps.
  * **RKill** – Terminates malware processes before scanning.
* **Network Monitoring:**
  * **Wireshark (Open-source)** – Detects unusual outbound traffic (e.g., keystrokes or screenshots being exfiltrated).

**2. Hardware Keyloggers (Manual Detection Only)**

* **Inspect USB/PS2 Connections:** Physically check for unexpected devices between the keyboard and PC.
* **Use a Virtual Keyboard:** Bypasses hardware keyloggers (Windows includes an On-Screen Keyboard).

**Prevention Tips**

* **Use Two-Factor Authentication (2FA):** Renders stolen keystrokes or screenshots less useful.
* **Encrypt Keystrokes:** Tools like **KeyScrambler (Free)** encrypt typing in real time.
* **Disable Unnecessary Screen Recording Permissions:** Restrict apps from capturing the screen without consent.
* **Regular Scans:** Schedule weekly checks with **Malwarebytes** or **ClamAV**.

**Note:** While software-based threats can be removed with scans, hardware keyloggers require physical inspection—always check your ports! For screen capture malware, staying vigilant about unusual processes and network traffic is key.

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

Gaining administrator (or root) privileges is a critical step in penetration testing. Attackers typically rely on four main methods to achieve privilege escalation, each with its own advantages and challenges. A skilled ethical hacker will use a combination of these methods, adapting based on the target’s defenses.&#x20;

**1. Cracking the Password of a Privileged Account**

This is often the most straightforward method—if you can obtain or guess the password of an administrator or root account, you gain immediate access without needing further exploits.

* **Approaches to Password Cracking:**
  * **Brute-force attacks:** Systematically trying every possible password combination.
  * **Dictionary attacks:** Using wordlists of common passwords.
  * **Rainbow tables:** Precomputed hash tables for reversing cryptographic hashes.
  * **Credential harvesting:** Extracting passwords from memory, keyloggers, or phishing.
* **Limitations:**
  * Strong password policies (complexity, lockouts) can make cracking difficult.
  * Modern systems often store passwords securely (e.g., salted hashes).

If successful, this method bypasses the need for further exploitation, making it highly efficient.

**2. Exploiting OS or Application Vulnerabilities**

When password attacks fail, the next best option is exploiting security flaws in the operating system or installed software.

* **How It Works:**
  * Attackers identify unpatched vulnerabilities (e.g., buffer overflows, privilege escalation bugs).
  * They craft or use existing exploits to execute arbitrary code with elevated privileges.
* **Key Considerations:**
  * **Vulnerability research is critical:** Websites like CVE Details, Exploit-DB, and vendor bulletins help identify known flaws.
  * **Automated scanners (e.g., Nessus, OpenVAS)** can detect missing patches.
  * **Zero-day exploits** (unknown vulnerabilities) are highly valuable but rare.
* **Example Scenario:**
  * If a Windows server hasn’t been patched for a known Local Privilege Escalation (LPE) flaw, an attacker can exploit it to gain SYSTEM-level access.

This method requires staying updated on security advisories and understanding how vulnerabilities translate into real-world attacks.

**3. Using Exploitation Frameworks (e.g., Metasploit)**

Tools like **Metasploit** automate and simplify the exploitation process, making them indispensable for penetration testers.

* **How Metasploit Works:**
  * **Step 1:** Select a target (IP, port, service).
  * **Step 2:** Choose an exploit (e.g., a known vulnerability in an application).
  * **Step 3:** Configure a payload (e.g., a reverse shell for remote access).
  * **Step 4:** Execute the attack—Metasploit handles the exploitation process.
* **Metasploit Versions:**
  * **Free (Community Edition):** Fully functional for most exploits.
  * **Metasploit Pro:** Adds advanced features like automated phishing, web app testing, and team collaboration.
  * Extensive resources (forums, blogs, guides) are available on [metasploit.com](http://www.metasploit.com/).
* **Armitage (GUI for Metasploit):**
  * Provides a visual interface, making exploitation more intuitive.
  * Useful for beginners or those who prefer graphical workflows.
  * More info at [fastandeasyhacking.com](http://fastandeasyhacking.com/).
* **Why Metasploit Dominates:**
  * It integrates reconnaissance, exploitation, and post-exploitation tools in one platform.
  * Its extensive module library covers thousands of known vulnerabilities.

While powerful, Metasploit requires skill to use effectively—misconfigurations can lead to failed exploits or detection.

**4. Social Engineering (The Human Factor)**

The easiest and often most effective method is bypassing technical defenses entirely by manipulating users.

* **Common Tactics:**
  * **Phishing Emails:** Sending malicious attachments (e.g., a disguised PDF or Word doc with embedded malware).
  * **Fake Updates:** Tricking users into installing "security patches" that are actually malware.
  * **USB Drops:** Leaving infected USB drives in public places, hoping someone plugs them in.
* **Why It Works:**
  * Users are often the weakest link—many will click links or open files without suspicion.
  * Even well-secured systems can be compromised if an admin is tricked into running malware.
* **Real-World Example:**
  * A hacker sends a fake "invoice" PDF that exploits an unpatched Adobe Reader flaw, granting them elevated access when opened.

Social engineering requires minimal technical skill but relies heavily on psychological manipulation.

**Note:**

Each privilege escalation method has its strengths:

* **Password attacks** are direct but depend on weak credentials.
* **Vulnerability exploits** are powerful but require up-to-date knowledge.
* **Metasploit** automates exploitation but has a learning curve.
* **Social engineering** is the easiest but relies on human error.

#### **Stealth: Before, During, and After**

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

**Rootkits**

A rootkit is a type of malicious software (_malware_) designed to hide an attacker’s presence on a compromised system. Unlike simpler viruses or trojans, rootkits actively conceal their activities—making them extremely dangerous for long-term infiltration.

**How Rootkits Work:**

* **Stealth Mechanisms:**
  * Modify system files, processes, and logs to evade detection.
  * Hide running malware, network connections, and unauthorized user accounts.
* **Persistence & Backdoors:**
  * Maintain long-term access by embedding deep in the OS (kernel-level rootkits) or firmware.
  * Provide remote attackers with covert entry points for future exploitation.
* **Anti-Forensics:**
  * Actively erase traces of malicious activity (e.g., deleting logs or disguising file changes).

**Why Rootkits Are More Than Just Cloaking:**

While their primary function is _obscuring compromise_, rootkits are inherently malicious:

1. **They are malware**—often bundled with payloads like keyloggers, ransomware, or botnet agents.
2. **They enable further attacks** by ensuring undetected access.
3. **They exploit system vulnerabilities** to gain privileged access (e.g., ring-0/kernel mode).

**Detection Challenges:**

* Traditional antivirus tools often fail because rootkits manipulate the OS itself.
* Specialized tools such as GMER, RootkitRevealer, chkrootkit, and Rootkit Hunter or offline scans are needed.

There are three main types of rootkits (Walker, 2012, p. 175):

• Application level: As the name implies, these rootkits are directed to replace valid application files with Trojan binaries. These kits work inside an application and can use an assortment of means to change the application’s behavior, user rights level, and actions.

• Kernel level: These rootkits attack the boot sectors and kernel level of the operating systems themselves, replacing kernel code with backdoor code. These are by far the most dangerous and are difficult to detect and remove.

• Library level: These rootkits basically make use of system-level calls to hide their existence.&#x20;

#### **The Evolution of Linux Rootkits**

Rootkits first emerged in the Linux environment, primarily taking two distinct forms:

1. **Binary Replacement Rootkits (Early Generation)**
   * **How They Worked:**\
     These rootkits replaced critical system binaries (e.g., `ls`, `ps`, `netstat`) with malicious versions designed to hide attacker activity.
   * **Detection Weakness:**\
     The modified binaries often had file size discrepancies, making them detectable by integrity-checking tools like **Tripwire**.
2. **Kernel-Level Rootkits (More Advanced)**
   * **Evolution:**\
     Attackers shifted to **Loadable Kernel Modules (LKMs)**, embedding rootkits directly into the kernel.
   * **Stealth Advantages:**
     * Operated at the highest privilege level (ring 0), making them far harder to detect.
     * Could manipulate system calls and data structures in real time.
   * **Early Examples:**\
     Notable Linux rootkits included **Adore**, **Flea**, and **T0rn**, which demonstrated the growing sophistication of kernel-mode attacks.

This progression from user-space binary replacement to kernel-level integration marked a critical shift in rootkit stealth and persistence—a trend that later influenced rootkit development across all operating systems.

Rootkits are exponentially more complicated than your typical malware application and reflect significant sophistication. If your company detects a customized rootkit and thinks they were targeted, it’s time to get the FBI involved. And to truly scare the wits out of you, check out what a truly sophisticated rootkit can do: http://en.wikipedia.org/wiki/Blue\_ Pill\_(malware). (Walker, 2012, p. 177)

### Key takeaways

Privilege escalation relies on weak credentials, unpatched vulnerabilities, exploitation tools like Metasploit, or social engineering
