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

• Offline attack: This happens when an attacker steals a password database (like Windows' **SAM file** or a Linux **/etc/shadow**) and cracks it offline on their own system using such tools as Hashcat or John the Ripper—without interacting with the target. When an attacker **"cracks"** a stolen password file, they use computational methods to convert the scrambled (hashed) passwords back into plaintext.&#x20;

There are three main methods of offline password cracking: dictionary attack, hybrid attack, and brute-force attack.&#x20;

A dictionary attack is the easiest and by far the fastest attack available. This attack uses a list of passwords in a text file, which is then hashed by the same algorithm/process the original password was put through. The hashes are compared and, if a match is found, the password is cracked. Technically speaking, dictionary attacks are only supposed to work on words you’d find in a dictionary. They can work just as well on “complex” passwords too; however, the word list you use must have the exact match in it—you can’t get close, it must be exact. You can create your own dictionary file or simply download any of the thousands available on the Internet. (Walker, 2012, p. 164)

A hybrid attack is a step above the dictionary attack. In the hybrid attack, the cracking tool is smart enough to take words from a list and substitute numbers and symbols for alpha characters—perhaps a zero for an O, an @ for an a. Hybrid attacks may also append numbers and symbols to the end of dictionary file passwords—bet you’ve never simply added a “1234” to the end of a password before, huh? By doing so, you stand a better chance of cracking passwords in a complex environment.\
(Walker, 2012, p. 164)
