# Using Wireshark to identify non-secure network traffic

Wireshark is often used to identify non-secure network traffic, for both defensive and offensive security purposes. Here is a breakdown of how this information could be used in each context:

#### 1. Defensive Security (Blue Team / Security Analysts)

If non-secure traffic is detected, defenders can use this information to:

* **Identify Vulnerabilities**: Discover weak protocols (e.g., HTTP, FTP, Telnet) that expose sensitive data.
* **Enforce Encryption**: Replace unencrypted protocols (HTTP → HTTPS, FTP → SFTP/FTPS, Telnet → SSH).
* **Detect Misconfigurations**: Find services accidentally running without TLS/SSL.
* **Monitor for Data Leaks**: Check for credentials, PII, or confidential data transmitted in plaintext.
* **Improve Security Policies**: Enforce stricter network segmentation and disable legacy insecure protocols.
* **Incident Response**: Detect unauthorized cleartext communication (e.g., malware C2 over HTTP instead of HTTPS).

**Example Defensive Actions:**

* Block cleartext protocols at the firewall.
* Implement **HSTS (HTTP Strict Transport Security)** to enforce HTTPS.
* Use **Wireshark alerts** to trigger SIEM (Security Information and Event Management) rules.

***

#### 2. Offensive Security (Red Team / Penetration Testers / Attackers)

Attackers can exploit non-secure traffic to:

* **Steal Credentials**: Sniff plaintext logins (e.g., HTTP, FTP, Telnet).
* **Conduct Man-in-the-Middle (MitM) Attacks**: Intercept unencrypted traffic.
* **Eavesdrop on Sensitive Data**: Capture unencrypted emails (SMTP), database queries, or API calls.
* **Identify Weaknesses**: Discover outdated services that can be exploited further.
* **Bypass Security Controls**: If encryption is missing, attackers may evade detection (e.g., exfiltrating data over HTTP instead of HTTPS).

**Example Offensive Exploits:**

* Using **Wireshark or tcpdump** to harvest credentials from HTTP logins.
* Performing **ARP spoofing** to redirect and capture unencrypted traffic.
* Exploiting **downgrade attacks** (e.g., forcing HTTP instead of HTTPS).

***

**Key Differences in Usage**

| **Aspect**       | **Defensive Security**                   | **Offensive Security**                     |
| ---------------- | ---------------------------------------- | ------------------------------------------ |
| **Goal**         | Identify and mitigate non-secure traffic | Exploit weaknesses, gain access            |
| **Action Taken** | Patch systems, enforce encryption        | Steal data, escalate attacks               |
| **Tools Used**   | Wireshark (monitoring), SIEM, IDS/IPS    | Wireshark (sniffing), Metasploit, Ettercap |

**Conclusion**

* **For defense**, detecting non-secure traffic is critical for improving security and preventing breaches.
* **For offense**, the same information is valuable for exploitation and to simulate attacks.

#### Steps to Identify Non-Secure Traffic with Wireshark

1. **Capture Traffic**:
   * Start Wireshark and select the appropriate network interface.
   * Begin capturing traffic by clicking the "Start" button.
2. **Apply Filters**:
   * Use display filters to narrow down traffic that is potentially non-secure. For example:
     * `http` for unencrypted HTTP traffic.
     * `tls` or `ssl` for encrypted traffic (to verify if encryption is missing).
     * `ftp` for unencrypted file transfers.
     * `telnet` for unencrypted remote login sessions.
     * `dns` for DNS queries (which can reveal sensitive information).
3. **Analyze Packet Details**:
   * Look for protocols that transmit data in plaintext (e.g., HTTP, FTP, Telnet).
   * Check for missing encryption (e.g., lack of TLS/SSL in web traffic).
   * Inspect payloads for sensitive information like usernames, passwords, or other credentials.
4. **Look for Anomalies**:
   * Unusual or unexpected traffic patterns (e.g., cleartext protocols in a secure environment).
   * Traffic to or from suspicious IP addresses or domains.
5. **Use Wireshark Features**:
   * Use the "Follow TCP Stream" feature to reconstruct and inspect the content of a session.
   * Use the "Expert Info" feature to identify warnings or errors (e.g., missing encryption).

***

**Types of Potentially Non-Secure Traffic Wireshark Can Identify**

1. **Unencrypted Protocols**:
   * **HTTP**: Transmits data in plaintext, including credentials and sensitive information.
   * **FTP**: Sends usernames, passwords, and files in cleartext.
   * **Telnet**: Transmits login credentials and commands in plaintext.
   * **SMTP/POP3/IMAP**: Email protocols that may transmit credentials and messages without encryption.
2. **Weak or Missing Encryption**:
   * Lack of TLS/SSL in web traffic (e.g., HTTPS missing).
   * Use of outdated or weak encryption algorithms (e.g., SSLv2, SSLv3, or weak ciphers).
3. **Sensitive Data Exposure**:
   * Credentials or personal information transmitted in cleartext.
   * Unencrypted database queries or API calls.
4. **Suspicious or Malicious Traffic**:
   * DNS queries revealing internal hostnames or sensitive domains.
   * Unencrypted communication with known malicious IPs or domains.
   * Unusual protocols or ports being used (e.g., cleartext traffic on non-standard ports).
5. **Misconfigured Services**:
   * Services that fall back to unencrypted communication when encryption fails.
   * Mixed content (e.g., HTTP resources loaded over an HTTPS connection).

***

**Examples of Wireshark Filters for Non-Secure Traffic**

* `http`: Captures all HTTP traffic (unencrypted).
* `ftp`: Captures all FTP traffic (unencrypted).
* `telnet`: Captures all Telnet traffic (unencrypted).
* `tls && !(tls.handshake.type == 1)`: Captures non-TLS traffic (e.g., missing encryption).
* `dns`: Captures DNS queries (can reveal sensitive information).
* `tcp.port == 80`: Captures traffic on port 80 (typically HTTP).
* `tcp.port == 23`: Captures traffic on port 23 (typically Telnet).

***

**Best Practices**

* Always use encryption (e.g., HTTPS, SFTP, SSH) for sensitive communications.
* Regularly monitor and analyze network traffic for vulnerabilities.
* Use Wireshark in conjunction with other security tools (e.g., IDS/IPS, firewalls) for comprehensive network security.
