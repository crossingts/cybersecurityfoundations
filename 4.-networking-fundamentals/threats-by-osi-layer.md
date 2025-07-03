---
description: >-
  This section discusses information security threats, cyber attacks, and
  defenses at each OSI layer
hidden: true
---

# Threats by OSI layer

## Learning objectives

• Identify and list common network attack types associated with each OSI layer\
• Understand how each attack type can compromise the network\
• Describe key mitigation methods

This section discusses network layers within the OSI model in the context of threats, vulnerabilities, and mitigation. The discussion focuses on the network attack types listed in the Common Attack Types by OSI Layer Summary Table.

## Topics covered in this section

* **Common attack types by OSI layer**
* **Common attack types and mitigation by OSI layer**
* **Explanation of threat scenarios and mitigation**
* **Key threat characteristics and mitigation strategies**

### Common attack types by OSI layer

Words

**Common Attack Types by OSI Layer Summary Table**

| **OSI Layer**         | **Function**                                                                               | **Attack Type/Threat**            |
| --------------------- | ------------------------------------------------------------------------------------------ | --------------------------------- |
| **L7 (Application)**  | Allows application processes to access network services                                    | DNS Spoofing, SQL Injection       |
| **L6 (Presentation)** | Formats data to be presented to L7                                                         | Phishing, Malicious File Uploads  |
| **L5 (Session)**      | Establishes and manages sessions between processes running on different stations           | Session Hijacking, SSL Stripping  |
| **L4 (Transport)**    | Ensures end-to-end error-free data delivery                                                | TCP SYN Flooding, UDP Flooding    |
| **L3 (Network)**      | Performs packet routing (logical addressing)                                               | ICMP Flooding, IP Spoofing        |
| **L2 (Data Link)**    | Provides node-to-node error-free data transfer (physical addressing)                       | ARP Spoofing (MITM), MAC Flooding |
| **L1 (Physical)**     | Specifies the physical characteristics of the medium used to transfer data between devices | Sniffing, Cable Tapping           |

### Common attack types and mitigation by OSI layer

Words

**Common Attack Types and Mitigation by OSI Layer Summary Table**

<table data-header-hidden><thead><tr><th width="73.265625"></th><th width="120.29296875"></th><th width="130.94921875"></th><th></th><th></th><th></th></tr></thead><tbody><tr><td><strong>OSI Layer</strong></td><td><strong>Attack Type/Threat</strong></td><td><strong>Attack Technique</strong></td><td><strong>Vulnerability Exploited</strong></td><td><strong>Risk Scenario</strong></td><td><strong>Mitigation</strong></td></tr><tr><td><strong>L7</strong></td><td>DNS Spoofing</td><td>Corrupting DNS cache to redirect users</td><td>Unvalidated DNS responses</td><td>Redirects users to malicious sites (e.g., fake banking portals)</td><td>DNSSEC, DoH/DoT (DNS over HTTPS/TLS)</td></tr><tr><td></td><td>SQL Injection</td><td>Injecting malicious SQL queries into input fields</td><td>Poor input validation, lack of parameterized queries</td><td>Bypasses authentication or exfiltrates DB data (e.g., <code>' OR 1=1 --</code> attacks)</td><td>Input validation, prepared statements, WAF (Web Application Firewall)</td></tr><tr><td><strong>L6</strong></td><td>Phishing</td><td>Social engineering to steal credentials</td><td>Human trust, lack of training</td><td>Tricks users into revealing credentials (e.g., fake login pages or malicious attachments)</td><td>User education, Email filtering (DMARC)</td></tr><tr><td></td><td>Malicious File Uploads</td><td>Uploading files with hidden exploits</td><td>Insufficient file type verification, lack of sandboxing</td><td>Uploads malware disguised as documents (e.g., PDFs with embedded exploits, Word files delivering Emotet or Locky)</td><td>File type verification, malware scanning, sandboxing</td></tr><tr><td><strong>L5</strong></td><td>Session Hijacking</td><td>Stealing valid session tokens</td><td>Weak session tokens, timeouts</td><td>Steals active sessions to impersonate users (e.g., stealing cookies via XSS or MITM)</td><td>HTTPS, Secure cookies, MFA</td></tr><tr><td></td><td>SSL Stripping</td><td>Downgrading HTTPS to HTTP via MITM</td><td>Lack of HSTS, insecure redirects</td><td>Forces HTTPS→HTTP to intercept plaintext data (e.g., evil-twin Wi-Fi attacks)</td><td>HSTS (HTTP Strict Transport Security), Certificate Pinning</td></tr><tr><td><strong>L4</strong></td><td>TCP SYN Flooding</td><td>Exploiting TCP handshake to exhaust resources</td><td>TCP handshake design flaw</td><td>Exhausts server TCP pools, causing service outages (e.g., volumetric DDoS)</td><td>SYN cookies, Firewall rules</td></tr><tr><td></td><td>UDP Flooding</td><td>Sending high-volume UDP packets to overwhelm services</td><td>Stateless nature of UDP</td><td>Exploits stateless UDP to flood services via reflection attacks (e.g., Mirai botnet’s DNS amplification attacks)</td><td>Rate limiting, DDoS protection (e.g., scrubbing centers)</td></tr><tr><td><strong>L3</strong></td><td>ICMP Flooding</td><td>Overwhelming a target with ping requests (DDoS)</td><td>No rate limiting on ICMP replies</td><td>DDoS attacks overwhelm bandwidth/resources (e.g., Smurf attacks using amplified ICMP replies)</td><td>ICMP rate limiting, Network filtering</td></tr><tr><td></td><td>IP Spoofing</td><td>Forging source IP headers to impersonate trusted hosts</td><td>Lack of IP source validation</td><td>Masquerading as trusted IPs to bypass ACLs or launch reflected attacks (e.g., NTP amplification)</td><td>BCP38 (RFC 2827), Ingress filtering</td></tr><tr><td><strong>L2</strong></td><td>ARP Spoofing (MITM)</td><td>Actively poisoning ARP tables to redirect traffic</td><td>Lack of ARP authentication</td><td>Attackers redirect or monitor traffic within a local network (e.g., stealing session cookies)</td><td>Dynamic ARP Inspection (DAI), VPNs</td></tr><tr><td></td><td>MAC Flooding</td><td>Flooding switches with fake MAC addresses</td><td>Switch CAM table limitations</td><td>Overwhelms switches to force open ports, enabling sniffing (e.g., CAM table overflow attacks)</td><td>Port security, MAC limiting</td></tr><tr><td><strong>L1</strong></td><td>Sniffing</td><td>Passive interception of unencrypted traffic</td><td>Unencrypted transmissions</td><td>Unauthorized data capture via exposed cables/Wi-Fi (e.g., stealing credentials from cleartext traffic)</td><td>Encryption (e.g., WPA3, MACsec)</td></tr><tr><td></td><td>Cable Tapping</td><td>Physically splicing or tapping network cables</td><td>Lack of physical security</td><td>Attacker physically taps fiber/copper lines to intercept data (common in espionage)</td><td>Tamper-evident seals, Fiber-optic monitoring (OTDR), Secure cabling conduits</td></tr></tbody></table>

### Explanation of threat scenarios and mitigation

**DNS Spoofing (L7)**

DNS Spoofing (or DNS Cache Poisoning) occurs when an attacker exploits vulnerabilities in the DNS system to inject fraudulent IP address mappings into a DNS server's cache. When a DNS server requests an IP address for a domain, the attacker sends a forged response before the legitimate one arrives. If the DNS server accepts the fake response, it stores the incorrect IP in its cache. Subsequent queries for that domain are answered with the poisoned entry, redirecting users to a malicious site (e.g., a phishing page) instead of the real one.

**Mitigation**&#x20;

DNS Spoofing is well-mitigated by DNSSEC (DNS Security Extensions) and encrypted DNS protocols (DNS over HTTPS/DNS over TLS). DNSSEC is a security protocol that adds digital signatures to DNS records, ensuring responses are authentic and unmodified. Prevents spoofing but does not encrypt queries. DoH encrypts DNS traffic inside HTTPS (port 443), hiding queries from snoopers. Used by browsers like Firefox. DoT encrypts DNS traffic using TLS (port 853), preventing tampering. Common in enterprise networks. DNSSEC verifies DNS data integrity (no encryption). DoH/DoT encrypts DNS traffic (privacy-focused).

**SQL Injection (L7)**

SQL Injection (SQLi) is a web security vulnerability where an attacker **injects malicious SQL queries** into an application’s input fields (like login forms, search boxes, or URLs). If the application fails to properly validate or sanitize user input, the attacker can manipulate the database, leading to:

* **Data theft** (stealing sensitive information like passwords, credit card details).
* **Data corruption or deletion** (modifying or destroying database records).
* **Authentication bypass** (logging in as an admin without credentials).
* **Remote code execution** (in extreme cases).

**Example of SQL Injection:**

**1. The Normal Login Query:**

Your login form uses this SQL query to check if a user exists:

```
SELECT * FROM users WHERE username = '$username' AND password = '$password';
```

* `$username` and `$password` are placeholders for what the user types in the login form.
*   Example: If you enter **`bob`** as the username and **`1234`** as the password, the query becomes:

    ```
    SELECT * FROM users WHERE username = 'bob' AND password = '1234';
    ```

    * The database checks: _Is there a user named "bob" with password "1234"?_
    * If yes → login succeeds. If no → fails.

**2. The Hacker’s Trick (SQL Injection):**

An attacker does not enter a normal username. Instead, they enter:

* **Username:** `admin'--`
* **Password:** (anything, e.g., `xyz`)

Now the query becomes:

```
SELECT * FROM users WHERE username = 'admin'--' AND password = 'xyz';
```

* `--` in SQL means _"ignore everything after this"_ (like a comment). Adding `'--` tricks the database to escape the password check.
*   So the database **only sees**:

    ```
    SELECT * FROM users WHERE username = 'admin';
    ```

    * It checks: _Is there a user named "admin"?_ (and ignores the password check).
    * If "admin" exists → the attacker logs in **without needing the password!**

**Mitigation**

**1. Coding Best Practices:**

* **Use Prepared Statements (Parameterized Queries):**

Instead of directly putting user input into the query, use **prepared statements** (a safer way).

**Example (in Python with SQLite):**

```
cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
```

* The `?` acts as a placeholder. The database treats inputs as **data**, not executable code.
* Even if the hacker types `admin'--`, it won’t break the query—it’ll just search for a user literally named `admin'--`.
* **Stored Procedures:**\
  Define SQL logic in the database and call it with parameters (but ensure they’re not dynamically generated inside).
* **Input Validation & Sanitization:**
  * Allow only expected characters (e.g., block SQL keywords like `'`, `--`, `UNION`).
  * Use allowlists (not blocklists).
* **Least Privilege Principle:**\
  Database accounts used by the app should have **minimal permissions** (e.g., no `DROP TABLE` access).

**2. Web Application Firewalls (WAFs):**

* A **WAF** acts as a filter between the app and users, blocking malicious requests (like SQLi patterns).
* Examples: Cloudflare WAF, AWS WAF, ModSecurity.
* **Limitation:** WAFs are a **reactive** measure and can be bypassed by sophisticated attacks. Always fix the code first!

**3. Additional Measures:**

* **ORM (Object-Relational Mapping):**\
  Tools like Django ORM or Hibernate auto-sanitize inputs.
* **Escaping User Input:**\
  If you must use dynamic SQL, escape special characters (e.g., `'` → `\'`).
* **Regular Security Testing:**\
  Use tools like **SQLMap**, Burp Suite, or manual penetration testing.

***

**Phishing (L6)**

Phishing is a cyberattack where attackers **impersonate trusted entities** (e.g., banks, companies, colleagues) to trick victims into:

* **Revealing credentials** (via fake login pages).
* **Downloading malware** (through malicious attachments/links).
* **Sending sensitive data** (e.g., "urgent" payment requests).

**Example Attack Flow:**

1. Victim receives a **fake "Password Reset" email** from "Microsoft Support."
2. Email contains a link to a **lookalike login page** (e.g., `microsoft-security.com`).
3. Victim enters credentials → Hacker steals them.

**Mitigation**

**1. User Education (Most Critical Defense)**

* Train users to:
  * **Check sender addresses** (e.g., `support@micr0soft.com` ≠ legit).
  * **Hover over links** before clicking (reveals real URL).
  * **Verify unusual requests** (e.g., call the sender if asked for money/data).
* Conduct **simulated phishing tests** to reinforce awareness.

**2. Email Filtering:** DMARC (Domain-based Message Authentication, Reporting & Conformance), DKIM (DomainKeys Identified Mail), SPF (Sender Policy Framework)

* **DKIM/SPF** ensure emails are not forged in transit. SPF establishes a list of approved email servers in DNS (e.g., "Only emails from mail.yourcompany.com are legit"). If a scammer sends from evil-server.com pretending to be you@yourcompany.com, SPF fails and the email gets flagged/rejected. DKIM adds a digital signature to outgoing emails using a private key. Receivers check your public DNS record to verify the signature. If altered in transit (e.g., by a hacker), DKIM fails and the email is marked as tampered.
* **DMARC** prevents email spoofing by verifying sender domains. It decides course of action if SPF/DKIM fail (e.g., "Reject all fakes") and provides reports on phishing attempts.

**3. Technical Controls**

* **Multi-Factor Authentication (MFA):** Even if credentials are stolen, MFA blocks access.
* **Browser Warnings:** Flags known phishing sites.
* **Attachment Sandboxing:** Scans email attachments in isolation before delivery.

**Malicious File Uploads (L6)**



Emotet is a banking Trojan often delivered via malicious email attachments (e.g., Word or Excel files with macros). Once executed, it steals sensitive data, spreads laterally, and can drop additional malware like ransomware.&#x20;

Locky Ransomware is typically distributed through phishing emails with malicious JavaScript or Office documents. When opened, it encrypts files on the victim’s system and demands payment for decryption.



**Mitigation**

Malicious File Uploads require technical controls like scanning and sandboxing to detect hidden threats.&#x20;



***

**Layer 5 (Session Layer):**

* **SSL Stripping** exploits insecure HTTP fallbacks, making HSTS and certificate pinning critical defenses.
* **Session Hijacking** is mitigated by secure session management (e.g., short-lived tokens, MFA).

***

**Layer 4 (Transport Layer):**

* **TCP SYN Flooding** abuses the three-way handshake—SYN cookies help mitigate resource exhaustion.
* **UDP Flooding** leverages UDP’s statelessness—rate limiting and traffic scrubbing are key defenses.

***

**Layer 3 (Network Layer):**

* **IP Spoofing** is a foundational attack for many DDoS techniques (e.g., SYN floods with spoofed IPs, NTP/DNS amplification). BCP38 (RFC 2827) is a critical mitigation.
* **ICMP Flooding** can be amplified (Smurf attacks)—network filtering and rate limiting are essential.

***

**Layer 2 (Data Link Layer):**

* **ARP Spoofing** enables MITM attacks—DAI (Dynamic ARP Inspection) and encrypted traffic (VPNs) are key defenses.
* **MAC Flooding** exploits switch CAM tables—port security (e.g., limiting MACs per port) prevents overflow.

***

**Layer 1 (Physical Layer):**

* **Sniffing** exploits unencrypted transmissions—modern encryption (WPA3, MACsec) is critical for mitigation. Use end-to-end encryption (e.g., HTTPS, VPNs) even if Layer 1 is compromised.
* **Cable Tapping** is a high-skill, high-reward attack (e.g., state-sponsored espionage). Physical safeguards like tamper-proof infrastructure and optical monitoring (OTDR) are essential. Employ optical time-domain reflectometers (OTDR) to detect fiber breaches, and restrict physical access to network junctions.

### Key threat characteristics and mitigation strategies

#### Key threat characteristics

1. **L1–L4 Threats**: Focus on **infrastructure disruption** (DDoS, MITM) and **data interception**.
   * _Example_: ICMP flooding threatens uptime (L3), while ARP spoofing threatens confidentiality (L2).
2. **L5–L7 Threats**: Target **sessions, users, and apps** (social engineering, logic flaws).
   * _Example_: Phishing (L6) exploits human trust, while SQLi (L7) exploits code flaws.

#### Mitigation strategies

* **Lower layers (L1–L4)**: Encryption, network hardening (e.g., firewall rules).
* **Upper layers (L5–L7)**: Behavioral controls (e.g., MFA, training).

**Mitigation Mapping**

| **Threat Category**        | **Mitigation Strategies**                              |
| -------------------------- | ------------------------------------------------------ |
| **App Logic (L7)**         | Input validation, WAFs, DNSSEC.                        |
| **Phishing (L6)**          | User training, DMARC/SPF/DKIM, email filters.          |
| **Session Hijacking (L5)** | MFA, short-lived tokens, HSTS.                         |
| **DDoS (L3/L4)**           | Rate limiting, BCP38 filtering, cloud-based scrubbing. |
| **Eavesdropping (L1/L2)**  | Encryption (WPA3, MACsec), physical access controls.   |

### Key takeaways

• Point 1\
• Point 2
