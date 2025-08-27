---
description: >-
  This section discusses information security threats, cyber attacks, and
  defenses at each OSI layer
---

# OSI model layers and security threats

## Learning objectives

• Identify and list common network attack types associated with each OSI layer\
• Understand how each attack type can compromise the network\
• Describe key mitigation methods for each attack type

This section discusses network layers within the OSI model in the context of threats, vulnerabilities, and mitigation. The discussion focuses on the following network attack types: DNS Spoofing (L7), SQL Injection (L7), Phishing (L6), Malicious File Uploads (L6), Session Hijacking (L5), SSL Stripping (L5), TCP SYN Flooding (L4), UDP Flooding (L4), ICMP Flooding (L3), IP Spoofing (L3), ARP Spoofing (L2), MAC Flooding (L2), Sniffing (L1), and Cable Tapping (L1).

## Topics covered in this section

* **Common attack types by OSI layer**
* **Common attack types and mitigation by OSI layer**
* **Explanation of threat scenarios and mitigation**
* **Key threat characteristics and mitigation strategies**

### Common attack types by OSI layer

The following tables lists common attack types/threats associated with each OSI model layer.

**Common Attack Types by OSI Layer Summary Table**

| **OSI Layer**         | **Function**                                                                               | **Attack Type/Threat**            |
| --------------------- | ------------------------------------------------------------------------------------------ | --------------------------------- |
| **L7 (Application)**  | Allows application processes to access network services                                    | DNS Spoofing, SQL Injection       |
| **L6 (Presentation)** | Formats data to be presented to L7                                                         | Phishing, Malicious File Uploads  |
| **L5 (Session)**      | Establishes and manages sessions between processes running on different stations           | SSL Stripping, Session Hijacking  |
| **L4 (Transport)**    | Ensures end-to-end error-free data delivery                                                | TCP SYN Flooding, UDP Flooding    |
| **L3 (Network)**      | Performs packet routing (logical addressing)                                               | ICMP Flooding, IP Spoofing        |
| **L2 (Data Link)**    | Provides node-to-node error-free data transfer (physical addressing)                       | ARP Spoofing (MITM), MAC Flooding |
| **L1 (Physical)**     | Specifies the physical characteristics of the medium used to transfer data between devices | Sniffing, Cable Tapping           |

### Common attack types and mitigation by OSI layer

The following tables lists and elaborates risk scenarios and mitigation techniques for each OSI model attack/threat type.

**Common Attack Types and Mitigation by OSI Layer Summary Table**

<table data-header-hidden><thead><tr><th width="73.265625"></th><th width="120.29296875"></th><th width="130.94921875"></th><th></th><th></th><th></th></tr></thead><tbody><tr><td><strong>OSI Layer</strong></td><td><strong>Attack Type/Threat</strong></td><td><strong>Attack Technique</strong></td><td><strong>Vulnerability Exploited</strong></td><td><strong>Risk Scenario</strong></td><td><strong>Mitigation</strong></td></tr><tr><td><strong>L7</strong></td><td>DNS Spoofing</td><td>Corrupting DNS cache to redirect users</td><td>Unvalidated DNS responses</td><td>Redirects users to malicious sites (e.g., fake banking portals)</td><td>DNSSEC, DoH/DoT (DNS over HTTPS/TLS)</td></tr><tr><td></td><td>SQL Injection</td><td>Injecting malicious SQL queries into input fields</td><td>Poor input validation, lack of parameterized queries</td><td>Bypasses authentication or exfiltrates DB data (e.g., <code>' OR 1=1 --</code> attacks)</td><td>Input validation, prepared statements, WAF (Web Application Firewall)</td></tr><tr><td><strong>L6</strong></td><td>Phishing</td><td>Social engineering to steal credentials</td><td>Human trust, lack of training</td><td>Tricks users into revealing credentials (e.g., fake login pages or malicious attachments)</td><td>User education, Email filtering (DMARC)</td></tr><tr><td></td><td>Malicious File Uploads</td><td>Uploading files with hidden exploits</td><td>Insufficient file type verification, lack of sandboxing</td><td>Uploads malware disguised as documents (e.g., PDFs with embedded exploits, Word files delivering Emotet or Locky)</td><td>File type verification, malware scanning, sandboxing</td></tr><tr><td><strong>L5</strong></td><td>SSL Stripping</td><td>Downgrading HTTPS to HTTP via MITM</td><td>Lack of HSTS, insecure redirects</td><td>Forces HTTPS→HTTP to intercept plaintext data (e.g., evil-twin Wi-Fi attacks)</td><td>HSTS, HTTPS Redirection &#x26; Secure Cookies, Certificate Pinning</td></tr><tr><td></td><td>Session Hijacking</td><td>Stealing valid session tokens</td><td>Weak session tokens, timeouts</td><td>Steals active sessions to impersonate users (e.g., stealing cookies via XSS or MITM)</td><td>Secure Session Management, Secure Cookie Attributes, MFA</td></tr><tr><td><strong>L4</strong></td><td>TCP SYN Flooding</td><td>Exploiting TCP handshake to exhaust resources</td><td>TCP handshake design flaw</td><td>Exhausts server TCP pools, causing service outages (e.g., volumetric DDoS)</td><td>Rate limiting, SYN cookies, Infrastructure Solutions (e.g., firewalls and load balancers)</td></tr><tr><td></td><td>UDP Flooding</td><td>Sending high-volume UDP packets to overwhelm services</td><td>Stateless nature of UDP</td><td>Exploits stateless UDP to flood services via reflection attacks (e.g., Mirai botnet’s DNS amplification attacks)</td><td>Rate limiting, DDoS protection (e.g., scrubbing centers)</td></tr><tr><td><strong>L3</strong></td><td>ICMP Flooding</td><td>Overwhelming a target with ping requests (DDoS)</td><td>No rate limiting on ICMP replies</td><td>DDoS attacks overwhelm bandwidth/resources (e.g., Smurf attacks using amplified ICMP replies)</td><td>ICMP rate limiting, Network filtering</td></tr><tr><td></td><td>IP Spoofing</td><td>Forging source IP headers to impersonate trusted hosts</td><td>Lack of IP source validation</td><td>Masquerading as trusted IPs to bypass ACLs or launch reflected attacks (e.g., NTP amplification)</td><td>BCP38 (RFC 2827), Ingress filtering</td></tr><tr><td><strong>L2</strong></td><td>ARP Spoofing (MITM)</td><td>Actively poisoning ARP tables to redirect traffic</td><td>Lack of ARP authentication</td><td>Attackers redirect or monitor traffic within a local network (e.g., stealing session cookies)</td><td>Dynamic ARP Inspection (DAI), VPNs</td></tr><tr><td></td><td>MAC Flooding</td><td>Flooding switches with fake MAC addresses</td><td>Switch CAM table limitations</td><td>Overwhelms switches to force open ports, enabling sniffing (e.g., CAM table overflow attacks)</td><td>Port security, MAC limiting</td></tr><tr><td><strong>L1</strong></td><td>Sniffing</td><td>Passive interception of unencrypted traffic</td><td>Unencrypted transmissions</td><td>Unauthorized data capture via exposed cables/Wi-Fi (e.g., stealing credentials from cleartext traffic)</td><td>Encryption (e.g., WPA3, MACsec)</td></tr><tr><td></td><td>Cable Tapping</td><td>Physically splicing or tapping network cables</td><td>Lack of physical security</td><td>Attacker physically taps fiber/copper lines to intercept data (common in espionage)</td><td>Tamper-evident seals, Fiber-optic monitoring (OTDR), Secure cabling conduits</td></tr></tbody></table>

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

Attackers upload harmful files (e.g., documents, scripts, executables) to a system, often via phishing emails (e.g., infected Word/Excel files) or compromised web forms (e.g., fake resume uploads). The malware is hidden inside innocent-looking files (PDFs, Word docs, Excel sheets, ZIPs, etc.). When the victim opens them, the malware executes—infecting their device, stealing data, or encrypting files for ransom. Two examples of malware are Emotet and Locky Ransomware. Emotet is a banking Trojan often delivered via malicious email attachments (e.g., Word or Excel files with macros). Once executed, it steals sensitive data, spreads laterally, and can drop additional malware like ransomware. Locky Ransomware is typically distributed through phishing emails with malicious JavaScript or Office documents. When opened, it encrypts files on the victim’s system and demands payment for decryption.

**Mitigation**

**1. Technical Controls**

* **File Upload Scanning:**
  * Use **antivirus/anti-malware** tools to scan uploads for known threats.
  * **Block risky file types** (e.g., `.js`, `.exe`, `.docm`, `.hta`).
* **Sandboxing:**
  * Execute suspicious files in an **isolated environment** to detect malicious behavior before allowing access.
* **Email Filtering:**
  * Block emails with executable attachments (e.g., `.js`, `.vbs`, `.scr`).

**2. User Awareness & Policies**

* **Disable Office Macros by Default** (only allow approved, signed macros).
* **Train Users:**
  * Never enable macros in unexpected documents.
  * Avoid opening attachments from unknown senders.
* **Least Privilege:** Restrict user permissions to limit malware spread.

**3. Advanced Protections**

* **Behavioral Analysis:** Tools like **EDR (Endpoint Detection & Response)** detect unusual file activity (e.g., mass file encryption).
* **Web Application Firewalls (WAFs):** Block malicious uploads in web forms.

***

**SSL Stripping (L5)**

SSL Stripping (also known as HTTP Downgrade attacks) is a man-in-the-middle (MitM) attack that exploits the common practice of websites offering both secure (HTTPS) and insecure (HTTP) access. The attacker intercepts the initial, unencrypted connection from a user to a website and manipulates the traffic to force a persistent HTTP connection, stripping away the SSL/TLS encryption. This allows the attacker to:

* **Eavesdrop on all communication** between the user and the website, capturing sensitive data like login credentials, personal information, and session cookies.
* **Monitor and modify all data** passing through the connection in plaintext.
* **Impersonate the legitimate website** while the user believes they are browsing normally.

**Example of SSL Stripping:**

1. **The Normal, Secure Connection:**\
   A user types `http://example.com` into their browser. The server typically responds with a redirect (301/302) to `https://example.com`, ensuring all subsequent communication is encrypted and secure.
2. **The Hacker’s Trick (SSL Stripping):**\
   An attacker on the same network (e.g., public Wi-Fi) positions themselves between the user and the website.
   * The user sends a request to `http://example.com`.
   * The attacker intercepts this request and forwards it to the real server.
   * The real server responds with a redirect to `https://example.com`.
   * The attacker intercepts this redirect, prevents it from reaching the user, and instead continues to communicate with the _server_ over HTTPS.
   * The attacker then returns a stripped-down, insecure HTTP version of the site to the _user_, acting as a proxy.
   * The user's browser now displays `http://example.com` in the address bar, and all their traffic passes through the attacker in plaintext, completely unaware of the breach.

**Mitigation**

1. **HTTP Strict Transport Security (HSTS):**\
   This is a critical web server header that instructs browsers to _only_ connect to the site using HTTPS for a specified period.
   * The server sends a header: `Strict-Transport-Security: max-age=31536000; includeSubDomains`
   * Upon receiving this, a compliant browser will automatically convert any `http://` request to `https://` for the given domain before sending it, defeating the downgrade attempt.
   * The `includeSubDomains` directive extends this protection to all subdomains.
   * **Preloading:** Sites can be submitted to the HSTS preload list, a list built into all major browsers that automatically uses HTTPS for the site even on the very first visit.
2. **Server-Side HTTPS Redirection & Secure Cookies:**
   * Web servers should be configured to permanently redirect all HTTP requests to their HTTPS counterparts.
   * Session cookies must be set with the `Secure` attribute, ensuring they are only sent over HTTPS connections and never in plaintext via HTTP.
3. **Certificate Pinning:**\
   This technique hardcodes (or pins) the expected public key or certificate of a website within the application itself (common in mobile apps).
   * When the app connects to the server, it verifies that the server's certificate matches one of the pinned certificates.
   * Even if an attacker presents a valid certificate from a trusted Certificate Authority (CA) during a MitM attack, the pinning check will fail because it doesn't match the specific pinned certificate, and the connection will be terminated.

**Session Hijacking (L5)**

Session hijacking is an attack where an attacker steals a user's unique session identifier (typically a session token stored in a cookie) and uses it to impersonate the victim. By taking over the user's active session, the attacker gains unauthorized access to the web application and is effectively authenticated as the user, which can lead to:

* **Identity theft** and unauthorized access to the victim's account and privileges.
* **Theft of sensitive personal or financial data** stored in the user's account.
* **Fraudulent actions** performed on the user's behalf (e.g., transferring funds, making purchases).

**Example of Session Hijacking:**

1. **The Normal Session:**\
   After a user successfully logs into `bank.com`, the server generates a unique session token (e.g., `SESSID=abc123`) and sends it to the user's browser in a cookie. The browser automatically includes this cookie with every subsequent request to `bank.com` to prove its authenticated identity.
2. **The Hacker’s Trick (Session Hijacking):**\
   An attacker can steal the `SESSID` token through various means:
   * **Network Eavesdropping:** If any part of the communication uses HTTP (not HTTPS), the token is sent in plaintext and can be sniffed from the network.
   * **Cross-Site Scripting (XSS):** The attacker injects malicious JavaScript into a web page. When the victim views the page, the script executes in their browser and steals their session cookie.
   * **Predictable Tokens:** If the application uses weak, predictable algorithms to generate session tokens, an attacker can guess a valid token. Once the attacker has the token `abc123`, they simply place it into their own browser's cookie for `bank.com`. The server cannot distinguish between the attacker's request and the victim's legitimate request, granting the attacker full access to the victim's account.

**Mitigation**

1. **Secure Session Management:**
   * **Use Long, Random, Unpredictable Session Tokens:** Tokens should be generated using a cryptographically secure random number generator.
   * **Implement Short Session Timeouts:** Automatically invalidate sessions after a short period of user inactivity. This limits the window of opportunity for an attacker to use a stolen token.
   * **Provide Logout Functionality:** Logout should immediately invalidate the session token on the server.
   * **Regenerate Session Tokens:** The application should invalidate the old session ID and issue a new one after login and any other major privilege change (e.g., password change, role elevation). This prevents session fixation attacks.
2.  **Secure Cookie Attributes:**

    * `Secure`: Ensures the session cookie is only sent over encrypted HTTPS connections.
    * `HttpOnly`: Prevents the cookie from being accessed by client-side JavaScript, mitigating theft via XSS attacks.
    * `SameSite=Strict` (or `Lax`): Controls when cookies are sent with cross-site requests, protecting against Cross-Site Request Forgery (CSRF) and some session hijacking techniques.

    A detailed explanation of the mechanism of action for each of these secure cookie attributes in mitigating session hijacking: [Secure cookie attributes explained](secure-cookie-attributes-explained.md).


3. **Multi-Factor Authentication (MFA):**\
   MFA adds a second layer of defense. Even if a session token is stolen, the attacker would still need to bypass the second factor (e.g., a code from a phone app) to access sensitive functionality or re-authenticate, rendering the stolen token largely useless.

***

**TCP SYN Flood (L4)**

A TCP SYN Flood is a type of Denial-of-Service (DoS) attack that exploits the fundamental connection-establishment process of the TCP protocol (the three-way handshake). The attacker sends a rapid succession of SYN packets with spoofed source IP addresses, consuming all available resources on the target server. This renders the server unable to accept legitimate connection requests, leading to a denial of service.

**Example of a TCP SYN Flood:**

1. **The Normal Three-Way Handshake:**
   * **Step 1 (SYN):** A legitimate client sends a `SYN` (synchronize) packet to a server to initiate a connection.
   * **Step 2 (SYN-ACK):** The server receives the `SYN`, allocates memory for the new connection (in a "half-open" state), and responds with a `SYN-ACK` (synchronize-acknowledge) packet.
   * **Step 3 (ACK):** The client responds with an `ACK` (acknowledge) packet. The connection is now fully established, and data transfer can begin.
2. **The Hacker’s Trick (SYN Flood):**\
   The attacker targets the second step of this process.
   * The attacker sends a high volume of `SYN` packets to the target server.
   * Crucially, the source IP address of each packet is **spoofed** (faked) to an address that does not exist or is unreachable.
   * The target server, following protocol, receives each `SYN` packet, allocates kernel memory for the new connection, and sends a `SYN-ACK` response back to the spoofed IP address.
   * The server then waits for the final `ACK` packet that will never arrive. Each of these "half-open" connections occupies space in a finite-sized connection queue.
   * Once this queue is full, the server cannot accept any new legitimate `SYN` requests, causing a denial of service for real users.

**Mitigation**

1. **Rate Limiting:** Network devices like routers, firewalls, and intrusion prevention systems (IPS) can be configured to monitor the rate of incoming SYN packets. If the number of SYN packets from a single source IP (or to a single destination port) exceeds a predefined threshold within a specific window, subsequent packets from that source can be dropped or challenged. This helps to mitigate the flood from a specific origin while allowing legitimate traffic from other sources to continue.
2. **SYN Cookies:**\
   This is a highly effective technical mitigation implemented on the server. SYN cookies help mitigate resource exhaustion.
   * Instead of immediately allocating memory upon receiving a `SYN`, the server encodes the connection details into a cryptographically hashed sequence number (the "cookie") and sends it back in the `SYN-ACK` response.
   * The server does **not** allocate any memory at this point, preserving its resources.
   * Memory is only allocated for the connection if a legitimate `ACK` packet is returned from the client, containing the correct sequence number + 1 (proving it received the `SYN-ACK`).
   * This technique completely defeats SYN Floods by ensuring resources are only committed to legitimate, completed handshakes. It is enabled by default on most modern operating systems.
3. **Network Infrastructure Solutions:**
   * **Upstream Filtering (BCP38):** Internet Service Providers (ISPs) can implement source address validation on the edge of their networks to prevent packets with spoofed source IPs from entering the internet, stopping attacks at their source.
   * **Firewalls and Load Balancers:** Modern network devices can be configured to act as a proxy for TCP connections. They can complete the handshake with the client first and only open a connection to the backend server once it's fully established, shielding the server from the flood.
   * **Intrusion Prevention Systems (IPS):** An IPS can be configured with rate-based signatures to detect and automatically block source IPs generating excessive SYN packets. This provides a reactive layer of defense that can throttle an attack, but it risks state table exhaustion and is less efficient than proxy-based solutions.
   * **DDoS Mitigation Services:** Cloud-based services (e.g., Cloudflare, AWS Shield, Akamai) have massive, distributed networks designed to absorb and filter out volumetric attacks like SYN Floods before they ever reach the target's origin server.
4. **Operating System Hardening:**
   * **Increase SYN Queue Size:** Modern operating systems allow administrators to increase the maximum size of the half-open connection queue, allowing the server to handle a larger flood before failing.
   * **Decrease SYN-RECEIVED Timer:** Reducing the time the server waits for the final `ACK` packet before dropping the half-open connection allows resources to be freed up more quickly.

**UDP Flood (L4)**

A UDP Flood is a volumetric Denial-of-Service (DoS) attack that targets a host by overwhelming its network with User Datagram Protocol (UDP) packets. Unlike TCP, UDP is connectionless; a host receiving a UDP packet does not need to perform a handshake or maintain any connection state. The attack's goal is simply to saturate the target's available network bandwidth, consuming all resources and making it unreachable.

**Example of a UDP Flood:**

1. **The Normal UDP Communication:**\
   A legitimate client, like a DNS resolver, sends a single UDP request packet (e.g., a DNS query) to a server. The server processes the request and sends back a single UDP response packet (e.g., a DNS answer). This is a stateless, efficient exchange.
2. **The Hacker’s Trick (UDP Flood):**\
   In UDP Flooding, the attacker exploits the stateless and unchecked nature of UDP
   * The attacker sends a massive number of large UDP packets to random ports on the target server.
   * Since the packets are sent to closed ports, the target server, per protocol, must check which application is listening on that port.
   * Finding no application, the server generates an ICMP "Destination Unreachable (Port Unreachable)" packet back to the source IP for each request.
   * If the source IP is **spoofed**, these response packets are sent to an innocent, spoofed host (which may itself become a victim of reflected traffic).
   * The primary damage is done by the sheer volume of incoming packets, which consumes the target's entire network bandwidth, CPU cycles for packet processing, and ability to send/receive legitimate traffic.

**Mitigation**

1. **Rate Limiting:**\
   Network routers, firewalls, and intrusion prevention systems (IPS) can be configured to limit the number of UDP packets allowed to pass through to a host within a specific time window. This prevents a single source (or a range of sources) from consuming all available bandwidth.
2. **Filtering and Blackholing:**
   * **BCP38 (Anti-Spoofing):** As with SYN floods, preventing spoofed packets at the network edge is a fundamental defense.
   * **Blackhole Filtering:** During a massive attack, a network administrator can instruct their upstream provider to "blackhole" traffic destined for the target's IP. This drops all traffic at the provider's edge, saving the target's bandwidth but making them unreachable—a last-resort tactic to avoid complete network failure.
3. **DDoS Mitigation Appliances & Services:**
   * **On-Premise Appliances:** These can be deployed in front of key servers to analyze traffic patterns and automatically drop malicious UDP flood traffic in real-time.
   * **Cloud-Based Scrubbing Centers:** This is the most robust defense for large-scale attacks. All traffic is routed through a cloud provider's global network. Their systems analyze the traffic, "scrub" out the malicious UDP flood packets, and forward only the legitimate traffic to the origin server. This is essential for absorbing the multi-gigabit attacks common today.
4. **Disabling Unused UDP Services:**\
   Reducing the attack surface by disabling any unused UDP-based services on a host minimizes the number of ports that can be targeted and eliminates the generation of ICMP error messages for those ports.

***

**ICMP Flood (L3)**

An ICMP Flood is a volumetric Denial-of-Service (DoS) attack that aims to overwhelm a target network's bandwidth by saturating it with a high volume of Internet Control Message Protocol (ICMP) packets. The most common variant is a "ping flood," which uses ICMP Echo Request (Type 8) packets. The goal is not to exploit a vulnerability but to consume all available incoming and outgoing bandwidth, as well as host resources, to render the target unreachable.

**Example of an ICMP Flood:**

1. **The Normal ICMP (Ping) Use:**\
   A network administrator sends a single ICMP Echo Request packet to a host (e.g., `ping 192.168.1.1`). The target host, if available and configured to respond, sends back a single ICMP Echo Reply (Type 0) packet. This is used for basic network diagnostics and connectivity testing.
2. **The Hacker’s Trick (ICMP Flood):**\
   The attacker subverts this diagnostic tool into a weapon.
   * Using a powerful machine or a botnet (a network of compromised devices), the attacker generates a massive, continuous stream of ICMP Echo Request packets directed at the target's IP address.
   * This flood can be massively amplified in a "Smurf attack," where the attacker sends ICMP requests to a network broadcast address with a spoofed source IP of the victim. Every device on that network then replies to the victim, multiplying the attack traffic.
   * The size of the packets may also be maximized to consume more bandwidth per packet.
   * The target host is obligated to process each incoming packet and generate a corresponding ICMP Echo Reply for each one.
   * The combined volume of the incoming requests and outgoing replies quickly saturates the target's network link. Legitimate traffic is unable to compete for bandwidth, resulting in a denial of service for real users and services.

**Mitigation**

1. **ICMP Rate Limiting:**\
   The primary defense against ICMP floods is to rate limit ICMP traffic at the network perimeter. This can be configured on routers, firewalls, or dedicated mitigation appliances.
   * **How it works:** The administrator sets a threshold for the number of ICMP packets per second that will be accepted from a single source IP or destined for a single target IP within the network.
   * **Result:** Once this threshold is exceeded, any additional ICMP packets are dropped for a cool-down period. This prevents the flood from consuming internal bandwidth while still allowing legitimate, low-volume pings (e.g., for monitoring) to function.
2. **Network Filtering:**
   * **Disabling ICMP:** On critical public-facing servers, ICMP Echo Replies can be completely disabled at the host firewall level. This prevents the host from responding to pings, making it "stealth" to external discovery tools. However, this also breaks legitimate network diagnostics.
   * **Filtering at the Edge:** More commonly, network administrators can configure edge routers or firewalls to selectively filter ICMP traffic. For example, allowing ICMP Echo Requests from trusted internal management networks but dropping them from untrusted external networks.

**IP Spoofing (L3)**

IP Spoofing is a foundational attack for many DDoS techniques (e.g., SYN floods with spoofed IPs, NTP/DNS amplification). IP Spoofing is not an attack in itself but a technique used to enable other attacks. It involves forging the source IP address in a packet's header to conceal the identity of the sender, impersonate another system, or both. By using a falsified source address, the attacker can bypass IP-based authentication, launch reflection attacks, and evade detection.&#x20;

**Example of IP Spoofing:**

1. **The Normal IP Communication:**\
   A client with IP address `192.168.1.10` sends a request to a server. The IP packet header correctly lists `192.168.1.10` as the source and the server's IP as the destination. Any replies from the server are correctly sent back to `192.168.1.10`.
2. **The Hacker’s Trick (IP Spoofing):**\
   An attacker uses a tool to manually create a raw network packet.
   * The attacker sets the **destination IP** to the address of their intended victim.
   * The attacker sets the **source IP** to the address of a different, innocent third party or a non-routable, random address.
   * This spoofed packet is sent, often as part of a larger flood (e.g., a SYN Flood or DNS Reflection attack).
   * **Consequence:** The victim receives the packet and sends any response (like a `SYN-ACK` or a DNS answer) back to the innocent spoofed source, not the attacker. This masks the attacker's true location and can make the innocent party appear to be the source of the attack.

**Mitigation**

1. **BCP38 (RFC 2827) - Ingress Filtering:**\
   This is the fundamental, network-level solution to IP spoofing, and it must be implemented by Internet Service Providers (ISPs) and network administrators at the edge of their networks.
   * **Principle:** A router should not forward any packet leaving its network if the source IP address does not belong to that network's allocated range of IP addresses.
   * **How it works:** An ISP's edge router checks the source IP of every packet coming from a customer. If a customer (ASN 65530) is assigned the IP range `192.0.2.0/24`, the router will drop any packet from that customer with a source IP _outside_ that block (e.g., `198.51.100.50`).
   * **Effect:** This prevents a customer from launching attacks with spoofed source IPs. Widespread adoption of BCP38 would stop the vast majority of spoofed attacks at their source.
2. **Egress Filtering:**\
   This is the counterpart to ingress filtering, implemented on an internal network to protect it.
   * **Principle:** A network's border firewall should be configured to block any outgoing packet whose source IP address is not from the organization's legitimate internal IP range.
   * **How it works:** This prevents malware or a compromised internal machine from launching spoofed attacks from within the network, helping the organization be a better "internet citizen" and potentially avoiding liability.

***

**ARP Spoofing (L2)**

ARP Spoofing (or ARP Poisoning) is a link-layer attack where an attacker sends forged Address Resolution Protocol (ARP) messages—more specifically, gratuitous ARP reply messages—onto a local area network (LAN). This malicious activity corrupts the ARP caches of other devices on the network, allowing the attacker to intercept, modify, or block data frames between two victims—a classic Man-in-the-Middle (MitM) attack on the local subnet.

**Example of ARP Spoofing:**

1. **The Normal ARP Process:**
   * Device A (`192.168.1.10`) wants to send data to Device B (`192.168.1.20`).
   * Device A broadcasts an ARP Request: "Who has IP `192.168.1.20`? Tell `192.168.1.10`."
   * Device B responds with a unicast ARP Reply: "I am `192.168.1.20`, my MAC address is `BB:BB:BB:BB:BB:BB`."
   * Device A stores this IP-to-MAC mapping in its ARP cache and sends frames directly to that MAC address.
2. **The Hacker’s Trick (ARP Spoofing):**\
   The attacker (`192.168.1.99`, MAC `CC:CC:CC:CC:CC:CC`) aims to intercept traffic between A and B.
   * The attacker sends a unsolicited ARP Reply (a "gratuitous ARP") to Device A, claiming: "I am `192.168.1.20`, my MAC address is `CC:CC:CC:CC:CC:CC`."
   * Simultaneously, the attacker sends a gratuitous ARP to Device B, claiming: "I am `192.168.1.10`, my MAC address is `CC:CC:CC:CC:CC:CC`."
   * Both victims update their ARP caches with these incorrect mappings. Device A now sends traffic destined for B to the attacker's MAC. The attacker can then forward the traffic to B (to avoid detection) after inspecting or modifying it. All communication between A and B now flows through the attacker.

**Mitigation**

1. **Dynamic ARP Inspection (DAI):**\
   This is the primary technical defense and is implemented on managed network switches.
   * **How it works:** DAI is a security feature that validates ARP packets in a network. It intercepts all ARP requests and replies on the network and checks them against a trusted database—the DHCP Snooping binding table—which contains valid IP-to-MAC address bindings for devices that obtained an IP via DHCP.
   * **Result:** Any ARP packet with an invalid IP-to-MAC binding (like an attacker claiming to be another device) is identified as malicious and immediately dropped. The switch can also shut down the port and alert the administrator. DAI effectively prevents ARP cache poisoning on the protected network.
2. **Virtual Private Networks (VPNs):**
   * **How it works:** A VPN encrypts all traffic from a device to a secure endpoint (e.g., a corporate server or a VPN provider) located outside the local network. This encryption creates a secure "tunnel" through the local LAN.
   * **Result:** Even if an attacker successfully performs ARP spoofing and intercepts the data frames, the content of the communication remains encrypted and unreadable. The attacker can see that communication is happening, but cannot decipher or modify the payload in a meaningful way. VPNs are a crucial defense for sensitive communications on untrusted networks (e.g., public Wi-Fi).

**MAC Flooding (L2)**

A MAC Flooding attack targets network switches in an attempt to compromise their intended functionality and force them to behave like a network hub (broadcasting all traffic to all ports). The attacker overwhelms the switch's Content Addressable Memory (CAM) table, which is a finite-sized hardware table that stores MAC address-to-port mappings.

**Example of MAC Flooding:**

1. **The Normal Switch Operation:**\
   A switch intelligently forwards traffic by learning which MAC addresses are connected to which physical ports.
   * When a device sends a frame, the switch notes the source MAC address and the port it came in on, populating its CAM table.
   * When a frame needs to be sent to a specific MAC address, the switch looks it up in the CAM table and forwards the frame only out of the correct port. This provides network segmentation and security.
2. **The Hacker’s Trick (MAC Flooding):**\
   The attacker uses a tool to generate a massive number of Ethernet frames in rapid succession, each containing a different, random fake source MAC address.
   * The switch receives these frames and tries to learn each new source MAC address, adding every single one to its limited CAM table.
   * Once the CAM table is completely full of these fake entries, the switch can no longer learn any legitimate MAC addresses. To handle subsequent traffic it does not have a mapping for, the switch enters a "fail-open" mode.
   * In this state, the switch acts like a hub, **broadcasting unknown unicast traffic out of every port** except the source port. This allows the attacker to connect to any port on the switch and capture all broadcasted traffic, potentially sniffing sensitive data from other hosts.

**Mitigation**

1. **Port Security:**\
   This is the fundamental switch-based security feature designed explicitly to prevent MAC flooding and other Layer 2 attacks.
   * **How it works:** Port Security allows an administrator to configure a switch port with specific rules:
     * **MAC Limiting:** Set a maximum number of MAC addresses that can be learned on a single port (e.g., 1 for an access port, a few more for a port connected to a VoIP phone and computer).
     * **Static MAC Assignment:** Specify the exact MAC address(es) that are allowed to use a port.
     * **Violation Actions:** Define what happens when a violation occurs (e.g., an attacker connects or tries to flood MACs). Actions include **shutdown** (hard-disabling the port), **restrict** (dropping packets and sending an alert), or **protect** (silently dropping packets from unauthorized MACs).
   * **Result:** When an attacker starts flooding fake MACs on a secured port, the violation limit is quickly exceeded. The switch triggers the configured action (e.g., shutting down the port), instantly neutralizing the attack and protecting the rest of the network.
2. **MAC Limiting (as part of Port Security):**\
   While often used synonymously, MAC limiting is the specific action within the broader Port Security feature set. Configuring a low limit (like 1-5 addresses) on access ports is a best practice that strictly enforces the principle of "one user, one port, a few devices," making a flooding attack impossible to execute without triggering a security response.

***

**Sniffing (Eavesdropping) (L1)**

Sniffing (or packet sniffing/eavesdropping) is the act of capturing and monitoring data as it travels across a network. Sniffing exploits unencrypted transmissions. In its benign form, sniffing is a crucial tool for network administrators to diagnose problems. However, when used maliciously, it becomes a potent attack to harvest unprotected data directly from the physical transmission medium, such as radio waves (Wi-Fi) or electrical signals in a cable.

**Example of Malicious Sniffing:**

1. **The Normal Network Communication:**
   * A user enters their credentials on a website that uses HTTP (not HTTPS).
   * Their computer assembles the data into frames and packets, which are converted into electrical signals (Ethernet) or radio waves (Wi-Fi) and transmitted onto the physical medium.
   * Network devices like switches are designed to forward these signals only to the intended recipient.
2. **The Hacker’s Trick (Sniffing):**\
   An attacker configures a device's network interface card (NIC) in "promiscuous mode," instructing it to capture all traffic it sees on the medium, not just traffic addressed to it.
   * **On a Shared Medium (Hubs/Wi-Fi):** In old networks using hubs or in a default Wi-Fi setting, all devices physically receive all traffic. The attacker can easily capture everything broadcasted.
   * **On a Switched Network:** While switches segment traffic, an attacker can use techniques like ARP spoofing (see L2) to redirect traffic to their machine, or they can gain access to a mirror/SPAN port configured for monitoring.
   * The sniffer software (e.g., Wireshark) captures the raw data and reassembles the packets. If the data is not encrypted, the attacker can directly read the usernames, passwords, and any other information sent in plaintext.

**Mitigation**

1. **Encryption:**\
   Encryption is the absolute and primary defense against sniffing. If an attacker captures the data but it is encrypted, the captured packets are useless without the encryption key.
   * **WPA3 (Wi-Fi Protected Access 3):** For wireless networks, WPA3 is the current security standard. It provides robust encryption for all wireless traffic, preventing eavesdroppers from decrypting data even if they capture the radio transmissions. It also offers forward secrecy, meaning past traffic cannot be decrypted if the password is later compromised.
   * **MACsec (IEEE 802.1AE):** For wired Ethernet networks, MACsec provides point-to-point encryption at the data link layer between devices (e.g., between a user's computer and the switch, or between two switches). It encrypts all traffic on the wire, securing it against physical tapping on the LAN segment.
   * **Upper-Layer Encryption (HTTPS, SSH, VPNs):** Application and transport-layer encryption like HTTPS (TLS) for web traffic, SSH for remote access, and VPNs for creating encrypted tunnels are critical. This strategy, often called "end-to-end encryption," protects data even if the underlying physical or network layers are compromised.

**Cable Tapping (L1)**

Cable Tapping is a physical intrusion attack (e.g., state-sponsored espionage) where an attacker gains unauthorized access to the network's physical transmission medium—the cables themselves—to intercept or monitor data signals. This is a direct, physical form of eavesdropping that bypasses all logical network security controls.

**Example of Cable Tapping:**

1. **The Normal Physical Link:**\
   Data travels securely within a cable (e.g., copper Ethernet or fiber-optic) running through a building's walls, ceilings, or conduits. The integrity of the physical path is assumed.
2. **The Hacker’s Trick (Tapping):**\
   An attacker with physical access gains the ability to intercept the signal.
   * **Copper Cable Tapping:** For copper-based cables (like Ethernet), an attacker can use inductive clamps that read the electromagnetic emissions from the cable without making physical contact, or they can physically splice into the line to create a direct connection.
   * **Fiber-Optic Tapping:** Tapping fiber is more difficult but possible. It requires bending the cable to force a small amount of light to leak out, which can be detected and read by a photodetector, or by cutting and splicing the cable to insert a splitter that diverts a portion of the light signal to the attacker's equipment.

**Mitigation**

1. **Tamper-Evident Seals and Secure Conduits:**
   * **Tamper-Evident Seals:** Use these on access panels, wiring closets, server room doors, and junction boxes. These seals provide a clear, visible indication if a physical area or cabinet has been accessed without authorization.
   * **Secure Conduits and Cable Trays:** Run all network cables through locked conduits, ceilings with limited access, or metal cable trays with locks. This prevents casual access and makes it exceedingly difficult for an attacker to reach the cables without being detected.
2. **Fiber-Optic Monitoring (OTDR):**
   * **How it works:** An Optical Time-Domain Reflectometer (OTDR) is a device that can be used to monitor the health and integrity of fiber-optic cables. It sends a pulse of light down the fiber and analyzes the light that is reflected back.
   * **Result:** Any attempt to tap the fiber—whether by bending, cutting, or splicing—will create a unique "signature" or fault in the reflected light that the OTDR can detect. This allows for continuous monitoring and immediate alerts for any physical tampering on the fiber link.
3. **Physical Security and Access Controls:**\
   The first line of defense is strict physical security. This includes using **locked server rooms and wiring closets** with access restricted via keycards, logs, or biometrics, and implementing **surveillance cameras** to monitor critical network infrastructure areas. Without physical access, a cable tapping attack cannot be performed.

***

### Key threat characteristics and mitigation strategies

**Key threat characteristics**

1. **L1–L4 Threats**: Focus on **infrastructure disruption** (DDoS, MITM) and **data interception**.
   * _Example_: ICMP flooding threatens uptime (L3), while ARP spoofing threatens confidentiality (L2).
2. **L5–L7 Threats**: Target **sessions, users, and apps** (social engineering, logic flaws).
   * _Example_: Phishing (L6) exploits human trust, while SQLi (L7) exploits code flaws.

**Mitigation strategies**

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

• Common L7 attacks are DNS Spoofing and SQL Injection\
• Common L6 attacks are Phishing and Malicious File Uploads\
• Common L5 attacks are Session Hijacking and SSL Stripping\
• Common L4 attacks are TCP SYN Flooding and UDP Flooding\
• Common L3 attacks are ICMP Flooding and IP Spoofing\
• Common L2 attacks are ARP Spoofing (MITM) and MAC Flooding\
• Common L1 attacks are Sniffing and Cable Tapping
