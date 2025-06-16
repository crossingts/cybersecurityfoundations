# Confidentiality, integrity, and availability of information

The most concrete (least abstract) and tactical (as opposed to strategic) goal of information security is the protection of the confidentiality, integrity, and availability of information assets.

A fundamental goal of security in an enterprise is to protect the confidentiality, integrity, and availability (CIA) of information assets. The principles of the CIA triad form the foundation of security.&#x20;

* Confidentiality: only authorized users should be able to access privileged/private data.
* Integrity: data should not be changed or modified by unauthorized users. Data should be correct and authentic.
* Availability: the enterprise network and systems should be operational and accessible to authorized users. For example, staff should be able to access the internal resources they need to perform their duties, and the company’s website should be up and running and available to customers.

(CCNA security fundamentals)

### Confidentiality

\<A key **technology** for data confidentiality is data leakage prevention (DLP), a system that tracks specific sets of sensitive data. For example, DLP can issue alerts when sensitive files are copied to a USB, or credit-card numbers are shared. DLP is a great tool, but it requires precise, organization specific data classification and alert creation in order to be effective.>

### Integrity

**Technologies**: encryption, backups, AAA accounting (data access), SVN/Git (data modification), SIEM

\<To protect data integrity, regular audits of information access and change are required. Data access has to be centrally logged, in case a bad actor manages to damage log data at the endpoint. Any employee who modifies sensitive data should do so using his or her personal user name. This allows non-repudiation, which means that an employee who modified data can’t deny his or her action.&#x20;

\<To truly safeguard information integrity, you’ll want to incorporate change management technology. Change management basically tracks changes to data, requires management approval of changes, or prevents changes forbidden by policy. Change management usually stores snapshot of data and tracks changes that are performed on it. Those changes are compared with system policy, and carried out only when they are in compliance with the policy. There are numerous change management products that can apply granular policies to track and prevent unwanted changes on almost any device, from storage filers to firewalls. One of best-known systems for change management is free SVN, which allows the detailed tracking of data inside a file, as well as granular permission control.

### Availability

Data can become unavailable due to being damaged or destroyed, or due to ransomeware.

You should also be aware that your data could be damaged by malware that remains dormant for long period of time.&#x20;

### Techniques of CIA attacks

#### Confidentiality attacks

A confidentiality attack is a type of cyberattack aimed at gaining unauthorized/unlawful access to privileged/private information. These attacks exploit vulnerabilities in systems, networks, or human behavior to access confidential data such as personal records, financial details, or trade secrets. Common attack techniques that compromise confidentiality include:

1. **Packet sniffing (packet capture):** Attackers intercept and analyze network traffic to extract sensitive information (e.g., using tools like Wireshark or tcpdump). For example, an attacker on an unsecured Wi-Fi network could capture unencrypted login credentials.
2. **Port scanning:** Attackers scan a target system’s open ports to identify vulnerable services (e.g., using Nmap). While port scanning itself does not directly steal data, it is often a precursor to exploitation (e.g., targeting an open SSH port to brute-force a password).
3. **Wiretapping (eavesdropping):** Attackers secretly monitor communications, such as phone calls (traditional wiretapping) or unencrypted VoIP traffic. Modern variants include man-in-the-middle (MITM) attacks, where an attacker intercepts and possibly alters data exchanged between two parties.
4. **SQL injection:** Malicious code is injected into a database query to extract unauthorized information from a vulnerable system.
5. **SSL/TLS stripping (HTTPS downgrade)**
   * Technique: An attacker forces a victim’s browser to downgrade an encrypted HTTPS connection to unencrypted HTTP using tools like sslstrip.
   * Impact: Login credentials or session cookies are transmitted in plaintext, allowing interception (e.g., on public Wi-Fi).

These techniques undermine confidentiality by exposing data to unauthorized entities, whether through passive interception (e.g., sniffing) or active exploitation (e.g., credential theft).

#### Integrity attacks

An information integrity attack is a malicious attempt to alter, modify, or corrupt data to deceive users, disrupt operations, or cause harm. The goal is to make data inaccurate or unreliable without authorization. Information sabotage through viruses, malware, or unauthorized modifications constitutes an integrity attack, as it compromises the accuracy, consistency, and reliability of data (Bishop, 2003; Pfleeger & Pfleeger, 2015). Common attack techniques that compromise integrity include:

1. **Session hijacking:** An attacker takes over an active session (e.g., a logged-in user’s web session) to manipulate or falsify data.
   * Example: Using cross-site scripting (XSS) or session fixation to steal a user’s session cookie, allowing the attacker to alter account details in a banking system.
2. **Man-in-the-middle (MITM) attacks:** An attacker intercepts and alters communications between two parties without their knowledge.
   * Example: Using ARP spoofing or SSL stripping to modify transaction details in real time (e.g., changing a recipient’s bank account number during an online transfer).
3. **Data tampering via malware:** Malicious software (e.g., ransomware, rootkits, or logic bombs) corrupts or falsifies data.
   * Example: The Stuxnet worm manipulated industrial control systems by altering programmable logic controller (PLC) code, causing physical damage.
4. **SQL injection**: A hacker injects malicious SQL code into a database query to modify, delete, or corrupt data.

Unlike confidentiality attacks (which focus on unauthorized access), integrity attacks ensure that even if data is accessed, it cannot be trusted due to unauthorized modifications.

#### Availability attacks

An information availability attack aims to disrupt access to data, systems, or services, making them unavailable to legitimate users. These attacks often involve overwhelming a system or blocking access. A denial-of-service (DoS) attack targets the availability of information systems, rendering them inaccessible to legitimate users (Stallings & Brown, 2018; Skoudis & Liston, 2005). Ransomware is another availability attack where attackers encrypt a victim’s data and demand payment to restore access, effectively denying service until the ransom is paid (e.g., WannaCry or LockBit). Common attack techniques that compromise availability include:

1. **SYN flood attack:** A SYN flood attack exploits the TCP three-way handshake by flooding a target with SYN packets (often from spoofed IPs). The server allocates resources for each request and sends SYN-ACKs, but the attacker never completes the handshake with the final ACK. This exhausts the server’s connection queue, denying service to legitimate users.
   * Impact: Overwhelms a web server, causing it to drop legitimate connections (e.g., disrupting an e-commerce site during peak sales).
2. **ICMP flood (ping flood) attack:** The target is bombarded with fake ICMP Echo Request (ping) packets, consuming bandwidth and processing power.
   * Impact: Slows down or crashes network devices (e.g., routers), making services unreachable.
3. **Distributed denial-of-service (DDoS) attack:** A coordinated large-scale attack using multiple compromised systems (e.g., a botnet) to amplify traffic and cripple targets.
   * Example: The Mirai botnet attack (2016) exploited IoT devices to take down major websites like Twitter and Netflix.
4. **Ransomware attack:** Encrypting critical data and demanding payment to restore access.
5. **Physical infrastructure sabotage:** Cutting network cables or destroying servers to halt operations.

Unlike confidentiality or integrity attacks, availability attacks aim primarily to disrupt service rather than steal or alter data. Mitigation strategies include rate limiting, traffic filtering, and cloud-based DDoS protection services (e.g., AWS Shield, Cloudflare).

(Professional ethical hacking body of knowledge/Network security basics)

### References

Reference
