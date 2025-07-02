---
description: >-
  This section discusses information security threats, cyber attacks, and
  defenses at each OSI layer
hidden: true
---

# Threats by OSI layer\_2

This section discusses network layers within the OSI model in the context of threats, vulnerabilities, and mitigation. The discussion focuses on the following network attack types:

L1 sniffing

L2 ARP spoofing MITM

L3 ICMP flooding

L4 TCP SYN flooding

L5 session hijacking

L6 phishing&#x20;

L7 DNS spoofing

**OSI model layers and security threats**

For the protocols associated with each OSI layer:

[Mapping of the TCP/IP model to the OSI Model](network-protocols-and-their-functions.md)

**Common Attack Types And Attack Techniques By OSI Layer**

| **OSI Layer**         | **Function**                                                                               | **Attack Type/Threat**            |
| --------------------- | ------------------------------------------------------------------------------------------ | --------------------------------- |
| **L7 (Application)**  | Allows application processes to access network services                                    | DNS Spoofing, SQL Injection       |
| **L6 (Presentation)** | Formats data to be presented to L7                                                         | Phishing, Malicious File Uploads  |
| **L5 (Session)**      | Establishes and manages sessions between processes running on different stations           | Session Hijacking, SSL Stripping  |
| **L4 (Transport)**    | Ensures end-to-end error-free data delivery                                                | TCP SYN Flooding, UDP Flooding    |
| **L3 (Network)**      | Performs packet routing (logical addressing)                                               | ICMP Flooding, IP Spoofing        |
| **L2 (Data Link)**    | Provides node-to-node error-free data transfer (physical addressing)                       | ARP Spoofing (MITM), MAC Flooding |
| **L1 (Physical)**     | Specifies the physical characteristics of the medium used to transfer data between devices | Sniffing, Cable Tapping           |

L1 sniffing (Eavesdropping Threat)

L1 Cable Tapping

L2 ARP spoofing MITM

L2 MAC Flooding (Switch Saturation Threat)

L3 ICMP flooding

L3 IP Spoofing (Source Identity Threat)

L4 TCP SYN flooding

L4 UDP Flooding

L5 session hijacking

L5 SSL Stripping (Downgrade Attack Threat)

L6 phishing&#x20;

L6 Malicious File Uploads

L7 DNS spoofing

L7 SQL Injection

**Threats by OSI Layer**

<table data-header-hidden><thead><tr><th width="73.265625"></th><th width="120.29296875"></th><th width="130.94921875"></th><th></th><th></th><th></th></tr></thead><tbody><tr><td><strong>OSI Layer</strong></td><td><strong>Attack Type/Threat</strong></td><td><strong>Attack Technique</strong></td><td><strong>Vulnerability Exploited</strong></td><td><strong>Risk Scenario</strong></td><td><strong>Mitigation</strong></td></tr><tr><td><strong>L7</strong></td><td>DNS Spoofing</td><td>Corrupting DNS cache to redirect users</td><td>Unvalidated DNS responses</td><td>Redirects users to malicious sites (e.g., fake banking portals)</td><td>DNSSEC, DoH/DoT (DNS over HTTPS/TLS)</td></tr><tr><td></td><td>SQL Injection</td><td></td><td></td><td>Bypasses authentication or exfiltrates DB data (e.g., <code>' OR 1=1 --</code> attacks)</td><td></td></tr><tr><td><strong>L6</strong></td><td>Phishing</td><td>Social engineering to steal credentials</td><td>Human trust, lack of training</td><td>Tricks users into revealing credentials (e.g., fake login pages or malicious attachments)</td><td>User education, Email filtering (DMARC)</td></tr><tr><td></td><td>Malicious File Uploads</td><td></td><td></td><td>Uploads malware disguised as documents (e.g., PDFs with embedded exploits)</td><td></td></tr><tr><td><strong>L5</strong></td><td>Session Hijacking</td><td>Stealing valid session tokens</td><td>Weak session tokens, timeouts</td><td>Steals active sessions to impersonate users (e.g., stealing cookies via XSS or MITM)</td><td>HTTPS, Secure cookies, MFA</td></tr><tr><td></td><td>SSL Stripping</td><td></td><td></td><td>Forces HTTPS→HTTP to intercept plaintext data (e.g., evil-twin Wi-Fi attacks)</td><td></td></tr><tr><td><strong>L4</strong></td><td>TCP SYN Flooding</td><td>Exploiting TCP handshake to exhaust resources</td><td>TCP handshake design flaw</td><td>Exhausts server TCP pools, causing service outages (e.g., volumetric DDoS)</td><td>SYN cookies, Firewall rules</td></tr><tr><td></td><td>UDP Flooding</td><td></td><td></td><td>Exploits stateless UDP to flood services (e.g., DNS/QUIC protocol abuse)</td><td></td></tr><tr><td><strong>L3</strong></td><td>ICMP Flooding</td><td>Overwhelming a target with ping requests (DDoS)</td><td>No rate limiting on ICMP replies</td><td>DDoS attacks overwhelm bandwidth/resources (e.g., Smurf attacks using amplified ICMP replies)</td><td>ICMP rate limiting, Network filtering</td></tr><tr><td></td><td>IP Spoofing</td><td></td><td></td><td>Masquerading as trusted IPs to bypass ACLs or launch reflected attacks (e.g., NTP amplification)</td><td></td></tr><tr><td><strong>L2</strong></td><td>ARP Spoofing (MITM)</td><td>Actively poisoning ARP tables to redirect traffic</td><td>Lack of ARP authentication</td><td>Attackers redirect or monitor traffic within a local network (e.g., stealing session cookies)</td><td>Dynamic ARP Inspection (DAI), VPNs</td></tr><tr><td></td><td>MAC Flooding</td><td></td><td></td><td>Overwhelms switches to force open ports, enabling sniffing (e.g., CAM table overflow attacks)</td><td></td></tr><tr><td><strong>L1</strong></td><td>Sniffing</td><td>Passive interception of unencrypted traffic</td><td>Unencrypted transmissions</td><td>Unauthorized data capture via exposed cables/Wi-Fi (e.g., stealing credentials from cleartext traffic)</td><td>Encryption (e.g., WPA3, MACsec)</td></tr><tr><td></td><td>Cable Tapping</td><td></td><td></td><td>Attacker physically taps fiber/copper lines to intercept data (common in espionage)</td><td></td></tr></tbody></table>

**Key Threat Characteristics**

1. **L1–L4 Threats**: Focus on **infrastructure disruption** (DDoS, MITM) and **data interception**.
   * _Example_: ICMP flooding threatens uptime (L3), while ARP spoofing threatens confidentiality (L2).
2. **L5–L7 Threats**: Target **sessions, users, and apps** (social engineering, logic flaws).
   * _Example_: Phishing (L6) exploits human trust, while SQLi (L7) exploits code flaws.
3. **Shared Patterns**:
   * **Spoofing**: ARP (L2), IP (L3), DNS (L7).
   * **Flooding**: ICMP (L3), TCP/UDP (L4).

**Key Clarifications**

1. **OSI Layer Context**:
   * **L1–L4**: Primarily infrastructure attacks (e.g., DDoS, MITM).
   * **L5–L7**: Focused on sessions, data manipulation, and human factors.
2. **Mitigation Strategies**:
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

**Real-World Threat Examples**

* **L2 Threat**: An attacker uses ARP spoofing in a coffee shop Wi-Fi to steal unencrypted emails.
* **L7 Threat**: DNS spoofing redirects victims to a fake PayPal site, harvesting credentials.

**Expanded OSI Attack Examples**

| **OSI Layer**         | **Attack Type/Threat**                                                                  | **Vulnerability**            | **Mitigation**                           |
| --------------------- | --------------------------------------------------------------------------------------- | ---------------------------- | ---------------------------------------- |
| **L7 (Application)**  | API abuse, Zero-day exploits                                                            | Logic flaws in apps          | WAFs, Input validation, Patch management |
| **L6 (Presentation)** | Malicious file uploads (e.g., PDF)                                                      | Improper file validation     | File type restrictions, sandboxing       |
| **L5 (Session)**      | SSL stripping, Man-in-the-Browser                                                       | Weak TLS implementation      | HSTS, Certificate pinning                |
| **L4 (Transport)**    | UDP flooding, Port scanning                                                             | Open ports, no rate limiting | IDS/IPS, stateful inspection             |
| **L3 (Network)**      | IP spoofing, Smurf attack                                                               | No source IP validation      | Ingress filtering (BCP38)                |
| **L2 (Data Link)**    | MAC flooding, VLAN hopping                                                              | Switch misconfigurations     | Port security, VLAN segregation          |
| **L1 (Physical)**     | <p>Physical tampering, Cable tapping, RFID cloning, Electromagnetic<br>Interference</p> | Physical access to media     | Physical security, encryption            |

### Key takeaways

• Point 1\
• Point 2
