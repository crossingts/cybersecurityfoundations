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

| **OSI Layer**         | **Function**                                                                               | **Attack Type/Threat** | **Attack Technique**                              | **Vulnerability Exploited**      |
| --------------------- | ------------------------------------------------------------------------------------------ | ---------------------- | ------------------------------------------------- | -------------------------------- |
| **L7 (Application)**  | Allows application processes to access network services                                    | DNS Spoofing           | Corrupting DNS cache to redirect users            | Unvalidated DNS responses        |
| **L6 (Presentation)** | Formats data to be presented to L7                                                         | Phishing               | Social engineering to steal credentials           | Human trust, lack of training    |
| **L5 (Session)**      | Establishes and manages sessions between processes running on different stations           | Session Hijacking      | Stealing valid session tokens                     | Weak session tokens/timeouts     |
| **L4 (Transport)**    | Ensures end-to-end error-free data delivery                                                | TCP SYN Flooding       | Exploiting TCP handshake to exhaust resources     | TCP handshake design flaw        |
| **L3 (Network)**      | Performs packet routing (logical addressing)                                               | ICMP Flooding          | Overwhelming a target with ping requests (DDoS)   | No rate limiting on ICMP replies |
| **L2 (Data Link)**    | Provides node-to-node error-free data transfer (physical addressing)                       | ARP Spoofing (MITM)    | Actively poisoning ARP tables to redirect traffic | Lack of ARP authentication       |
| **L1 (Physical)**     | Specifies the physical characteristics of the medium used to transfer data between devices | Sniffing               | Passive interception of unencrypted traffic       | Unencrypted transmissions        |

\--

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

| **OSI Layer**         | **Attack Type/Threat** | **Attack Technique** | **Risk Scenario**                                                                                       | **Mitigation**                          |
| --------------------- | ---------------------- | -------------------- | ------------------------------------------------------------------------------------------------------- | --------------------------------------- |
| **L7 (Application)**  | DNS Spoofing           |                      | Redirects users to malicious sites (e.g., fake banking portals).                                        | DNSSEC, DoH/DoT (DNS over HTTPS/TLS)    |
|                       | SQL Injection          |                      | Bypasses authentication or exfiltrates DB data (e.g., `' OR 1=1 --` attacks).                           |                                         |
| **L6 (Presentation)** | Phishing               |                      | Tricks users into revealing credentials (e.g., fake login pages or malicious attachments).              | User education, Email filtering (DMARC) |
|                       | Malicious File Uploads |                      | Uploads malware disguised as documents (e.g., PDFs with embedded exploits).                             |                                         |
| **L5 (Session)**      | Session Hijacking      |                      | Steals active sessions to impersonate users (e.g., stealing cookies via XSS or MITM).                   | HTTPS, Secure cookies, MFA              |
|                       | SSL Stripping          |                      | Forces HTTPS→HTTP to intercept plaintext data (e.g., evil-twin Wi-Fi attacks).                          |                                         |
| **L4 (Transport)**    | TCP SYN Flooding       |                      | Exhausts server TCP pools, causing service outages (e.g., volumetric DDoS).                             | SYN cookies, Firewall rules             |
|                       | UDP Flooding           |                      | Exploits stateless UDP to flood services (e.g., DNS/QUIC protocol abuse).                               |                                         |
| **L3 (Network)**      | ICMP Flooding          |                      | DDoS attacks overwhelm bandwidth/resources (e.g., Smurf attacks using amplified ICMP replies).          | ICMP rate limiting, Network filtering   |
|                       | IP Spoofing            |                      | Masquerading as trusted IPs to bypass ACLs or launch reflected attacks (e.g., NTP amplification).       |                                         |
| **L2 (Data Link)**    | ARP Spoofing (MITM)    |                      | Attackers redirect or monitor traffic within a local network (e.g., stealing session cookies).          | Dynamic ARP Inspection (DAI), VPNs      |
|                       | MAC Flooding           |                      | Overwhelms switches to force open ports, enabling sniffing (e.g., CAM table overflow attacks).          |                                         |
| **L1 (Physical)**     | Sniffing               |                      | Unauthorized data capture via exposed cables/Wi-Fi (e.g., stealing credentials from cleartext traffic). | Encryption (e.g., WPA3, MACsec)         |
|                       | Cable Tapping          |                      | Attacker physically taps fiber/copper lines to intercept data (common in espionage).                    |                                         |

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

**Takeaways**

* **NIST Alignment**: L1–L4 attacks often exploit misconfigurations (e.g., ARP spoofing), while L5–L7 involve logic flaws (e.g., phishing).
* **Threat Actors**: Lower-layer attacks (L1–L4) are common in network pentests; upper layers (L5–L7) target apps/users.
