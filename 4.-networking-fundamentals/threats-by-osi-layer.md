---
description: >-
  This section discusses information security threats, cyber attacks, and
  defenses at each OSI layer
hidden: true
---

# Threats by OSI layer

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

| **OSI Layer**         | **Function**                                                                               | **Attack Type**     | **Attack Technique**                              | **Vulnerability Exploited**      | **Mitigation**                          |
| --------------------- | ------------------------------------------------------------------------------------------ | ------------------- | ------------------------------------------------- | -------------------------------- | --------------------------------------- |
| **L7 (Application)**  | Allows application processes to access network services                                    | DNS Spoofing        | Corrupting DNS cache to redirect users            | Unvalidated DNS responses        | DNSSEC, DoH/DoT (DNS over HTTPS/TLS)    |
| **L6 (Presentation)** | Formats data to be presented to L7                                                         | Phishing            | Social engineering to steal credentials           | Human trust, lack of training    | User education, Email filtering (DMARC) |
| **L5 (Session)**      | Establishes and manages sessions between processes running on different stations           | Session Hijacking   | Stealing valid session tokens                     | Weak session tokens/timeouts     | HTTPS, Secure cookies, MFA              |
| **L4 (Transport)**    | Ensures end-to-end error-free data delivery                                                | TCP SYN Flooding    | Exploiting TCP handshake to exhaust resources     | TCP handshake design flaw        | SYN cookies, Firewall rules             |
| **L3 (Network)**      | Performs packet routing (logical addressing)                                               | ICMP Flooding       | Overwhelming a target with ping requests (DDoS)   | No rate limiting on ICMP replies | ICMP rate limiting, Network filtering   |
| **L2 (Data Link)**    | Provides node-to-node error-free data transfer (physical addressing)                       | ARP Spoofing (MITM) | Actively poisoning ARP tables to redirect traffic | Lack of ARP authentication       | Dynamic ARP Inspection (DAI), VPNs      |
| **L1 (Physical)**     | Specifies the physical characteristics of the medium used to transfer data between devices | Sniffing            | Passive interception of unencrypted traffic       | Unencrypted transmissions        | Encryption (e.g., WPA3, MACsec)         |

**Key Clarifications**

1. **Attacks vs. Threat Vectors**:
   * **Attack**: A specific malicious action (e.g., ICMP flooding).
   * **Threat Vector**: The _method_ used to deliver the attack (e.g., phishing emails for credential theft).
   * _Overlap_: Some terms (e.g., DNS spoofing) describe both an attack and a vector.
2. **OSI Layer Context**:
   * **L1–L4**: Primarily infrastructure attacks (e.g., DDoS, MITM).
   * **L5–L7**: Focused on sessions, data manipulation, and human factors.
3. **Mitigation Strategies**:
   * **Lower layers (L1–L4)**: Encryption, network hardening (e.g., firewall rules).
   * **Upper layers (L5–L7)**: Behavioral controls (e.g., MFA, training).

***

How each attack type translates into a broader threat category, along with real-world implications and risk scenarios:

**Threats by OSI Layer**

| **OSI Layer**         | **Attack Type**        | **Threat Classification**    | **Threat Impact & Scenario**                                                                            |
| --------------------- | ---------------------- | ---------------------------- | ------------------------------------------------------------------------------------------------------- |
| **L7 (Application)**  | DNS Spoofing           | Trust Manipulation Threat    | Redirects users to malicious sites (e.g., fake banking portals).                                        |
|                       | SQL Injection          | Application Logic Threat     | Bypasses authentication or exfiltrates DB data (e.g., `' OR 1=1 --` attacks).                           |
| **L6 (Presentation)** | Phishing               | Human Manipulation Threat    | Tricks users into revealing credentials (e.g., fake login pages or malicious attachments).              |
|                       | Malicious File Uploads | Data Integrity Threat        | Uploads malware disguised as documents (e.g., PDFs with embedded exploits).                             |
| **L5 (Session)**      | Session Hijacking      | Authentication Bypass Threat | Steals active sessions to impersonate users (e.g., stealing cookies via XSS or MITM).                   |
|                       | SSL Stripping          | Downgrade Attack Threat      | Forces HTTPS→HTTP to intercept plaintext data (e.g., evil-twin Wi-Fi attacks).                          |
| **L4 (Transport)**    | TCP SYN Flooding       | Connection Resource Threat   | Exhausts server TCP pools, causing service outages (e.g., volumetric DDoS).                             |
|                       | UDP Flooding           | Unfiltered Protocol Threat   | Exploits stateless UDP to flood services (e.g., DNS/QUIC protocol abuse).                               |
| **L3 (Network)**      | ICMP Flooding          | Network Availability Threat  | DDoS attacks overwhelm bandwidth/resources (e.g., Smurf attacks using amplified ICMP replies).          |
|                       | IP Spoofing            | Source Identity Threat       | Masquerading as trusted IPs to bypass ACLs or launch reflected attacks (e.g., NTP amplification).       |
| **L2 (Data Link)**    | ARP Spoofing (MITM)    | LAN Integrity Threat         | Attackers redirect or monitor traffic within a local network (e.g., stealing session cookies).          |
|                       | MAC Flooding           | Switch Saturation Threat     | Overwhelms switches to force open ports, enabling sniffing (e.g., CAM table overflow attacks).          |
| **L1 (Physical)**     | Sniffing               | Eavesdropping Threat         | Unauthorized data capture via exposed cables/Wi-Fi (e.g., stealing credentials from cleartext traffic). |
|                       | Cable Tapping          | Physical Intrusion Threat    | Attacker physically taps fiber/copper lines to intercept data (common in espionage).                    |

**Key Threat Characteristics**

1. **L1–L4 Threats**: Focus on **infrastructure disruption** (DDoS, MITM) and **data interception**.
   * _Example_: ICMP flooding threatens uptime (L3), while ARP spoofing threatens confidentiality (L2).
2. **L5–L7 Threats**: Target **sessions, users, and apps** (social engineering, logic flaws).
   * _Example_: Phishing (L6) exploits human trust, while SQLi (L7) exploits code flaws.
3. **Shared Patterns**:
   * **Spoofing**: ARP (L2), IP (L3), DNS (L7).
   * **Flooding**: ICMP (L3), TCP/UDP (L4).

***

**Mitigation Mapping**

| **Threat Category**        | **Mitigation Strategies**                              |
| -------------------------- | ------------------------------------------------------ |
| **App Logic (L7)**         | Input validation, WAFs, DNSSEC.                        |
| **Phishing (L6)**          | User training, DMARC/SPF/DKIM, email filters.          |
| **Session Hijacking (L5)** | MFA, short-lived tokens, HSTS.                         |
| **DDoS (L3/L4)**           | Rate limiting, BCP38 filtering, cloud-based scrubbing. |
| **Eavesdropping (L1/L2)**  | Encryption (WPA3, MACsec), physical access controls.   |

***

**Real-World Threat Examples**

* **L2 Threat**: An attacker uses ARP spoofing in a coffee shop Wi-Fi to steal unencrypted emails.
* **L7 Threat**: DNS spoofing redirects victims to a fake PayPal site, harvesting credentials.

***

**Expanded OSI Attack Examples**

| **OSI Layer**         | **Common Attacks/Threats**         | **Vulnerability**            | **Mitigation**                           |
| --------------------- | ---------------------------------- | ---------------------------- | ---------------------------------------- |
| **L7 (Application)**  | API abuse, Zero-day exploits       | Logic flaws in apps          | WAFs, Input validation, Patch management |
| **L6 (Presentation)** | Malicious file uploads (e.g., PDF) | Improper file validation     | File type restrictions, sandboxing       |
| **L5 (Session)**      | SSL stripping, Man-in-the-Browser  | Weak TLS implementation      | HSTS, Certificate pinning                |
| **L4 (Transport)**    | UDP flooding, Port scanning        | Open ports, no rate limiting | IDS/IPS, stateful inspection             |
| **L3 (Network)**      | IP spoofing, Smurf attack          | No source IP validation      | Ingress filtering (BCP38)                |
| **L2 (Data Link)**    | MAC flooding, VLAN hopping         | Switch misconfigurations     | Port security, VLAN segregation          |
| **L1 (Physical)**     | Cable tapping, RFID cloning        | Physical access to media     | Physical security, encryption            |

***

**Takeaways**

* **NIST Alignment**: L1–L4 attacks often exploit misconfigurations (e.g., ARP spoofing), while L5–L7 involve logic flaws (e.g., phishing).
* **Threat Actors**: Lower-layer attacks (L1–L4) are common in network pentests; upper layers (L5–L7) target apps/users.
