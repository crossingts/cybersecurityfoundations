---
description: >-
  This sections introduces core and foundational cybersecurity concepts and
  practices such as confidentiality, integrity, and availability (the CIA triad)
---

# Foundational cybersecurity concepts and practices

## Learning objectives

• Become familiar with key cybersecurity concepts and practices\
• Learn key cybersecurity definitions \
• Describe where cybersecurity fits within corporate organizational structures \
• Understand how cybersecurity is practiced within organizations

This section introduces cybersecurity concepts and practices germane to any instruction aiming to establish a practical understanding of the goals of cybersecurity and how it is practiced within organizations. This section covers definitions of information security, the CIA triad, risk, threat, vulnerability, mitigation, and the AAA framework (Authentication, Authorization, and Accounting).

## Topics covered in this section

* **Information security definition**
* **The place of information security in enterprise IT governance**
* **Confidentiality, integrity, and availability of information**
* **Techniques of CIA attacks**
* **Information security risk management**
* **Other information security concepts and practices**

### Information security definition

The terms information security, cybersecurity, Internet security, computer security, and network security have intersecting and evolving meanings, but generally refer to processes of implementing security controls including IA/IT governance frameworks to protect the confidentiality, integrity, and availability of privileged information as well as the technological infrastructure of a computer network or system against unauthorized access or manipulation (Anderson, 2003; Blakley, McDermott & Geer, 2001; Cherdantseva & Hilton, 2013; CNSS, 2010; ISACA, 2008; ISO/IEC 27000:2009; Venter & Eloff, 2003).

Sensitive data should be protected based on the potential impact of a loss of confidentiality, integrity, or availability. **Confidentiality** refers to protecting information from being accessed by unauthorized parties. **Integrity** refers to ensuring the authenticity of information—that information is not altered, and that the source of the information is genuine. **Availability** of information means that information is accessible by authorized users.

Information security is “a risk management discipline" (Blakley et al., 2001) focused on identifying information assets, associated risks, and suitable (pragmatic) mitigation methods.

Information security,

* “preserves the confidentiality, integrity and availability of information” (ISO/IEC 27000:2009);
* is concerned with “authenticity, accountability, non-repudiation and reliability” (ISO/IEC 27000:2009 sees CIA as properties of information);
* ensures that “only authorized users (confidentiality) have access to accurate and complete information (integrity) when required (availability)” (ISACA, 2008);
* is concerned with both the protection of information as well as the of technological infrastructure or information systems (Cherdantseva & Hilton, 2013; CNSS, 2010);
* is concerned with access to information (CNSS, 201; ISACA, 2008); and
* aims to provide assurance “that information risks and controls are in balance” (Anderson, J., 2003).

Key information security concepts include privacy, authenticity and trustworthiness, non-repudiation, accountability and auditability, and reliability (Cherdantseva & Hilton, 2013; ISO/IEC 27000:2009).&#x20;

The broad pragmatic goal of information security management is to reduce the probability of unauthorized access or damage to valued information assets to an acceptable risk level through risk mitigation strategies that involve management controls (e.g., security policies), technical controls (e.g., intrusion detection techniques), and operational controls (best practices/standard operating procedures).

Information security threats most commonly rated as a concern in higher education in North America are as follows. Confidentiality attacks: Exposure of confidential or sensitive information (79%), Integrity attacks: Unauthorized or accidental modification of data (29%), Availability attacks: Loss of availability or sabotage of systems (16%), mixed threat attacks: Email viruses, ransomware, or other malware (31%), and Unauthorized, malicious network/system access (27%) (EDUCAUSE Information Security Almanac, April 2019, p. 2).

### The place of information security in enterprise IT governance

Information security governance is the top-level enterprise business function accountable for information security under the rubric of IT governance (NCC 2005 IT Governance). The IT department is a customer of the information security governance business function or service, (e.g., HR, Finance).&#x20;

IT security as integrated with enterprise-wide risk management policy/framework (IT security risk management) operates within the information security governance framework. Information security is a specialized function within business organizations focused on securing an organization’s information assets against unauthorized access or damage. An information security professional from IT ensures an institution’s IT system is operating in a way that meets varied regulatory requirements.&#x20;

IT security is a stakeholder level concern within enterprises and is concerned with Internet access and identity and access management, and the technological infrastructure of the IT network and its smooth operation. Information security governance is concerned with defining security policy and aligning security strategy with business strategy. Information Systems are comprised of hardware, software, and communications “with the purpose to help identify and apply information security industry standards, as mechanisms of protection and prevention, at three levels or layers: Physical, personal and organizational” (Cherdantseva & Hilton, 2013).&#x20;

Areas for which central IT most commonly has primary responsibility in higher education are Network security (94%), Monitoring (88%), Communications security (86%), and Identity management (83%) (EDUCAUSE Information Security Almanac, April 2019).

### Confidentiality, integrity, and availability of information

The most concrete (least abstract) and tactical (as opposed to strategic) goal of information security is the protection of the confidentiality, integrity, and availability of information assets. The principles of the CIA triad form the foundation of security. These three principles help ensure that data is protected, accurate, and accessible when needed.

* Confidentiality denotes an imperative that only authorized users should be able to access privileged/private data.
* Integrity denotes an imperative that data should not be changed or modified by unauthorized users. Data should be correct and authentic.
* Availability denotes an imperative that an information system should be operational and accessible to authorized users. For example, staff should be able to access the internal resources they need to perform their duties, and the company’s website should be up and running and available to customers.

#### Confidentiality

\<A key **technology** for data confidentiality is data leakage prevention (DLP), a system that tracks specific sets of sensitive data. For example, DLP can issue alerts when sensitive files are copied to a USB, or credit-card numbers are shared. DLP is a great tool, but it requires precise, organization specific data classification and alert creation in order to be effective.>

#### Integrity

**Technologies**: encryption, backups, AAA accounting (data access), SVN/Git (data modification), SIEM

\<To protect data integrity, regular audits of information access and change are required. Data access has to be centrally logged, in case a bad actor manages to damage log data at the endpoint. Any employee who modifies sensitive data should do so using his or her personal user name. This allows non-repudiation, which means that an employee who modified data can’t deny his or her action.&#x20;

\<To truly safeguard information integrity, you’ll want to incorporate change management technology. Change management basically tracks changes to data, requires management approval of changes, or prevents changes forbidden by policy. Change management usually stores snapshot of data and tracks changes that are performed on it. Those changes are compared with system policy, and carried out only when they are in compliance with the policy. There are numerous change management products that can apply granular policies to track and prevent unwanted changes on almost any device, from storage filers to firewalls. One of best-known systems for change management is free SVN, which allows the detailed tracking of data inside a file, as well as granular permission control.

#### Availability

**Technologies**: backups, AAA accounting (data access)/Identity and Access Management, SVN/Git, SIEM, high availability/network redundancy

Data can become unavailable due to being damaged or destroyed, or due to ransomeware or dormant malware.&#x20;

Unlike confidentiality or integrity attacks, availability attacks aim primarily to disrupt service rather than steal or alter data. Mitigation strategies include rate limiting, traffic filtering, and cloud-based DDoS protection services (e.g., AWS Shield, Cloudflare).

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

### Information security risk management

### Other information security concepts and practices

### Key takeaways

• Tactically, cybersecurity is about protecting the CIA of information assets \
• Strategically, cybersecurity is about compliance with rules \
• Cybersecurity and information security can be synonymous \
• Organizations take a risk-based approach to cybersecurity management

### References

Shamil Alifov. (2016). How to get started in cryptography (Ch. 5). In _Beginner’s Guide To Information Security_ (pp. 27-31). Peerlyst. Retrieved from https://www.peerlyst.com/posts/peerlyst-announcing-its-first-community-ebook-the-beginner-s-guide-to-information-security-limor-elbaz

Yuri Livshitz. (2016). How to secure your data (Ch. 6). In Beginner’s Guide To Information Security (pp. 32-35). Peerlyst. Retrieved from https://www.peerlyst.com/posts/peerlyst-announcing-its-first-community-ebook-the-beginner-s-guide-to-information-security-limor-elbaz
