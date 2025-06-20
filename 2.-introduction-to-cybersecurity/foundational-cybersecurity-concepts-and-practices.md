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

In addition to the CIA triad, other foundational information security concepts include:&#x20;

* A vulnerability is any potential weakness that can compromise the CIA of information assets. A window in a house is a vulnerability burglars can exploit to enter the house.&#x20;
* An exploit is something that can potentially be used to exploit the vulnerability. A rock can exploit the weakness of glass windows and may be used to enter a house.
* A threat is the potential of a vulnerability to be exploited. The threat of house burglary is the likelihood a burglar will exploit the glass window vulnerability using a rock (or other exploits) to gain entry into a house.&#x20;
* A mitigation technique is something that can protect against threats. Appropriate mitigation techniques should be implemented everywhere a vulnerability can be exploited, for example, client devices, servers, switches, and routers.

#### Risk = threat, vulnerability, and mitigation

The concept of risk is intimately tied to the concepts of threat, vulnerability, and mitigation. Risk is a threat that exploits a vulnerability.

**Vulnerabilities**

Vulnerabilities can be understood as security flaws or holes.

We can think of security flaws in the context of people, process, and technology.

Vulnerabilities can stem from:

• The software infrastructure, including software programs/applications, and OS\
• The network infrastructure\
• The hardware involved\
• Organizational/network policies/procedures which could lead eventually to a security hole\
• Human vulnerabilities to social hacking techniques/lack of security awareness\
• Device configuration mistakes (e.g., unsecured endpoints)

#### Information security in practice

Pragmatically, organizations approach information security in terms of risk, threat, vulnerability, and mitigation. Organizations take a risk-based approach to information security management.

A standard definition of risk is the potential to lose something of value. Another definition involves the exposure to danger. In information security, risk is typically understood as threat times vulnerability times impact (the likelihood that a threat will exploit a vulnerability resulting in a business impact), or threat times vulnerability with an overlay of control effectiveness or velocity. The cybersecurity risk manager should determine what is the suitable definition. A key risk management challenge is prioritizing risk for optimal investment in countermeasures. A well-understood list of risks must be matched with a list of suitable mitigations for those risks. A risk can be accepted (evaluate if the cost of the countermeasure outweighs the possible cost of loss due to the threat), mitigated (implement safeguards and countermeasures to eliminate vulnerabilities or to block threats), or transferred (place the cost of the threat to another business function or unit) (Stewart, 2012).

A risk-based approach allows an organization to prioritize the vulnerabilities identified and focus its efforts on the risks that are the most significant to its operations. The first step in identifying business risks should be to understand the business as a society, as a social system–its identity, corporate vision, social/community relations, and values. Clause 4 of ISO 22301 calls for understanding internal and external environments, including an organization’s activities, functions, services, and the organization’s risk appetite (ISO 22301 Portal: Societal security – Business continuity management system, 2015). Businesses need to evaluate information security risks for the purposes of insurance underwriting and resource allocation; or if they are attempting to comply with HIPAA, PCI, and other regulations, they will perform a risk assessment periodically.&#x20;

Risk assessment “identifies risks generated by the possibility of threats acting on vulnerabilities, and what can be done to mitigate each one” (PCI DSS Risk Assessment Guidelines, 2005). Several major regulatory frameworks, including HIPAA, PCI, and SSAE 16, require businesses to perform periodic risk assessment.&#x20;

\<In order to simplify data governance, information **should be segregated by levels of importance and risk**, since it is very complicated to safeguard all the data in organization using the same standards … sensitive data has to be protected by more security measures in order to safeguard it. In some cases, in order to archive “defense in depth,” multiple security devices from different vendors are recommended.

A popular definition of risk management by ISO Guide 73:2009:

_In ideal risk management, a prioritization process is followed whereby the risks with the greatest loss (or impact) and the greatest probability of occurring are handled first, and risks with lower probability of occurrence and lower loss are handled in descending order. In practice the process of assessing overall risk can be difficult, and balancing resources used to mitigate between risks with a high probability of occurrence but lower loss versus a risk with high loss but lower probability of occurrence can often be mishandled._

**Acceptable risk**

After risk assessment, risks may be accepted, mitigated, or transferred (e.g., to another department or third party better equipped to manage them).

Systems can be more secure or less secure, but there is no absolute security. For example, you can implement malware detection on your network firewall and have the best antivirus software on client PCs, but the chance of the PCs getting infected with malware is never zero.&#x20;

**Security vs functionality**

Data that is not accessible to anyone may be perfectly secure, but it’s worthless to the enterprise if it cannot be seen and used.

### Other information security concepts and practices

#### The AAA framework&#x20;

AAA stands for Authentication, Authorization, and Accounting. It’s a framework for controlling and monitoring users of a computer system such as a network.

Authentication is how you control access to your network and prevent intrusions, data loss, and unauthorized users.

AAA stands for Authentication, Authorization, and Accounting. It’s a framework for controlling and monitoring users of a computer system, such as a network.

\*Authentication is the process of verifying a user’s identity. When a user logs in, ideally using multi-factor authentication, that’s authentication.

\*Authorization is the process of granting the user the appropriate access and permissions. So, granting the user access to some files and services, but restricting access to other files and services, is authorization.&#x20;

\*Accounting is the process of recording the user’s activities on the system. For example, logging when a user makes a change to a file, or recording when a user logs in or logs out, is accounting.&#x20;

Enterprises typically use an AAA server to provide AAA services. ISE (Identity Services Engine) is Cisco’s AAA server. AAA (network access control) servers typically support the following two AAA protocols: 1) RADIUS (Remote Authentication Dial-In User System), which is an open standard protocol and uses UDP ports 1812 and 1813; and 2) TACACS+ (Terminal Access Controller Access-Control System Plus), which is also an open standard (that was developed by Cisco) and uses TCP port 49.

#### Foundational cryptography concepts

The primary goals of cryptography are confidentiality, authentication, data integrity, and non-repudiation.

• Confidentiality protects information from unauthorized access.

• Authentication verifies the identity of users and the authenticity of data.

• Data integrity guarantees that information remains unaltered by unauthorized parties, ensuring its accuracy.

• Non-repudiation ensures that a party cannot later deny having performed an action (such as sending a message or approving a transaction). It provides irrefutable proof—through digital signatures, timestamps, or audit logs—that a specific user took a particular action, preventing false denials and holding parties accountable.

#### Essential cryptography terms&#x20;

<**Encryption** is a process of transforming simple text/data, called plaintext, into unintelligible form, named as ciphertext. Decryption is the inverse process of encryption. **Cipher** is an algorithm that performs encryption/decryption. A **key** is a secret string of characters or symbols that is used for the encryption/decryption of plaintext/ciphertext. Sometimes, the term **cryptosystem** is used instead of cipher. There are two types of ciphers depending on the use of keys: symmetric and asymmetric.\
**Symmetric ciphers**, also referred as secret-key ciphers, use the same key for encryption and decryption. Symmetric cryptosystems are divided into two groups: block and stream ciphers. In block ciphers, operations of encryption/decryption are performed on blocks of bits or bytes, whereas stream ciphers operate on individual bits/bytes. **Asymmetric ciphers**, alternatively named public-key ciphers, use two keys, one for encryption and other for decryption. **Cryptanalysis** is a study of techniques for “cracking” encryption ciphers, i.e., attacks on cryptosystems. And chances are you’ve heard about **hashing algorithms**, which involves taking an input of any length and outputting a fixed-length string, called a hash. Which can be used, for example, as signatures or for data-integrity purposes.>

### Key takeaways

• Tactically, cybersecurity is about protecting the CIA of information assets \
• Strategically, cybersecurity is about compliance with rules \
• Cybersecurity and information security can be synonymous \
• Organizations take a risk-based approach to cybersecurity management

### References

Blakley, B., McDermott, E., & Geer, D. (2001, September). Information security is information risk management. In Proceedings of the 2001 workshop on New security paradigms (pp. 97-104). ACM.

Shamil Alifov. (2016). How to get started in cryptography (Ch. 5). In _Beginner’s Guide To Information Security_ (pp. 27-31). Peerlyst. Retrieved from https://www.peerlyst.com/posts/peerlyst-announcing-its-first-community-ebook-the-beginner-s-guide-to-information-security-limor-elbaz
