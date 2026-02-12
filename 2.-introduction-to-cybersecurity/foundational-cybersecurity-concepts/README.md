---
description: This sections introduces core and foundational cybersecurity concepts such as the CIA triad, risk, threat, vulnerability, mitigation, and the AAA framework
---

# Foundational cybersecurity concepts

## Learning objectives

* Become familiar with key cybersecurity concepts and practices
* Learn key cybersecurity definitions
* Describe where cybersecurity fits within corporate organizational structures
* Understand how cybersecurity is practiced within organizations

This section introduces cybersecurity concepts and practices germane to any instruction aiming to establish a practical understanding of the goals of cybersecurity and how it is practiced within organizations. This section covers definitions of information security, the CIA triad, risk, threat, vulnerability, mitigation, and the AAA framework (Authentication, Authorization, and Accounting).

## Topics covered in this section

* **Information security definition**
* **The place of information security in enterprise IT governance**
* **Confidentiality, Integrity, and Availability (CIA) of information**
* **Information security risk management**
* **Techniques of CIA attacks**
* **CIA attacks mitigation technologies**
* **Other foundational information security concepts**

### Information security definition

The terms information security, cybersecurity, Internet security, computer security, and network security have intersecting and evolving meanings, but generally refer to processes of implementing security controls including IA (Information Assurance)/IT governance frameworks to protect the confidentiality, integrity, and availability of privileged information as well as the technological infrastructure of a computer network or system against unauthorized access or manipulation (Anderson, 2003; Blakley, McDermott & Geer, 2001; Cherdantseva & Hilton, 2013; CNSS, 2010; ISACA, 2008; ISO/IEC 27000:2009; Venter & Eloff, 2003).

Sensitive data should be protected based on the potential impact of a loss of confidentiality, integrity, or availability. **Confidentiality** refers to protecting information from being accessed by unauthorized parties. **Integrity** refers to ensuring the authenticity of information—that information is not altered, and that the source of the information is genuine. **Availability** of information means that information is accessible by authorized users when needed.

Information security is “a risk management discipline" (Blakley et al., 2001) focused on identifying information assets, associated risks, and suitable mitigation methods. An asset is any hardware, software, information system, network, or database which an organization uses to achieve its business goals.

Information security,

* “preserves the confidentiality, integrity and availability of information” (ISO/IEC 27000:2009);
* is concerned with “authenticity, accountability, non-repudiation and reliability” (ISO/IEC 27000:2009);
* ensures that “only authorized users (confidentiality) have access to accurate and complete information (integrity) when required (availability)” (ISACA, 2008);
* is concerned with both the protection of information as well as the of technological infrastructure or information systems (Cherdantseva & Hilton, 2013; CNSS, 2010);
* is concerned with access to information (CNSS, 201; ISACA, 2008); and
* aims to provide assurance “that information risks and controls are in balance” (Anderson, J., 2003).

Key information security concepts include privacy, authenticity and trustworthiness, non-repudiation, accountability and auditability, and reliability (Cherdantseva & Hilton, 2013; ISO/IEC 27000:2009).

The broad pragmatic goal of information security is to reduce the likelihood of unauthorized access or damage to valued information assets to an acceptable level through risk mitigation strategies that involve management controls (e.g., security policies), technological controls (e.g., intrusion detection techniques), and procedural/operational controls (best practices/standard operating procedures).

Information security threats most commonly rated as a concern in higher education in North America are as follows. Confidentiality attacks: Exposure of confidential or sensitive information (79%); Integrity attacks: Unauthorized or accidental modification of data (29%); Availability attacks: Loss of availability or sabotage of systems (16%); Mixed threat attacks: Email viruses, ransomware, or other malware (31%); and Unauthorized, malicious network/system access (27%) (EDUCAUSE Information Security Almanac, April 2019, p. 2).

### The place of information security in enterprise IT governance

Information systems (IS) are comprised of hardware, software, and communications infrastructure, designed to process, store, and transmit data. Within this context, information security is the specialized discipline focused on protecting the confidentiality, integrity, and availability (CIA) of that data against unauthorized access, disclosure, disruption, or damage "at three levels or layers: Physical, personal and organizational” (Cherdantseva & Hilton, 2013).

To understand the place of information security in enterprise IT governance, we must first distinguish between governance and management. Governance is the system of direction and control. Information security governance is a top-level enterprise business function, operating under the broader rubric of IT governance (e.g., COBIT, ISO 38500), responsible for defining security strategy, establishing policy, and ensuring that security investments align with business objectives. 

In comparison, IT security (often referred to as security management or operations) is the technical and administrative function responsible for implementing that strategy. IT security professionals execute controls, monitor systems, manage identities, and maintain the technological infrastructure. Therefore, contrary to a service-oriented model, the IT department is not a customer of the security governance function. Rather, IT is the primary execution partner and control implementer. While Human Resources or Finance are business customers who consume security services (e.g., access recertification), the IT organization is the subject of governance oversight, responsible for operationalizing policy within the network and systems architecture.

This distinction is codified in the separation of duties common in mature enterprises. Governance sets the risk appetite and policy framework; IT security operationalizes controls to keep the organization within that appetite. This is evidenced by the 2019 EDUCAUSE Information Security Almanac, which notes that central IT holds primary responsibility for technical domains such as Network security (94%), Monitoring (88%), and Identity management (83%).

The relationship between information security and IT governance can be visualized through the **three-tier governance model** frequently cited in risk management frameworks (NIST SP 800-39, ISO 27001). At the top tier (Tier 1), enterprise governance defines the organizational risk tolerance and strategic direction. Information security governance translates this enterprise view into specific security principles and a formal security program charter.

At the middle tier (Tier 2), these policies are interpreted into specific business process requirements and system-level control objectives. This is where *risk management* acts as the bridge. IT security professionals conduct risk assessments (qualitative and quantitative) to identify gaps between current operational states and the governance-mandated policy. The results of these assessments flow up to governance to inform policy updates, and flow down to IT operations to drive control selection (e.g., technical safeguards, intrusion detection systems, encryption standards).

At the operational tier (Tier 3), IT security implements and monitors controls. However, a key CISSP principle is that security governance retains **accountability** even when operational control is delegated. This is achieved through continuous monitoring and formal reporting mechanisms (e.g., Balanced Scorecards, KRIs). Thus, information security governance is not merely a support function for IT; it is an integrated component of **enterprise governance**, ensuring that cyber risk is treated with the same fiduciary gravity as financial or legal risk. This integration prevents security from being viewed as a technical obstacle and repositions it as an enabler of informed business risk-taking.

### Confidentiality, Integrity, and Availability (CIA) of information

The most concrete (as opposed to abstract) and tactical (as opposed to strategic) goal of information security is the protection of the confidentiality, integrity, and availability of information assets. By comparison, the most strategic goal of information security in an enterprise is to support the enterprise's strategic vision and mission. The principles of the CIA triad form the foundation of security. These three principles help ensure that data is protected, accurate, and accessible when needed.

* Confidentiality denotes an imperative that only authorized users should be able to access privileged/private data.
* Integrity denotes an imperative that data should not be changed or modified by unauthorized users. Data should be correct and authentic.
* Availability denotes an imperative that an information system should be operational and accessible to authorized users. For example, staff should be able to access the internal resources they need to perform their duties, and the company’s website should be up and running and available to customers.

In addition to the CIA triad, closely related and foundational information security concepts include:

* A vulnerability is any potential weakness that can compromise the CIA of information assets. A window in a house is a vulnerability burglars can exploit to enter the house.
* An exploit is something that can potentially be used to exploit the vulnerability. A rock can exploit the weakness of glass windows and may be used to enter a house.
* A threat is the potential of a vulnerability to be exploited. The threat of house burglary is the potential a burglar will exploit the glass window vulnerability using a rock (or other exploits) to gain entry into a house.
* A threat vector is a means or method a threat actor can use or follow to exploit a vulnerability. A glass window a burglar can use to gain entry into a house can be considered a threat vector.
* A mitigation technique is something that can protect against threats. Appropriate mitigation techniques should be implemented everywhere a vulnerability can be exploited, for example, devices, servers, switches, and routers. In our window example, adding welded metallic bars would be a mitigation technique.

### Information security risk management

Risk management requires understanding **threats, vulnerabilities, and mitigation** strategies.

* **Risk = Threat × Vulnerability (with consideration of mitigation)**
* A risk arises when a threat exploits a vulnerability.
* Related concepts: **exploit** (how the attack happens) and **threat vector** (the pathway of the attack).

Risk is “a threat that exploits some vulnerability that could cause harm to an asset” (Peltier, 2005, p.16). “One instance of risk within a system is represented by the formula (asset\*threat\*vulnerability)” (Landoll & Landoll, 2005, p. 8).

The Risk Management Guide of the National Institute of Standards and Technology defines risk assessment as “the process of identifying the risks to system security and determining the probability of occurrence, the resulting impact, and additional safeguards that would mitigate this impact” (Landoll & Landoll, 2005, p. 10).

According to the General Security Risk Assessment Guidelines, ASIS International (2003), the basic components of a risk assessment plan include, identifying assets, specifying loss events (threats), assessing the frequency and impact of events, recommending mitigation options, conducting a cost/benefit analysis, and making decisions.

**Sources of Vulnerabilities**

Computer system vulnerabilities can be categorized based on their origin:

* **Software infrastructure:** Flaws in applications, operating systems, or firmware.
* **Network infrastructure:** Weaknesses in network devices, network protocols, or configurations.
* **Hardware:** Physical security flaws or insecure device designs.
* **Organizational and network policies:** Poorly defined security policies that create security gaps.
* **Human factors:** Susceptibility to social engineering or lack of security awareness.
* **Configuration mistakes:** Unsecured endpoints, default passwords, or misconfigured devices.

#### Information security in practice

Pragmatically, organizations approach information security in terms of risk, threat, vulnerability, and mitigation. Organizations take a risk-based approach to information security management.

A standard definition of risk is the potential to lose something of value. Another definition involves the exposure to danger. In information security, risk is typically understood as threat times vulnerability times impact (the likelihood that a threat will exploit a vulnerability resulting in a business impact), or threat times vulnerability with an overlay of control effectiveness. The cybersecurity risk manager should determine what is the suitable definition of risk.

A risk-based approach allows an organization to prioritize the vulnerabilities identified and focus its efforts on the risks that are the most significant to its operations. The first step in identifying business risks should be to understand the business as a social system—its identity, corporate vision, social/community relations, and values. Clause 4 of ISO 22301 calls for understanding internal and external environments, including an organization’s activities, functions, services, and the organization’s risk appetite (ISO 22301 Portal: Societal security – Business continuity management system, 2015). Businesses need to evaluate information security risks for the purposes of insurance underwriting and resource allocation; or if they are attempting to comply with HIPAA, PCI, and other regulations, they will perform a risk assessment periodically.

Risk assessment “identifies risks generated by the possibility of threats acting on vulnerabilities, and what can be done to mitigate each one” (PCI DSS Risk Assessment Guidelines, 2005). Several major regulatory frameworks, including HIPAA, PCI, and SSAE 16, require businesses to perform periodic risk assessment. As such, risk assessments are usually performed in the context of compliance with standards or regulations.

In order to properly secure data, an organization should develop clear and precise standards of data classification. To simplify data governance, information should be segregated by levels of importance and risk, since it is impractical to safeguard all the data in an organization using the same standards. Sensitive data should be protected by more security measures in order to safeguard it.

A key risk management challenge is prioritizing risk for optimal investment in countermeasures. A well-understood list of risks must be matched with a list of suitable mitigations for those risks. ISO Risk Management Guide 73:2009 defines risk management as follows:

In ideal risk management, a prioritization process is followed whereby the risks with the greatest loss (or impact) and the greatest probability of occurring are handled first, and risks with lower probability of occurrence and lower loss are handled in descending order. In practice the process of assessing overall risk can be difficult, and balancing resources used to mitigate between risks with a high probability of occurrence but lower loss versus a risk with high loss but lower probability of occurrence can often be mishandled.

**Acceptable risk**

In the context of assessing information security risk, risk level is assessed (scored) based on likelihood and impact - meaning, the higher the probability of an attack or breach, the higher the risk; and the higher the potential impact of an attack or breach, the higher the risk.

Risk assessments outlines what threats exist to specific assets and the associated risk levels. Risk mangers use risk levels to select appropriate security defenses and countermeasures to lower the risk to an acceptable level (Engebretson, 2011; Landoll & Landoll, 2005; Peltier, 2005).

After a risk assessment, a risk can be accepted (this involves an evaluation of whether the cost of countermeasures outweighs the potential cost of loss due to the threat), mitigated (this involves implementing safeguards and countermeasures to eliminate vulnerabilities or to block threats), or transferred (this involves transferring the cost of the threat to another business function or unit) (Stewart, 2012).

The goal of risk assessment is “to identify which investments of time and resources will best protect the organization from its most likely and serious threats” (Reynolds, 2012, p. 103).

Systems can be more secure or less secure, but there is no absolute security. For example, you can implement malware detection on your network firewall and have the best antivirus software on client PCs, but the chance of the PCs getting infected with malware is never zero.

**Security vs functionality**

Data that is not accessible to anyone may be perfectly secure, but it’s worthless to an enterprise if it cannot be seen and used. A security access policy is always trying to balance security and functionality (or access privileges).

### Techniques of CIA attacks

#### Confidentiality attacks

A confidentiality attack is a type of cyberattack aimed at gaining unauthorized/unlawful access to privileged/private information. These attacks exploit vulnerabilities in systems, networks, or human behavior to access confidential data such as personal records, financial details, or trade secrets. Common attack techniques that compromise confidentiality include:

1. **Packet sniffing (packet capture):** Attackers intercept and analyze network traffic to extract sensitive information (e.g., using tools like Wireshark or tcpdump). For example, an attacker on an unsecured Wi-Fi network could capture unencrypted login credentials.
2. **Port scanning:** Attackers scan a target system’s open ports (e.g., using Nmap) to identify vulnerable services. While port scanning itself does not directly steal data, it is often a precursor to exploitation (e.g., targeting an open SSH port to brute-force a password).
3. **Wiretapping (eavesdropping):** Attackers secretly monitor communications, such as phone calls (traditional wiretapping) or unencrypted VoIP traffic. Modern variants include man-in-the-middle (MITM) attacks, where an attacker intercepts and possibly alters data exchanged between two parties.
4. **SQL injection:** Malicious code is injected into a database query to extract unauthorized information from a vulnerable system.
5. **SSL/TLS stripping (HTTPS downgrade)**
   * Technique: An attacker forces a victim’s browser to downgrade an encrypted HTTPS connection to unencrypted HTTP using tools like sslstrip.
   * Impact: Login credentials or session cookies are transmitted in plaintext, allowing interception (e.g., on public Wi-Fi).

These techniques undermine confidentiality by exposing data to unauthorized entities, whether through passive interception (e.g., sniffing) or active exploitation (e.g., credential theft).

#### Integrity attacks

An information integrity attack is a malicious attempt to alter, modify, or corrupt data to deceive users, disrupt operations, or cause harm. The goal is to make data inaccurate or unreliable. Information sabotage through viruses, malware, or unauthorized modifications constitutes an integrity attack, as it compromises the accuracy, consistency, and reliability of data (Bishop, 2003; Pfleeger & Pfleeger, 2015). Common attack techniques that compromise integrity include:

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

### CIA attacks mitigation technologies

#### **Technologies for Confidentiality, Integrity, and Availability**

| **Security Objective** | **Key Technologies**                                                                                                                                                                                                                                                   | **Purpose**                                      | **Notes**                                                    |
| ---------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------ | ------------------------------------------------------------ |
| **Confidentiality**    | <p>Data Loss Prevention (DLP)</p><p><br>Encryption (AES, TLS, PGP)</p><p><br>Access Controls (IAM, RBAC, AAA)</p><p><br>Tokenization</p><p><br>SIEM</p><p>Backups</p><p>Rate Limiting (prevents brute-force attacks)</p>                                               | Protects data from unauthorized access and leaks | SIEM provides monitoring for all three pillars               |
| **Integrity**          | <p>Hashing (SHA-256, HMAC)</p><p><br>Digital Signatures</p><p><br>Version Control (Git, SVN)</p><p><br>SIEM + Centralized Logging</p><p><br>Access Controls (audit logs track changes)</p><p><br>Backups (ensure clean restore points)</p>                             | Ensures data accuracy and prevents tampering     | Access controls support integrity through audit trails       |
| **Availability**       | <p>DDoS Protection (Cloudflare, AWS Shield)</p><p>Backups (recovery, 3-2-1 Rule, immutable backups)</p><p><br>Load Balancers (Nginx, F5)</p><p><br>High Availability systems</p><p><br>SIEM</p><p><br>Access Controls (MFA)</p><p><br>Rate Limiting (secures APIs)</p> | Maintains system uptime and access               | Rate limiting protects both availability and confidentiality |

See [CIA attacks mitigation technologies](cia-attacks-mitigation-technologies.md)

#### Confidentiality mitigation technology in focus: Data Loss Prevention (DLP)

A key technology for ensuring data confidentiality is Data Loss Prevention (DLP), which monitors and protects sensitive information by detecting and blocking unauthorized transfers. For instance, DLP can trigger alerts if confidential files are copied to removable drives or if payment card data is shared improperly. While highly effective, DLP requires careful configuration—including accurate data classification and tailored alert rules—to maximize its security value.

**How DLP Monitors and Blocks Unauthorized Data Transfers**

1. **Content-Centric Detection**\
   DLP systems scan data **at rest** (e.g., databases), **in use** (e.g., open files), and **in motion** (e.g., emails, cloud uploads) for sensitive content. DLP systems use techniques like:
   * **Pattern matching** (e.g., credit card/PII regex).
   * **File fingerprinting** (e.g., exact matches of proprietary designs).
   * **Machine learning** (e.g., identifying confidential documents by context).
2. **Policy-Driven Blocking**\
   When DLP detects policy violations (e.g., an employee attaching customer data to an external email), it can:
   * **Block** the action outright (like preventing file copies to USB).
   * **Quarantine** the data for review.
   * **Encrypt** sensitive content mid-transfer.
3. **Targeted Alerting**\
   DLP generates specific alerts for policy breaches (e.g., "Unauthorized SharePoint export of HR records"). These alerts can:
   * Feed into broader security systems (e.g., SIEMs for correlation).
   * Trigger automated workflows (e.g., notifying compliance teams).

DLP operates at the data layer—understanding content, not just traffic or behavior—making it uniquely effective against insider threats and accidental leaks.

**Open-Source & Freemium DLP Tools**

1. **MyDLP** (Community Edition)
   * Network/email DLP with basic policies (e.g., credit card detection).
2. **OpenDLP**
   * Scans endpoints for sensitive files (no real-time blocking).
3. **Spyderbat** (Behavioral DLP)
   * Open-source runtime monitoring for data exfiltration.
4. **Apache Nifi** + **Regex Policies**
   * Custom DIY DLP using workflows to filter sensitive data in transit.

**Commercial DLP Solutions**

1. **Symantec Data Loss Prevention (Broadcom)**
   * Comprehensive coverage (network, endpoint, cloud).
   * Strong regulatory compliance (GDPR, HIPAA, PCI-DSS).
2. **Microsoft Purview Data Loss Prevention**
   * Native integration with M365, Azure, and Windows endpoints.
   * Uses AI for content classification (e.g., sensitive docs in SharePoint).
3. **Forcepoint DLP**
   * Focuses on behavioral analytics (e.g., detects risky user actions).
   * Supports hybrid cloud/on-prem deployments.
4. **Digital Guardian**
   * Endpoint-centric with advanced threat response (blocks USB/exfiltration).

**Cloud-Native & Integrated Tools**

* **Google Workspace DLP** (for Gmail/Drive)
* **AWS Macie** (ML-based S3 data classification)
* **Nightfall.ai** (API-driven DLP for SaaS apps)

#### Integrity mitigation technology in focus: Centralized logging

Several centralized logging technologies can enhance security and compliance by aggregating logs from multiple sources for monitoring, analysis, and auditing. Some key solutions include:

**1. SIEM (Security Information and Event Management) Systems**

* **Splunk** – Powerful log aggregation, real-time analysis, and alerting.
* **IBM QRadar** – Combines logs with threat intelligence for security monitoring.
* **Microsoft Sentinel** – Cloud-native SIEM with AI-driven threat detection.
* **Elastic SIEM (Elastic Stack / ELK Stack)** – Open-source option using **Elasticsearch, Logstash, and Kibana (ELK)** for log parsing and visualization.

**2. Log Management & Analytics Platforms**

* **Graylog** – Open-source log aggregation with alerting and dashboards.
* **Datadog** – Cloud-based monitoring with log correlation and APM.
* **Sumo Logic** – SaaS-based log analytics with machine learning insights.
* **Fluentd / Fluent Bit** – Lightweight log collectors that integrate with other tools.

**3. Cloud-Native & Enterprise Solutions**

* **AWS CloudTrail + Amazon CloudWatch Logs** – For AWS environments.
* **Google Cloud Logging** – Centralized logging for GCP services.
* **Azure Monitor Logs** – Log analytics for Microsoft Azure.
* **Syslog-ng / Rsyslog** – Traditional Unix-based log forwarders.

**Key Features to Look For:**

* **Real-time log aggregation** (from servers, applications, network devices).
* **Retention & compliance** (long-term storage for audits).
* **Search & analytics** (to detect anomalies or breaches).
* **Alerting & automation** (trigger responses to suspicious activity).

**Free/Open-Source vs. Commercial Tools**

| Category                       | Tool Name                       | Type            | Notes                                                                                                                   |
| ------------------------------ | ------------------------------- | --------------- | ----------------------------------------------------------------------------------------------------------------------- |
| **SIEM Systems**               | **Splunk**                      | **Commercial**  | Powerful commercial platform. A free version (Splunk Free) exists with a daily data cap.                                |
|                                | **IBM QRadar**                  | **Commercial**  | Enterprise-grade commercial SIEM.                                                                                       |
|                                | **Microsoft Sentinel**          | **Commercial**  | Cloud-native SaaS solution, billed based on data ingestion.                                                             |
|                                | **Elastic SIEM (ELK Stack)**    | **Open Source** | The core Elasticsearch, Logstash, and Kibana stack is open-source. Elastic offers paid commercial features and support. |
| **Log Management & Analytics** | **Graylog**                     | **Open Source** | The core Graylog product is open-source. An enterprise version with advanced features is available.                     |
|                                | **Datadog**                     | **Commercial**  | Commercial SaaS platform with usage-based pricing.                                                                      |
|                                | **Sumo Logic**                  | **Commercial**  | Commercial SaaS platform with usage-based pricing.                                                                      |
|                                | **Fluentd / Fluent Bit**        | **Open Source** | Cloud-native CNCF-graduated open-source projects.                                                                       |
| **Cloud-Native & Enterprise**  | **AWS CloudTrail + CloudWatch** | **Commercial**  | Part of AWS's paid ecosystem. Pricing is based on events and log storage.                                               |
|                                | **Google Cloud Logging**        | **Commercial**  | Part of GCP's paid ecosystem. Includes a free tier with monthly allowances.                                             |
|                                | **Azure Monitor Logs**          | **Commercial**  | Part of Microsoft Azure's paid ecosystem. Billed based on data ingestion and retention.                                 |
|                                | **Syslog-ng / Rsyslog**         | **Open Source** | Standard, free, and open-source log forwarders available on most Unix/Linux systems.                                    |

#### Clarifications:

* **Freemium Models:** Several tools listed as "Commercial" (like Splunk, Datadog, and the cloud platforms) offer generous free tiers or free plans for low-volume use, but their full-featured enterprise versions are paid services.
* **Open Core Models:** Tools like **Elastic SIEM** and **Graylog** have strong open-source cores. However, the companies behind them also sell commercial extensions (like advanced security features, supported plugins, and professional support), which is a common business model in the open-source world.
* **Cloud Services:** While the underlying technology of tools like Fluentd is open source, the managed services from AWS, GCP, and Azure (**CloudWatch, Google Cloud Logging, Azure Monitor**) are commercial products.

#### Availability mitigation technology in focus: DDoS protection services (e.g., AWS Shield, Cloudflare)

Data can become unavailable due to being damaged or destroyed, or due to ransomeware or dormant malware. Unlike confidentiality or integrity attacks, availability attacks aim primarily to disrupt service rather than steal or alter data. Mitigation strategies include rate limiting, traffic filtering, and cloud-based DDoS protection services (e.g., AWS Shield, Cloudflare).

Availability attacks, such as Distributed Denial of Service (DDoS) attacks, aim to disrupt services by overwhelming systems with malicious traffic, rendering data or applications inaccessible. To counter these threats, organizations leverage cloud-based DDoS protection services like **AWS Shield** and **Cloudflare**, which employ advanced mitigation techniques such as traffic filtering, rate limiting, and anomaly detection. AWS Shield provides automatic protection for AWS resources, defending against common network-layer attacks, while Cloudflare’s global Anycast network absorbs and disperses malicious traffic before it reaches the target. These services ensure high availability by continuously monitoring and mitigating attack traffic, allowing legitimate requests to proceed uninterrupted. By integrating such solutions, businesses can maintain operational resilience against increasingly sophisticated DDoS campaigns.

### Other foundational information security concepts

#### The AAA framework

AAA stands for Authentication, Authorization, and Accounting. It’s a framework for controlling and monitoring users of a computer system such as a network.

* Authentication is the process of verifying a user’s identity. When a user logs in, ideally using multi-factor authentication, that’s authentication. In other words, Authentication is how you control access to your network and prevent intrusions, data loss, and unauthorized users.
* Authorization is the process of granting the user the appropriate access and permissions. So, granting the user access to some files and services, but restricting access to other files and services, is authorization.
* Accounting is the process of recording the user’s activities on the system. For example, logging when a user makes a change to a file, or recording when a user logs in or logs out, is accounting.

Enterprises typically use an AAA server to provide AAA services. ISE (Identity Services Engine) is Cisco’s AAA server. AAA servers typically support the following two AAA protocols for network access control: 1) RADIUS (Remote Authentication Dial-In User System), which is an open standard protocol and uses UDP ports 1812 and 1813; and 2) TACACS+ (Terminal Access Controller Access-Control System Plus), which is also an open standard (that was developed by Cisco) and uses TCP port 49.

#### Foundational cryptography concepts

The primary goals of cryptography are confidentiality, authentication, data integrity, and non-repudiation.

* Confidentiality protects information from unauthorized access.
* Authentication verifies the identity of users and the authenticity of data.
* Data integrity guarantees that information remains unaltered by unauthorized parties, ensuring its accuracy.
* Non-repudiation ensures that a party cannot later deny having performed an action (such as sending a message or approving a transaction). It provides irrefutable evidence—through digital signatures, timestamps, or audit logs—that a specific user took a particular action, preventing false denials and holding parties accountable.

### Key takeaways

* The core, tactical goal of information security is to protect the Confidentiality, Integrity, and Availability (CIA Triad) of information assets.
* Information security is a risk management discipline focused on identifying assets, associated risks, and implementing suitable mitigation controls (management, technical, and operational).
* Key related concepts form the foundation of risk management:
  * A vulnerability is a weakness that can be exploited.
  * A threat is the potential for a vulnerability to be exploited.
  * Risk is the likelihood that a threat will exploit a vulnerability, resulting in a negative impact.
* Organizations take a risk-based approach to prioritize vulnerabilities and focus mitigation efforts on the most significant risks to business operations, often driven by compliance requirements.
* Information security governance is a top-level business function accountable for defining security policy and aligning security strategy with business objectives, while IT security is a stakeholder-level concern focused on the technological infrastructure.
* There is no absolute security; the goal is to reduce risk to an acceptable level through mitigation, acceptance, or transfer, while balancing security needs with system functionality.
* The AAA framework (Authentication, Authorization, and Accounting) is essential for controlling and monitoring access to systems and data.
* Foundational cryptography provides the technical mechanisms to achieve the core security goals of confidentiality, integrity, authentication, and non-repudiation.

### References

Anderson, J. M. (2003). Why we need a new definition of information security. _Computers & Security. 22_ (4): 308–313. doi:10.1016/S0167-4048(03)00407-3.

ASIS International. (2003). _General Security Risk Assessment Guidelines._

Bishop, M. (2003). _Computer security: art and science_. Addison-Wesley Professional.

Blakley, B., McDermott, E., & Geer, D. (2001, September). Information security is information risk management. In _Proceedings of the 2001 workshop on New security paradigms_ (pp. 97-104). ACM.

Cherdantseva, Y. & Hilton, J. (2013). Information security and information assurance. The discussion about the meaning, scope and goals. In: _Organizational, Legal, and Technological Dimensions of Information System Administrator._ Almeida F., Portela, I. (eds.). IGI Global Publishing.

CNSS (Committee on National Security Systems). (2010). National Information Assurance (IA) Glossary, CNSS Instruction No. 4009, 26 April 2010.

EDUCAUSE Information Security Almanac 2019. (April 10, 2019). Retrieved January 21, 2020, from https://library.educause.edu/resources/2019/4/the-educause-information-security-almanac-2019

Engebretson, P. (2011). _The basics of hacking and penetration testing: Ethical hacking and penetration testing made easy_. \[Books24x7 version] Retrieved March 26, 2013, from http://common.books24x7.com.proxy.bib.uottawa.ca/toc.aspx?bookid=44730

ISACA. (2008). Glossary of terms, 2008. Retrieved January 21, 2020, from http://www.isaca.org/Knowledge-Center/Documents/Glossary/glossary.pdf

ISO/IEC 27000:2009. _Information technology — Security techniques — Information security management systems — Overview and vocabulary._

ISO 22301 Portal. (2015). _Societal security – Business continuity management system._

ISO Risk Management Guide. (2009). _Risk management — Vocabulary_ (ISO Guide 73:2009).

Landoll, D. J., & Landoll, D. (2005). _The security risk assessment handbook: A complete guide for performing security risk assessments._ CRC Press.

NCC (National Computing Centre). (2005). IT Governance: Developing a Successful Governance Strategy (published by ISACA). Retrieved August 20, 2019, from http://m.isaca.org/Certification/CGEIT-Certified-in-the-Governance-of-Enterprise-IT/Prepare-for-the-Exam/Study-Materials/Documents/Developing-a-Successful-Governance-Strategy.pdf

PCI DSS. (2005). _PCI DSS Risk Assessment Guidelines_. Retrieved from https://www.pcisecuritystandards.org/

Peltier, T. R. (2005). _Information Security Risk Analysis_ (2nd ed.). Auerbach Publications.

Pfleeger, C. P., & Pfleeger, S. L. (2015). _Analyzing computer security: A threat/vulnerability/countermeasure approach_ (5th ed.). Pearson Education.

Reynolds, G. W. (2012). _Ethics in information technology_. Boston, MA: Cengage Learning.

Skoudis, E., & Liston, T. (2005). _Counter hack reloaded: A step-by-step guide to computer attacks and effective defenses_ (2nd ed.). Prentice Hall.

Stallings, W., & Brown, L. (2018). _Computer security: Principles and practice_ (4th ed.). Pearson.

Stewart, J. (2012). CISSP Certified Information Systems Security Professional Study Guide Sixth Edition. Canada: John Wiley & Sons, Inc. pp. 255–257. ISBN 978-1-118-31417-3.

Venter, H. S., & Eloff, J. H. (2003). A taxonomy for information security technologies. _Computers & Security, 22(_&#x34;), 299-307.

Whitman, M. E., & Mattord, H. J. (2014). Principles of information security (p. 656). Boston, MA: Thomson Course Technology.
