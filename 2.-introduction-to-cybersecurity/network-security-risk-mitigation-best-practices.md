---
description: >-
  This section discusses network security risk mitigation best practices,
  including least privilege access control, network monitoring, incident
  response management, and layered security
---

# Network security risk mitigation best practices

## Learning objectives

* List and describe key network security risk mitigation best practices
* Develop an appreciation for the conceptual overlap between risk mitigation approaches
* Develop an appreciation for the need for a layered approach to cybersecurity
* Identify the need for a system's view of cybersecurity management

This section reviews common network security risk mitigation best practices, including least privilege access control, on time software patching, multi-factor authentication, network monitoring, incident response and disaster recovery, and layered security (defense in depth).

## Topics covered in this section

* **Least privilege access control**
* **Multi-factor authentication**
* **Network monitoring**&#x20;
* **Layered security (defense in depth)**
* **Incident response and disaster recovery**
* **Using multiple vendors**
* **Quality assurance**
* **Timely software patching**&#x20;
* **Physically securing the network**

### Least privilege access control

The principle of least privilege rules that only the necessary and sufficient level of access privilege is granted to each authorized user or user group. Establishing and enforcing the least-privilege principle for access management and access control is the principal preventive measure against insider threats. Giving users the least amount of access they need to do their jobs enhances data security because it limits what they can accidentally or deliberately access and ensures that if their passwords are compromised, a hacker does not have all keys to the kingdom.

It is easier to stay secure by enabling access when needed than to revoke and mitigate damage after an incident.&#x20;

\<In order to properly secure data, an organization should develop clear and precise standards of data classification. Usually data access is governed via a data-access control scheme. A simple and sound way to develop one is using **role-based access control (RBAC)**.>

Employee access to data should be on a need-to-know basis. In addition, procedures should be set up to ensure immediate permission removal in the case of termination or role change for an employee.

#### Implementing Robust Access Controls

**Identity and Access Management**

Identification, authentication, authorization, accounting, and identity management.

A critical aspect of network (re)design is enforcing strict access controls to prevent unauthorized entry. Role-based access control (**RBAC**) ensures that users and devices only have permissions necessary for their functions, minimizing insider threats and credential misuse. Multi-factor authentication (MFA) adds an extra layer of security, requiring additional verification beyond passwords. Additionally, network administrators should regularly audit access logs and revoke unnecessary privileges to maintain a least-privilege environment.

Best practices for access control in network design:

* **Least Privilege Principle**: Granting minimal access required for users to perform their duties.
* **Multi-Factor Authentication (MFA)**: Mandating multiple verification steps for sensitive systems.
* **Continuous Monitoring**: Using SIEM (Security Information and Event Management) tools to detect anomalies. Access to data and modification of data has to be logged and recorded in the central SIEM system. A SIEM system consumes multiple logs and allows those handling security to connect the dots and create a big picture that gives insight into multiple events. For example, it can draw attention to a user who sends abnormal amounts of data outbound, or one who connects to an unusual amount of servers.
* **Automated Policy Enforcement**: Deploying solutions like NAC (Network Access Control) to validate device compliance before granting access.

**Network Access Control (NAC)** restricts network access to only those devices that comply with security policies, such as having up-to-date antivirus or OS patches. Non-compliant devices may be blocked, quarantined, or automatically remediated (e.g., by redirecting to a patch server). NAC works best in tightly controlled environments like corporate offices or government networks but can be challenging in dynamic settings like hospitals or universities, where device types and users change frequently, which complicates policy enforcement.

**Examples of NAC Technologies:**

* **Open Source:**
  1. **PacketFence** – A widely used open-source NAC that enforces policies via VLAN assignment, captive portals, and device profiling.
  2. **FreeRADIUS** – A flexible authentication server often integrated with NAC to control network access via protocols like 802.1X.
* **Commercial:**
  1. **Cisco ISE (Identity Services Engine)** – A leading enterprise NAC solution that enforces policies, profiles devices, and automates threat responses.
  2. **Aruba ClearPass** – A policy-based NAC platform that supports BYOD, IoT security, and dynamic role-based access.

**NAC vs Identity and Access Management (IAM)**

**Network Access Control (NAC)** and **Identity and Access Management (IAM)** are both security frameworks, but they serve different purposes and operate at different layers of IT infrastructure. Here’s how they differ, with concrete examples:

**1. Primary Focus**

* **NAC** → Controls **device access to the network** based on compliance (e.g., antivirus status, OS patches).
  * _Example:_ A hospital blocks an unpatched laptop from connecting to the network until it updates its OS.
* **IAM** → Manages **user identities and their access to systems/applications** (e.g., logins, permissions).
  * _Example:_ An employee uses single sign-on (SSO) to access Salesforce but is denied entry to the HR system due to their role.

**2. Scope of Enforcement**

* **NAC** operates at the **network layer** (ports, VLANs, Wi-Fi).
  * _Tools:_ Cisco ISE, Aruba ClearPass, PacketFence.
  * _Use case:_ A university grants students Wi-Fi access only after their devices pass an antivirus check.
* **IAM** operates at the **application/cloud layer** (user logins, APIs, databases).
  * _Tools:_ Okta, Microsoft Entra ID (Azure AD), Keycloak.
  * _Use case:_ A contractor can log in to Google Workspace but can’t access the company’s AWS admin console.

**3. Key Functions**

| **NAC**                                      | **IAM**                                              |
| -------------------------------------------- | ---------------------------------------------------- |
| Authenticates _devices_                      | Authenticates _users_                                |
| Checks device health (e.g., firewall status) | Manages roles/permissions (e.g., "Read-only" access) |
| Assigns VLANs or restricts network segments  | Enforces multi-factor authentication (MFA)           |
| Often uses 802.1X, MAC filtering             | Uses SAML, OAuth, OpenID Connect                     |

**4. Overlap & Integration**

Modern systems often combine both:

* A **NAC** (like Cisco ISE) might integrate with an **IAM** (like Microsoft Entra ID) to enforce:
  * _Step 1:_ Device compliance (NAC) → "Is your laptop patched?"
  * _Step 2:_ User authentication (IAM) → "Is this employee allowed to use the finance app?"

**Example:** A bank might use:

* **NAC** to block a teller’s personal tablet from the corporate network.
* **IAM** to ensure the same teller can’t approve transactions in the banking software.

**When to Use Which?**

* **Use NAC** when you need to:
  * Secure network ports/Wi-Fi against rogue devices.
  * Enforce endpoint compliance (e.g., HIPAA-mandated encryption).
* **Use IAM** when you need to:
  * Manage user access to cloud apps (e.g., SaaS like Slack).
  * Implement least-privilege access (e.g., "Developer" vs. "Admin" roles).

Think of it this way: NAC guards the _network door_ (devices), while IAM guards the _application doors_ (users). Both are critical for Zero Trust security.

### Multi-factor authentication

No matter how secure the password, there is still a chance it gets into the hands of an attacker. That’s why multi-factor authentication is becoming more and more wide-spread.

Multi-factor authentication involves using at least two authentication methods from at least two of the following categories to prove your identity.

First is something you know, for example a username and password combination.

Next is something you have, for example pressing a notification that appears on your phone using an authenticator app, or using a badge that is scanned.

The third is something you are, these are unique characteristics about you. For example, biometrics such as a face scan, palm scan, fingerprint scan, retina scan, etc.&#x20;

#### Enhancing Visibility and Threat Detection

A secure network design must incorporate robust monitoring to detect and respond to threats in real time. Deploying intrusion detection and prevention systems (IDS/IPS) helps identify malicious activity, while endpoint detection and response (EDR) solutions track suspicious behavior across devices. Network traffic analysis (NTA) tools provide visibility into data flows, helping detect lateral movement by attackers. By integrating these technologies, organizations can proactively identify vulnerabilities and mitigate risks before they escalate.

Essential tools for improved network visibility:

* **Intrusion Detection/Prevention Systems (IDS/IPS)**: Monitoring for and blocking malicious traffic.
* **Endpoint Detection and Response (EDR)**: Analyzing endpoint activities for signs of compromise.
* **Network Traffic Analysis (NTA)**: Identifying unusual patterns that may indicate an attack.
* **SIEM Solutions**: Aggregating and correlating logs for centralized threat detection.

### Network monitoring

Network security monitoring is a broad term that encompasses various techniques and tools for detecting and responding to security threats. A robust network security monitoring strategy often combines IDS/IPS (Intrusion Detection System/Intrusion Prevention System) to detect/block known malicious traffic, SIEM (Security Information and Event Management) to correlate alerts from IDS, firewalls, endpoints, etc., EDR/XDR (Endpoint Detection and Response/Extended Detection and Response) to detect advanced endpoint threats, and NTA (Network Traffic Analysis) to detect unusual lateral movement.

#### Intrusion Detection Systems (IDS)

An IDS is a device or software application that monitors a network or systems for malicious activity or policy violations. Any intrusion activity or violation is typically either reported to an administrator or collected centrally using a security information and event management (SIEM) system. A SIEM system combines outputs from multiple sources and uses alarm filtering techniques to distinguish malicious activity from false alarms. (Wikipedia)

IDS types range in scope from single computers to large networks. The most common classifications are network intrusion detection systems (NIDS) and host-based intrusion detection systems (HIDS). (Wikipedia)

A **Network Intrusion Detection System (NIDS)** is a security mechanism that monitors network traffic for malicious activity or policy violations by analyzing packet headers and payloads, using signature-based detection (known threats) or anomaly-based detection (deviations from baseline behavior). It operates in passive mode, alerting administrators without directly blocking traffic (unlike an IPS). A NIDS can be deployed inline (span port) or via network taps, leveraging protocols like Deep Packet Inspection (DPI) for enhanced threat detection. By comparison, a **Host-Based Intrusion Detection System (HIDS)** monitors important operating system files. An HIDS is capable of monitoring and analyzing the internals of a computing system as well as the network packets on its network interfaces.

**Network Intrusion Detection System (NIDS)**

NIDS can be classified based on their detection approach. The most well-known variants are signature-based detection (recognizing bad patterns, such as exploitation attempts) and anomaly-based detection (detecting deviations from a model of "good" traffic, which often relies on machine learning). Another common variant is reputation-based detection (recognizing the potential threat according to the reputation scores). (Wikipedia)

**A. Signature-Based Detection (IDS/IPS)**

* **Example Tools:** Snort, Suricata, Cisco Firepower
* **How it works:**
  * Compares network traffic or system activity against known attack patterns (signatures).
  * **IDS (Intrusion Detection System):** Passive monitoring and alerting.
  * **IPS (Intrusion Prevention System):** Actively blocks malicious traffic.
* **Strengths:** Effective against known threats, low false positives for well-defined attacks.
* **Limitations:** Struggles with zero-day attacks and advanced threats that evade signatures.

**B. Anomaly-Based Detection (Network Behavior Analysis)**

* **Example Tools:** Darktrace, Cisco Stealthwatch
* **How it works:**
  * Uses machine learning or statistical baselining to detect unusual behavior.
  * Can identify novel attacks but may have higher false positives.
* **Best for:** Detecting insider threats, lateral movement, and unknown attacks.

#### SIEM (Security Information and Event Management)

SIEM can integrate and correlate distributed events and alert on hostile or abnormal behavior.

* **Example Tools:** Wazuh, Splunk, IBM QRadar, Elastic SIEM
* **How it works:**
  * **Aggregates logs** from multiple sources (e.g., network devices, cloud services, IDS, servers).
  * **Correlates events** to detect complex attack patterns (e.g., multiple failed logins followed by a successful one).
  * Provides **real-time alerting**, historical analysis, and compliance reporting.
* **Strengths:**
  * Holistic visibility across the environment.
  * Helps with **incident response** and **forensics**.
* **Limitations:**
  * Requires fine-tuning to reduce noise.
  * Not a direct replacement for IDS/IPS but complements them.

#### Endpoint Detection and Response/Extended Detection and Response (EDR/XDR)

* **Example Tools:** CrowdStrike, SentinelOne, Microsoft Defender for Endpoint
* **How it works:**
  * Monitors **endpoint behavior** (processes, file changes, registry edits).
  * Uses behavioral analysis to detect malware and suspicious activity.
* **Best for:** Detecting advanced threats on endpoints/workstations/servers.

#### **Network Traffic Analysis (NTA)**

**NTA** (also called **Network Detection and Response, NDR**) focuses on **analyzing raw network traffic** to detect suspicious behavior that evades traditional tools.

**Key Technologies & Tools:**

* **Zeek (formerly Bro)** → Generates high-level network logs (e.g., HTTP requests, DNS queries).
* **Suricata (in NTA mode)** → Analyzes traffic for anomalies beyond just signatures.
* **Darktrace, Cisco Stealthwatch** → AI-driven anomaly detection (e.g., unusual data exfiltration).
* **Moloch, Arkime** → Packet capture (PCAP) analysis for forensic investigations.

**How NTA Complements Other Tools:**

| Scenario                                               | Firewall                     | IDS/IPS                         | SIEM                                     | NTA                                 |
| ------------------------------------------------------ | ---------------------------- | ------------------------------- | ---------------------------------------- | ----------------------------------- |
| **A hacker slowly exfiltrates data via DNS**           | Allows it (DNS is permitted) | Likely misses it (no signature) | Might miss it (unless logs are detailed) | Detects unusual DNS query patterns  |
| **Lateral movement via RDP (Remote Desktop Protocol)** | Blocks if port is closed     | May detect brute-forcing        | Logs the event (if logging is enabled)   | Flags abnormal internal connections |

**NTA’s Strengths:**

* Detects **low-and-slow attacks** (e.g., data exfiltration, C2 beaconing).
* Helps with **post-breach investigations** (e.g., reconstructing attacker movements).
* Works well with **encrypted traffic analysis** (via JA3 fingerprints, TLS metadata).

**Limitations:**

* Requires **high storage** for full packet capture (PCAP).
* Can be **noisy** without proper tuning.

### Layered security (defense in depth)

Defense in depth is a **strategy** for the protection of information assets that uses multiple layers\
and different types of controls (managerial, operational, and technical) to provide optimal\
protection.

* **Defense in depth: the broader, more established term** (originating from military strategy) and is widely recognized in cybersecurity as a comprehensive approach combining multiple security layers (technical, administrative, and physical controls).
* **Layered security: a subset of defense in depth**, often referring specifically to the **technical controls** (firewalls, encryption, endpoint protection, etc.) rather than the full strategy.

Mitigation techniques also include preventing unauthorized persons from gaining physical access to the devices, for example, by keeping them in a secure rack behind a secure door.

By working together, risk mitigation methods create a layered security approach to safeguard information assets and maintain network integrity.

Layers of Defense example: firewall > IDS/IPS > SIEM

### Incident response and disaster recovery&#x20;

One of the biggest challenges facing today's IT professionals is planning and preparing for the almost inevitable security incident.

Incident Response (IR) is a structured methodology for handling security breaches, cyber threats, and policy violations. The goal is to manage the situation in a way that limits damage, reduces recovery time and costs, and prevents future occurrences. A standard IR process follows a lifecycle, often based on the NIST framework (NIST SP 800-61r2) which includes:

1. **Preparation**
2. **Detection & Analysis**
3. **Containment, Eradication & Recovery**
4. **Post-Incident Activity**

#### 1. Preparation

This is the proactive phase focused on getting ready for a potential incident _before_ it happens.

* **What it entails:** Establishing a Security Incident Response Team (SIRT), developing and writing an IR plan, acquiring necessary tools (forensic software, communication systems), and providing training through drills and simulations. This phase also includes implementing general security controls to prevent incidents.

The first consideration in an incident response plan is **preparation**. There should be a manifesto or playbook outlining a structured approach to managing security incidents. Typically an organization should have a SIRT, which will investigate and document incidents. SIRT can be cross functional assembled from various IT related departments or units, and it can be part of or an extension of a SOC team.

The playbook will provision responses commensurate with established risk levels to data assets. For instance, it is important to rank incidents by severity level. It is critical to differentiate between security events (less serious) and security incidents (serious and requiring immediate action). A security event, like a virus on endpoint, might escalate to incident level, but typically it can be addressed via standard procedures or even automation.&#x20;

#### 2. Detection & Analysis

This is the phase where potential security events are identified and investigated to confirm an incident and understand its scope.

* **What it entails:** Monitoring systems for alerts (from IDS/IPS, SIEM, antivirus), analyzing the evidence to determine the cause, assessing the impact (what systems/data are affected), and prioritizing the incident's severity to allocate appropriate resources.

#### 3. Containment, Eradication & Recovery

This is the reactive core of the IR process where the incident is actively handled and resolved.

* **Containment:** Taking immediate, short-term actions to limit the damage (e.g., isolating a network segment, disabling accounts). This is often split into short-term and long-term containment strategies.
* **Eradication:** Removing the root cause of the incident from the environment (e.g., deleting malware, disabling breached user accounts, addressing vulnerabilities that were exploited).
* **Recovery:** Restoring systems and data to normal operation and confirming they are no longer compromised (e.g., restoring from clean backups, rebuilding systems, bringing services back online).

Organizations should schedule data backups in order to guarantee business continuity in the case of a security incident or disaster. Backups should be created on a yearly, monthly, and weekly basis, and stored in an offsite location. It is critical to encrypt backup data in order to prevent untrusted access to it.

#### 4. Post-Incident Activity

This critical phase occurs after the incident is resolved and focuses on learning from the event to improve future response.

* **What it entails:** Conducting a "lessons learned" meeting to review what happened, what was done well, and what could be improved. This phase results in a formal incident report that is used to update the IR plan, policies, and security controls to prevent a recurrence.

### Using multiple vendors

To enhance security, it is best practice to diversify your vendor choices. For instance, when defending against malware, deploy antimalware solutions from different vendors across various layers—such as individual computers, the network, and the firewall. Since a single vendor typically uses the same detection algorithms across all its products, relying on just one provider (e.g., Vendor A) for all three layers means that if one product fails to detect a threat, the other vendor products likely will too. A more effective strategy is to use Vendor A for the firewall, Vendor B for the network, and Vendor C for workstations. This way, the likelihood of all three solutions—each with distinct detection algorithms/methods—missing the same malware is significantly lower than if you depended on a single vendor.

### Quality assurance

**• Information assurance as a holistic approach to information security management**

Implementing quality assurance (QA) in enterprise information security risk management involves systematically evaluating processes, controls, and policies to ensure they meet defined security standards and effectively mitigate risks. QA aligns with established frameworks like NIST SP 800-37 (Risk Management Framework), NIST CSF (Cybersecurity Framework), and ISO/IEC 27001 by incorporating continuous monitoring, audits, and compliance checks to validate that security controls are functioning as intended. For example, NIST SP 800-37 emphasizes ongoing assessment and authorization, while ISO 27001 requires regular internal audits and management reviews to maintain certification. By integrating QA practices—such as control testing, gap analysis, and corrective action plans—organizations can proactively identify weaknesses, improve security postures, and ensure adherence to regulatory requirements. This structured approach not only enhances risk management maturity but also fosters a culture of continuous improvement, reducing vulnerabilities and strengthening overall information assurance.

**• Security testing as skills in quality assurance**

\*Software Development Lifecycle (SDLC)

SDLC models: Waterfall, Lean, and Agile.

ISO/IEC 12207: The international standard for software lifecycle processes.

\*Test-driven development and unit testing

Unit Testing: A structured and automated testing methodology to ensure resilient software.

Example: Using the internal Python module unittest to automate Python code testing.

### Timely software patching

Timely software patching is critical for maintaining a secure network, as unpatched systems are prime targets for cyberattacks. Vulnerabilities in software, whether in operating systems, applications, or firmware, are frequently exploited by threat actors to gain unauthorized access, deploy malware, or exfiltrate data. For example, zero-day vulnerabilities—flaws unknown to vendors until exploited—require immediate patching to mitigate risks. Additionally, compliance frameworks such as NIST, CIS, and ISO 27001 mandate regular patch management to meet security standards. Delayed patching can lead to:

* **Increased attack surface**: Unpatched systems expose networks to known exploits.
* **Regulatory penalties**: Non-compliance with security standards may result in fines.
* **Operational disruptions**: Exploits like ransomware can cripple business continuity.

**How Automation Enhances Consistency and Compliance in Patching**

Automation is a game-changer in patch management, ensuring patches are deployed promptly and uniformly across an organization’s infrastructure. Manual patching is error-prone and often inconsistent, especially in large or hybrid environments. Automated patch management tools (e.g., WSUS, SCCM, or third-party solutions like Qualys or Tanium) streamline the process by:

* **Scheduling and deploying patches** during maintenance windows to minimize downtime.
* **Prioritizing critical updates** based on CVSS scores or vendor advisories.
* **Generating audit logs** for compliance reporting, proving adherence to regulatory requirements.\
  Automation also enables **continuous monitoring** for missing patches and **rollback capabilities** if updates cause instability. By integrating with SIEM or IT service management (ITSM) platforms, automated patching systems can trigger alerts for failed deployments, ensuring no asset is left unprotected. In essence, automation reduces human error, enforces policy adherence, and strengthens overall security posture.

### Physically securing the network

To protect an enterprise network from physical threats, organizations must implement robust **physical security controls** to prevent unauthorized access, theft, or tampering with critical infrastructure. Below are key strategies used in real-world environments:

**1. Controlled Access to Facilities**

Physical access control protects equipment and data from potential attackers by only allowing authorized users into protected areas such as network closets or data center floors. This is not just to prevent people outside of the organization from gaining access to these areas. Even within the company, access to these areas should be limited to those who need access.

* **Badge & Biometric Systems** – Require employees to use **smart cards, key fobs, or biometric scans** (fingerprint/retina) to enter secure areas. Multifactor locks can protect access to restricted areas. For example, a door that requires users to swipe a badge and scan their fingerprint to enter. That’s something you have, a badge, and something you are, your fingerprint. Badge systems are very flexible, and permissions granted to a badge can easily be changed. This allows for strict, centralized control of who is authorized to enter where.
* **Mantraps & Turnstiles** – Use double-door entry systems (mantraps) to prevent tailgating and ensure only one person enters at a time.
* **Visitor Logs & Escorts** – All guests must sign in, present ID, and be accompanied by authorized personnel while inside restricted zones.

**2. Securing Network Infrastructure**

* **Locked Server Rooms & Cabinets** – Critical network devices (servers, routers, switches) should be housed in **access-controlled, monitored rooms** with **rack-mounted locks**.
* **Tamper-Evident Seals** – Use security screws, seals, or sensors to detect unauthorized hardware modifications.
* **Disable Unused Ports** – Physically block or disable unused Ethernet, USB, and console ports to prevent unauthorized connections.

**3. Surveillance & Monitoring**

* **24/7 CCTV with AI Analytics** – Deploy high-resolution cameras with **motion detection and facial recognition** to monitor sensitive areas.
* **Security Guards & Patrols** – On-site personnel should conduct **random checks** and verify access permissions.
* **Environmental Sensors** – Monitor for **temperature, humidity, and smoke** to prevent equipment damage.

**4. Preventing Data & Hardware Theft**

* **Asset Tagging & RFID Tracking** – Tag all equipment with **barcodes or RFID chips** to track movement and detect unauthorized removal.
* **Checkpoint Inspections** – Security staff should inspect bags and devices when employees exit the building to prevent data theft.
* **Secure Disposal Policies** – Destroy decommissioned drives (shredding/degaussing) and enforce strict e-waste handling procedures.

**5. Redundancy & Disaster Preparedness**

* **Offsite Backup Storage** – Keep backups in a **geographically separate, access-controlled facility** to ensure recovery in case of physical damage.
* **UPS & Backup Power** – Use **uninterruptible power supplies (UPS)** and generators to maintain operations during outages.
* **Fire Suppression Systems** – Install **gas-based (e.g., FM-200) or waterless suppression systems** in server rooms to avoid damage from traditional sprinklers.

**Enforcement & Best Practices**

* **Regular Audits** – Conduct surprise inspections to verify compliance with physical security policies.
* **Employee Training** – Educate staff on **social engineering risks** (e.g., impersonators) and proper access protocols.
* **Zero Trust for Physical Access** – Apply the **principle of least privilege**—only grant access to personnel who absolutely need it.

By implementing these measures, enterprises can significantly reduce the risk of **physical breaches, insider threats, and unauthorized data exfiltration**, ensuring the integrity of their network infrastructure.

### Key takeaways

* Network security risk mitigation best practices include Identity and Access Management, network monitoring, incident response and disaster recovery, and layered security

### References

Whitman, M. E., & Mattord, H. J. (2014). Principles of information security (p. 656). Boston, MA: Thomson Course Technology.

Yuri Livshitz. (2016). How to respond to a security incident (Ch. 9). In _Beginner’s Guide To Information Security_ (pp. 42-45). Peerlyst. Retrieved from https://www.peerlyst.com/posts/peerlyst-announcing-its-first-community-ebook-the-beginner-s-guide-to-information-security-limor-elbaz
