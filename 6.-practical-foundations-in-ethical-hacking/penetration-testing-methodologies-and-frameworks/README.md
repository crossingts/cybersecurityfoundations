---
description: This section discusses major penetration testing methodologies and frameworks
---

# Penetration testing methodologies and frameworks

## Learning objectives

* Become familiar with major penetration testing methodologies and frameworks

This section discusses major penetration testing methodologies (e.g., OSSTMM, NIST SP 800-115, PTES, and ISSAF) and frameworks (e.g., OWASP Testing Guide and MITRE ATT\&CK/cyber kill chain).

### Topics covered in this section

* **Major penetration testing methodologies**
* **MITRE ATT\&CK® framework**

### Major penetration testing methodologies

Security assessments follow structured methodologies to ensure thorough testing. Below are the most widely used penetration testing frameworks and their key features and use cases.

#### OSSTMM (Open Source Security Testing Methodology Manual)

* **Focus:** Scientific, rules-based security testing (not just pentesting).
* **Key Features:**
  * Covers **operational security (OpSec), physical, wireless, networks, and human security**.
  * Uses **RAV (Risk Assessment Values)** for measurable risk scoring.
  * Emphasizes **legal compliance and safety**.
* **Best For:** Comprehensive audits beyond just hacking (e.g., compliance, physical security).

#### NIST SP 800-115 (Technical Guide to Information Security Testing)

* **Focus:** Aligns with **NIST Cybersecurity Framework (CSF)**.
* **Key Features:**
  * Covers **vulnerability scanning, pentesting, and social engineering**.
  * Used heavily in **government and compliance (e.g., FISMA)**.
* **Best For:** Organizations needing **regulatory compliance**.

#### PTES (Penetration Testing Execution Standard)

* **Focus:** Standardized phases for pentesting.
* **7 Phases:**
  1. **Pre-engagement** (Scope, contracts).
  2. **Intelligence Gathering** (Recon).
  3. **Threat Modeling** (Identify attack vectors).
  4. **Vulnerability Analysis** (Scanning).
  5. **Exploitation** (Gaining access).
  6. **Post-Exploitation** (Persistence, pivoting).
  7. **Reporting** (Remediation guidance).
* **Best For:** General pentesting (network, web, cloud).

#### ISSAF (Information Systems Security Assessment Framework)

* **Focus:** Step-by-step pentesting (older but still referenced).
* **Key Features:**
  * Detailed **exploitation techniques** (now outdated in parts).
  * Covers **network, web apps, and databases**.
* **Best For:** Learning historical pentesting methods.

#### OWASP Testing Guide

* **Focus:** Web application security.
* **Key Features:**
  * Detailed checklist for **OWASP Top 10 vulnerabilities** (SQLi, XSS, CSRF, etc.).
  * Covers **APIs, serverless, and cloud apps**.
* **Best For:** Web app pentesters, DevSecOps teams.

#### MITRE ATT\&CK-Based Testing

* **Focus:** Emulating **real-world adversary TTPs** (Tactics, Techniques, Procedures).
* **Key Features:**
  * Maps attacks to **threat groups (APT29, Lazarus, etc.)**.
  * Used for **red teaming, purple teaming, and detection engineering**.
* **Best For:** Advanced adversary simulation.

**Comparison Table**

| Methodology       | Scope                             | Strengths                   | Weaknesses                 | Best Used For                    |
| ----------------- | --------------------------------- | --------------------------- | -------------------------- | -------------------------------- |
| **OSSTMM**        | Broad (physical, networks, human) | Scientific, measurable      | Less focus on exploitation | Compliance, full-spectrum audits |
| **NIST 800-115**  | Compliance-focused                | Aligns with NIST CSF        | Less technical depth       | Government/regulated industries  |
| **PTES**          | General pentesting                | Structured phases           | Not industry-enforced      | Network/web pentests             |
| **ISSAF**         | Historical pentesting             | Detailed exploitation steps | Outdated in parts          | Learning basics                  |
| **OWASP**         | Web apps                          | Covers OWASP Top 10         | Limited to apps            | Web security                     |
| **MITRE ATT\&CK** | Adversary emulation               | Real-world TTPs             | Not a full methodology     | Red teaming, threat hunting      |

**Which Should You Use?**

* **For compliance?** → **OSSTMM, NIST SP 800-115**
* **For web apps?** → **OWASP Testing Guide**
* **For general pentesting?** → **PTES**
* **For red teaming?** → **MITRE ATT\&CK**

#### Open source penetration testing methodologies

Key open source penetration testing methodologies include Open Source Security Testing Methodology Manual (OSSTMM) (Herzog, 2006), NIST 800-115 (2008) Technical Guide to Information Security Testing and Assessment, The Open Web Application Security Project (OWASP), The Penetration Testing Execution Standard (PTES), The Information System Security Assessment Framework (ISSAF), PCI-DSS v.1 2015 Penetration Testing Guide, and Communications Security Establishment/Royal Canadian Mounted Police, Harmonized Threat and Risk Assessment Methodology (CSE/RCMP, 2007) (see Bradbury, 2010; Faircloth, 2011; Goel & Mehtre, 2015; Shah & Mehtre, 2015; Valvis & Polemi, 2005).

Key open source penetration testing methodologies discussed here are Open Source Security Testing Methodology Manual (**OSSTMM 3.0**), NIST Special Publication 800-115: Technical Guide to Information Security Testing and Assessment (**NIST 800-115**), and Communications Security Establishment/Royal Canadian Mounted Police, Harmonized Threat and Risk Assessment Methodology (**CSE/RCMP, 2007**).&#x20;

_A comparative analysis of three open source methodologies—OSSTMM 3.0, NIST 800-115, and CSE/RCMP Harmonized Threat and Risk Assessment Methodology (2007)—offers insights into establishing a harmonized penetration testing methodology (see Table 20: Information Security Assessment Methodologies)._

The original Open Source Security Testing Methodology Manual (OSSTMM) is a peer-reviewed manual of security testing and analysis, “a methodology for a thorough security test, known as an OSSTMM audit” by the Institute for Security and Open Methodologies (ISECOM), was published on December 18, 2000. The current version OSSTMM 3.0 was published on August 2, 2008. In version 3, OSSTMM encompasses tests from all channels: Human, Physical, Wireless, Telecommunications, and Data Networks. A set of security metrics used, Risk Assessment Values (RAVs), provide a tool that can provide a graphical representation of changes in state over time. The primary focus in version 3 has been to move away from solution-based testing, which assumes specific security solutions will be found in a scope and are required for security (like a firewall). Instead, the focus is on a metric for the attack surface (the exposure) of a target or scope, allowing for a factual metric with no bias (the risk-based approach).&#x20;

The purpose of NIST SP 800-115: Technical Guide to Information Security Testing and Assessment (September 2008) is “to provide guidelines for organizations on planning and conducting technical information security testing and assessments, analyzing findings, and developing mitigation strategies” (NIST, 2008, p. ES-1). NIST SP 800-115 divides penetration testing into four main phases: Planning phase, Discovery phase (addressing Target Identification and Analysis Techniques), Attack phase (addressing Target Vulnerability Validation Techniques), and Reporting. NIST SP 800-115 Section 4 Target Identification and Analysis Techniques focuses on “identifying active devices and their associated ports and services, and analyzing them for potential vulnerabilities” (p. 4-1). It includes Network Discovery which “uses a number of methods to discover active and responding hosts on a network, identify weaknesses, and learn how the network operates.”&#x20;

Passive (examination) and active (testing) techniques discover devices and active hosts on a network. Passive techniques can use a network sniffer to monitor network traffic and record the IP addresses of the active hosts, and they can report which ports are in use and which operating systems on the network have been discovered–without sending out a single probing packet (p. 4-1). Section 4 also covers Network Port and Service Identification. “Some scanners can help identify the application running on a particular port through a process called service identification” (p. 4-3). Banner grabbing involves “capturing banner information transmitted by the remote port when a connection is initiated. This information can include the application type, application version, and even OS type and version.” The result of network discovery and network port and service identification is “a list of all active devices operating in the address space that responded to the port scanning tool, along with responding ports” (NIST, 2008, p. 4-3). Port scanners can identify active hosts, operating systems, ports, services, and applications, but they can not identify vulnerabilities. “To identify vulnerable services, the assessor compares identified version numbers of services with a list of known vulnerable versions, or performs automated vulnerability scanning” (p. 4-4).

Vulnerability scanners can be broadly divided in to two categories: Web application scanners such as Acunetix, WebInspect, and NetSparker; and network and infrastructure scanners such as Nessus, Qualys, and Metasploit. Vulnerability scanners can check compliance with host application usage and security policies, identify hosts and open ports, identify known vulnerabilities, and provide information on how to mitigate discovered vulnerabilities. Vulnerability scanners often use their own proprietary methods for defining the risk levels. One scanner might use the levels low, medium, and high; another scanner might use the levels informational, low, medium, high, and critical, making it difficult to compare findings among multiple scanners. Vulnerability scanners rely on a repository of signatures which requires the assessors to update these signatures frequently to enable the scanner to recognize the latest vulnerabilities. NIST SP 800-115 Section 5 Target Vulnerability Validation Techniques focuses on using information produced from target identification and analysis to further explore the existence of potential vulnerabilities. The objective is to prove that a vulnerability exists, and to demonstrate the security exposures that occur when it is exploited” (p. 4-5).

The Harmonized Threat and Risk Assessment Methodology (TRA-1) by the Communications Security Establishment (CSE) and the Royal Canadian Mounted Police (RCMP) (CSE/RCMP, 2007) presents a flexible approach which can be automated and serves as a general framework for a harmonized penetration testing methodology by applying a project management frame. The TRA approach provides “a clear rationale for cost-effective risk mitigation strategies and safeguards to meet business requirements; and a transparent audit trail and record of risk management decisions to demonstrate due diligence and accountability, thereby satisfying statutory obligations and policy requirements” (CSE/RCMP, 2007, p. EO-2).

**Table 20: Information Security Assessment Methodologies**

<table data-header-hidden><thead><tr><th valign="top"></th><th valign="top"></th><th valign="top"></th></tr></thead><tbody><tr><td valign="top">OSSTMM 3.0</td><td valign="top"> NIST 800-115</td><td valign="top">TRA-1 (CSE/RCMP, 2007)</td></tr><tr><td valign="top"><p>Background:</p><p><br></p><p>This current version is published on Saturday, August 2, 2008.</p><p><br></p><p>The OSSTMM is for free dissemination under the Open Methodology License (OML) 3.0 and CC Creative Commons 2.5 Attribution-NoDerivs.</p><p><br></p><p>OSSTMM 3.0 “is maintained by the Institute for Security and Open Methodologies (ISECOM), developed in an open community, and subjected to peer and cross-disciplinary review.”</p><p><br></p><p>“Financing for all ISECOM projects is provided through partnerships, subscriptions, certifications, licensing, and case-study-based research. ISECOM is registered in Catalonia, Spain as a Non-Profit Organization and maintains a business office in New York, USA. p.1</p></td><td valign="top"><p>Background:</p><p><br></p><p>Federal (US) sponsorship   </p><p>September 2008</p><p><br></p><p>Section 2 Security Testing and Examination Overview</p><p>presents an overview of information security assessments, including policies, roles and responsibilities, methodologies, and techniques.</p><p><br></p><p>􀀟Section 3 Review Techniques</p><p>provides a detailed description of several technical examination techniques, including documentation review, log review, network sniffing, and file integrity checking.</p><p><br></p></td><td valign="top"><p>Background:</p><p><br></p><p>At the highest level, the Government Security Policy (GSP) prescribes two complementary approaches to security risk management.</p><p><br></p><p>The first is “the application of baseline security requirements, or minimum security standards, specified in the policy itself and other supporting documentation, specifically the operational security standards and technical documentation described in section 9 of the GSP.”</p><p><br></p><p>The second approach is to “address these issues, the GSP provides for continuous risk management in the form of a threat and risk assessment (TRA) as an effective supplement” (p. MS-1).</p><p><br></p><p>The Harmonized TRA Methodology presents the TRA as a project conducted in five distinct phases (TRA phases).</p><p><br></p><p>1) Preparation: Obtain Management Commitment, Establish Project Mandate, Determine Scope of Assessment</p><p><br></p><p>2) Asset Identification: Identify Assets, Assess Injuries, Assign Asset Values</p></td></tr><tr><td valign="top"><p>11.2 Logistics:</p><p>This is the preparation of the channel test environment needed to prevent false positives and false negatives which lead to inaccurate test results. Framework and Network Quality.</p><p><br></p><p>Framework:</p><p>activities similar to recon information gathering,</p><p>e.g., (a) Verify the scope and the owner of the targets outlined for the audit.</p><p>(b) Determine the property location and the owner of the property housing the targets.</p><p>(c) Verify the owner of the targets from network registration.</p></td><td valign="top"><p>Section 4 Target Identification and Analysis Techniques</p><p>describes several techniques for identifying targets and analyzing them for potential vulnerabilities.</p><p><br></p><p>Examples of these techniques include network discovery and vulnerability scanning.</p><p>􀀟</p></td><td valign="top"><p>3) Threat Assessment: Identify Threats, Assess Threat Likelihood, Assess Threat Gravity, Assign Threat Levels</p><p><br></p><p>4) Risk Assessment: Identify Existing Safeguards, Assess Safeguard Effectiveness, Determine Vulnerabilities, Assess Vulnerability Impact, Assign Vulnerability Values</p><p><br></p><p><br></p></td></tr><tr><td valign="top"><p>11.3 Active Detection Verification</p><p>11.3.1 Filtering</p><p>11.3.2 Active Detection</p></td><td valign="top"><br></td><td valign="top"><br></td></tr><tr><td valign="top"><p>11.4 Visibility Audit</p><p>Enumeration and indexing of the targets in the scope through direct and indirect interaction with or</p><p>between live systems.</p><p>11.4.1 Network Surveying -- activities similar to recon footprinting</p><p>e.g., (a) Identify the perimeter of the network segment.</p><p>11.4.2 Enumeration - activities similar to scanning and enumeration (Faircloth 2011</p><p>e.g., Examine target web-based application source code and scripts to determine the</p><p>existence of additional targets in the network.</p></td><td valign="top"><br></td><td valign="top"><br></td></tr><tr><td valign="top"><p>11.5 Access Verification</p><p>Tests for the enumeration of access points leading within the scope.</p><p><br></p><p>- activities similar to port scanning (Faircloth 2011</p><p><br></p><p>11.5.1 Access Process</p><p>(a) Request known, common services which utilize UDP for connections from all addresses.</p><p>(b) Request known, common VPN services including those which utilize IPSEC and IKE for</p><p>connections from all addresses.</p><p><br></p><p>11.5.2 Services</p><p>(a) Request all discovered TCP ports for service banners (flags).</p><p><br></p><p>11.5.3 Authentication</p><p><br></p></td><td valign="top"><p>Section 6 Security Assessment Planning</p><p>presents an approach and process for planning a security assessment.</p><p><br></p></td><td valign="top"><br></td></tr><tr><td valign="top"><p>11.6 Trust Verification</p><p>Tests for trusts between systems within the scope where trust refers to access to information or physical</p><p>property without the need for identification or authentication.</p><p>11.6.1 Spoofing</p><p>11.6.2 Phishing</p><p><br></p></td><td valign="top"><p>Section 5 Target Vulnerability Validation Techniques</p><p>explains techniques commonly used to validate the existence of vulnerabilities, such as password cracking and penetration testing.</p></td><td valign="top"><br></td></tr><tr><td valign="top"><p>11.7 Controls Verification</p><p>Tests to enumerate and verify the operational functionality of safety measures for assets and services.</p><p><br></p></td><td valign="top"><br></td><td valign="top"><br></td></tr><tr><td valign="top"><p>11.8 Process Verification</p><p>11.9 Configuration Verification</p><p>11.10 Property Validation</p><p>11.11 Segregation Review</p><p>11.12 Exposure Verification</p><p>11.13 Competitive Intelligence Scouting</p><p>11.14 Quarantine Verification</p><p>11.15 Privileges Audit</p><p>11.16 Survivability Validation</p><p>11.17 Alert and Log Review</p></td><td valign="top"><p>Section 7 Security Assessment Execution</p><p>discusses factors that are key to the execution of security assessments, including coordination, the assessment itself, analysis, and data handling.</p><p>􀀟</p><p>Section 8 Post-Testing Activities</p><p>presents an approach for reporting assessment findings, and provides an overview of remediation activities.</p></td><td valign="top">5) Recommendations: Identify Unacceptable Risks, Select Potential Safeguards, Identify Safeguard Costs, Assess Projected Risk</td></tr></tbody></table>

### MITRE ATT\&CK® framework

MITRE ATT\&CK® (Adversarial Tactics, Techniques, and Common Knowledge) is a globally accessible knowledge base of adversary behaviors, based on real-world cyber threats. MITRE ATT\&CK is an "encyclopedia of hacking"—helping defenders understand attackers and build better defenses. It serves as a foundation for threat intelligence, detection, red teaming, and defense strategies.

#### 1. What is MITRE ATT\&CK?

* A **structured framework** mapping how attackers operate, from initial access to data exfiltration.
* Used by **security teams, threat hunters, red teams, and SOC analysts** to:
  * Understand attacker **Tactics, Techniques, and Procedures (TTPs)**.
  * Improve **detection & response** (e.g., SIEM rules, EDR alerts).
  * Conduct **red team exercises** (simulating real attacks).
  * Benchmark security controls (**"How well can we detect Technique X?"**).

#### 2. ATT\&CK Matrices: Breaking Down the Structure

The framework organizes threats into **matrices** for different environments:

| Matrix                 | Focus                                                                |
| ---------------------- | -------------------------------------------------------------------- |
| **Enterprise ATT\&CK** | Covers Windows, Linux, macOS, cloud (AWS, Azure, GCP), and networks. |
| **Mobile ATT\&CK**     | Android & iOS threats (e.g., spyware, malicious apps).               |
| **ICS ATT\&CK**        | Industrial Control Systems (OT/SCADA environments).                  |

#### **Core Components:**

1. **Tactics** (The "Why" – Attacker Goals)
   * High-level objectives (e.g., _Initial Access, Execution, Persistence, Privilege Escalation_).
   * Example: **Lateral Movement** (TA0008).
2. **Techniques** (The "How" – Methods Used)
   * Specific methods attackers use (e.g., _Pass the Hash, Spearphishing, DLL Side-Loading_).
   * Example: **Phishing (T1566)** → Spearphishing Link (T1566.002).
3. **Sub-Techniques** (More Granular Details)
   * Variations of techniques (e.g., _Spearphishing Attachment vs. Link_).
4. **Procedures (Real-World Examples)**
   * How threat groups (e.g., APT29, Lazarus) use these techniques.

#### 3. How Organizations Use MITRE ATT\&CK

**Defensive Use Cases (Blue Team/SOC)**

✔ **Threat Detection** – Map detection rules (SIEM, EDR) to ATT\&CK techniques.\
✔ **Gap Analysis** – "Can we detect **Credential Dumping (T1003)?"**\
✔ **Incident Response** – Investigate breaches using ATT\&CK as a playbook.

#### **Offensive Use Cases (Red Team/Pentesters)**

✔ **Simulate Real Attacks** – Test defenses against known TTPs.\
✔ **Purple Teaming** – Collaborate with defenders to improve detection.

#### **Threat Intelligence**

✔ **Track Threat Actors** – Compare APT groups (e.g., _Russian Cozy Bear uses T1195.002_).

#### 4. Example: Mapping an Attack with ATT\&CK

**Scenario:** Ransomware Attack

1. **Initial Access (TA0001)** → Phishing (T1566).
2. **Execution (TA0002)** → PowerShell (T1059.001).
3. **Persistence (TA0003)** → Registry Run Keys (T1547.001).
4. **Lateral Movement (TA0008)** → Pass the Hash (T1550.002).
5. **Impact (TA0040)** → Data Encrypted for Ransom (T1486).

#### 5. ATT\&CK vs. Other Frameworks

| Framework                            | Purpose                                  | Comparison                     |
| ------------------------------------ | ---------------------------------------- | ------------------------------ |
| **MITRE ATT\&CK**                    | Describes **how** attacks happen (TTPs). | More granular than Kill Chain. |
| **Lockheed Martin Cyber Kill Chain** | Focuses on **stages** of an attack.      | Less detailed than ATT\&CK.    |
| **NIST CSF**                         | Risk management framework.               | High-level, not TTP-focused.   |

#### 6. Getting Started with ATT\&CK

* **Explore:** [MITRE ATT\&CK Website](https://attack.mitre.org/)
* **Tools:**
  * **ATT\&CK Navigator** (Visualize TTPs).
  * **CALDERA** (Automated adversary simulation).
  * **Atomic Red Team** (Test detections for ATT\&CK techniques).

### Key takeaways

* Major penetration testing methodologies include OSSTMM, NIST SP 800-115, PTES, and ISSAF.
* Major penetration testing frameworks include OWASP Testing Guide and MITRE ATT\&CK/cyber kill chain.
