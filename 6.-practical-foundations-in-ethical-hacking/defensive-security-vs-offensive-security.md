---
description: >-
  This section explains two important concepts within the cybersecurity field,
  defensive security and offensive security, and their importance for an
  effective organizational security policy
---

# Defensive security vs offensive security

• Become familiar with defensive security and offensive security approaches, including SIRT/CSIRT (Security Incident Response Team/Computer Security Incident Response Team), SOC (Security Operations Center), red teaming, and ethical hacking.

### Two key cybersecurity paradigms

| **Strategy**              | **Offensive Security**                                                                                               | **Defensive Security**                                                                                   |
| ------------------------- | -------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------- |
| **Approach**              | Ethical hacking, “hacker powered security” (e.g., HackerOne and Bugcrowd)                                            | Diligence, SDLC/agile security, DevSecOps/security-by-design, best practices, IA (Information Assurance) |
| **Mindset**               | Attacker, adversarial, damage, break, deceive, trick                                                                 | Defender, ally, protect, prevent, mitigate                                                               |
| **Skillsets**             | How to penetrate an information system                                                                               | How to protect an information system (risk assessment/governance skills)                                 |
| **Conflict of Interests** | Less conflict of interests (hired external ethical hackers)                                                          | Conflict of interests (hackers are typically employees)                                                  |
| **Related Paradigms**     | Red teaming                                                                                                          | Hygiene culture, Security culture, blue teaming                                                          |
| **Permission of Owner**   | Authorized, legal                                                                                                    | Authorized, legal                                                                                        |
| **Testing Approaches**    | <p>Blackbox testing, Black hat hacking </p><p></p><p>Third party audit/auditor perspective of infosec governance</p> | Whitebox testing, White hat hacking                                                                      |
| **Authentication**        | Unauthenticated scan (outsider attack)                                                                               | Authenticated scan (simulation of insider attack)                                                        |

***

### Ethical hacking vs red teaming

#### Ethical hacking vs red teaming organizational position

#### **1. White Hat Hackers (Ethical Hackers)**

* **Typically Contracted Professionals (but not always):**
  * Many white hat hackers work as **independent consultants** or are employed by **cybersecurity firms** that provide penetration testing, bug bounty hunting, or security audits to multiple clients.
  * Some may also be **full-time employees** of a company, especially in large organizations with dedicated security teams.
* **Common Roles:**
  * **Bug bounty hunters** (freelancers who find vulnerabilities for rewards).
  * **Penetration testers** (hired to simulate attacks).
  * **Security researchers** (may work for firms or independently).

#### **2. Red Teams**

* **Usually Company Employees (but not always):**
  * Red teams are often **internal teams** within an organization tasked with simulating real-world attacks to test defenses.
  * Some companies **outsource red teaming** to specialized firms (making them contracted professionals).
* **Key Difference from White Hats:**
  * Red teams focus on **long-term, adversarial simulations** (like advanced persistent threats), whereas white hats may do shorter-term assessments (like pentests).

#### **General Rule of Thumb**

| Role                 | Typically Employed By             | Focus                                            |
| -------------------- | --------------------------------- | ------------------------------------------------ |
| **White Hat Hacker** | External (but sometimes internal) | Pentests, bug bounties, vulnerability research   |
| **Red Team**         | Internal (but sometimes external) | Advanced attack simulations, adversary emulation |

#### **Overlap & Inconsistencies**

* Some **white hats** are employees (e.g., in-house security teams).
* Some **red teams** are external contractors (e.g., hired for a specific engagement).
* **Purple Teams** (a blend of red + blue teams) further blur the lines, as they involve collaboration between attackers and defenders.

#### Ethical hacking vs red teaming cybersecurity activities

#### **Key Similarities:**

* Both involve authorized attempts to identify vulnerabilities in systems, networks, or organizations.
* Both aim to improve security by exposing weaknesses before malicious actors exploit them.
* Both require technical skills in penetration testing, social engineering, and attack simulations.

#### **Key Differences:**

| **Aspect**         | **Ethical Hacking**                         | **Red Teaming**                                                                   |
| ------------------ | ------------------------------------------- | --------------------------------------------------------------------------------- |
| **Scope**          | Often focuses on specific systems or apps.  | Broader, simulating real-world adversaries (including physical & social attacks). |
| **Objective**      | Find and fix vulnerabilities.               | Test detection & response capabilities (not just tech flaws).                     |
| **Duration**       | Short-term, targeted engagements.           | Longer, multi-phase operations (like espionage).                                  |
| **Stealth**        | May or may not avoid detection.             | Often prioritizes stealth to mimic real attackers.                                |
| **Team Structure** | Usually individual testers or small groups. | Larger, multidisciplinary teams (cyber, physical, social).                        |
| **Reporting**      | Detailed technical remediation guidance.    | Focuses on strategic security gaps & organizational resilience.                   |

#### **When They Overlap:**

* A red team can use ethical hacking techniques (e.g., exploiting a server vulnerability).
* Some ethical hackers perform red teaming if the engagement includes advanced adversary simulation.

***

#### SOC (Security Operations Center)/Blue Teaming

**SOC (Security Operations Center) analysts and engineers are essentially the operational arm of the "Blue Team."** However, whether they are **in-house employees or contracted** depends on the organization's structure.

**SOC as the Blue Team (Defenders)**

* **Primary Role:**
  * Monitor, detect, analyze, and respond to security incidents.
  * Handle alerts from SIEM (Security Information and Event Management), EDR (Endpoint Detection & Response), firewalls, etc.
  * Perform **threat hunting** (proactively searching for undetected threats).
  * Work closely with **Incident Response (IR)** teams when breaches occur.

#### **In-House vs. Contracted/MSSP SOCs**

| Type                      | Description                                                            | Pros                                                                                               | Cons                                                                                |
| ------------------------- | ---------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------- |
| **In-House SOC**          | Employees directly hired by the company.                               | <p>- Better knowledge of internal systems.<br>- Faster coordination with IT/other teams.</p>       | <p>- Expensive to maintain 24/7.<br>- Requires hiring skilled analysts.</p>         |
| **Contracted SOC (MSSP)** | Managed by a third-party **MSSP (Managed Security Service Provider)**. | <p>- Cost-effective (no need for full-time staff).<br>- Access to broader threat intelligence.</p> | <p>- Less familiarity with internal networks.<br>- Possible delays in response.</p> |

**Key Overlaps & Clarifications**

1. **Blue Team ≠ SOC (but SOC is a core part of Blue Team)**
   * The **Blue Team** is a broader concept, including **SOC, IR, vulnerability management, and security hardening teams**.
   * The **SOC is the 24/7 monitoring & initial response unit** within the Blue Team.
2. **Some Companies Have Hybrid Models**
   * Example: A company might have an **in-house SOC for critical systems** but outsource **lower-priority monitoring** to an MSSP.
3. **Contract SOC Analysts (Staff Augmentation)**
   * Some firms hire **temporary SOC analysts** through staffing agencies (neither fully in-house nor full MSSP).
