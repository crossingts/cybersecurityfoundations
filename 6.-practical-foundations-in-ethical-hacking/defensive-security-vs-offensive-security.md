---
description: >-
  This section explains two important concepts within the cybersecurity field,
  defensive security and offensive security, and their importance for an
  effective organizational security policy
---

# Defensive security vs offensive security

• Become familiar with defensive security and offensive security approaches, including SIRT/CSIRT (Security Incident Response Team/Computer Security Incident Response Team), SOC (Security Operations Center), red teaming, and ethical hacking.

**Two key cybersecurity paradigms**

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

#### How red teaming and ethical hacking differ and overlap

#### **Similarities:**

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

* A red team _can_ use ethical hacking techniques (e.g., exploiting a server vulnerability).
* Some ethical hackers perform red teaming if the engagement includes advanced adversary simulation.

#### **Analogy:**

* **Ethical Hacking** = A home inspector checking for structural flaws.
* **Red Teaming** = A burglary drill testing alarms, guards, and response times.

#### **Bottom Line:**

Red teaming is a _subset_ of ethical hacking with a broader, adversarial focus. Ethical hacking is more general, while red teaming mimics sophisticated threat actors. Many professionals do both, but not all ethical hackers are red teamers.
