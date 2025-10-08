---
description: This section explains two important concepts within the cybersecurity field, defensive security and offensive security, and their importance for an effective organizational security strategy
---

# Defensive security vs offensive security

## Learning objectives

* Become familiar with defensive security and offensive security paradigms
* Recognize blue teams as an organization's cybersecurity defensive cadre 
* Recognize SOC as the operational arm of blue teams
* Understand the focus of SIRT/CSIRT in incident response for escalated SOC events
* Understand how the roles of ethical hackers and red teams intersect and transverse

This section delineates the two fundamental, complementary paradigms of cybersecurity: defensive security and offensive security. Defensive security, embodied by the organization's blue team and its operational arms like the Security Operations Center (SOC) and Computer Security Incident Response Team (CSIRT), focuses on a protector's mindset to prevent, detect, and respond to threats through system hardening, continuous monitoring, and incident management. Conversely, offensive security adopts an adversarial perspective through the practices of ethical hacking and red teaming, which involve authorized, real-world attack simulations to proactively identify and exploit vulnerabilities before malicious actors can. Ultimately, understanding the distinct mindsets, skills, and organizational roles associated with each paradigm is crucial for building a robust and resilient security posture.

## Topics covered in this section

* **Two key cybersecurity paradigms**
* **Blue teaming core functions**
* **SOC (Security Operations Center)**
* **SIRT/CSIRT (Security Incident Response Team/Computer SIRT)**
* **Ethical hacking vs red teaming cybersecurity roles/activities**

### Two key cybersecurity paradigms

Since a malicious hacker may be an insider or an outsider, an effective cybersecurity defense strategy often necessitates a two-prone approach to security testing: outsider’s attack (more associated with offensive security and black box testing) and insider’s attack (more associated with defensive security and white box testing). 

**Two Key Cybersecurity Paradigms**

| **Strategy**              | **Offensive Security**                                                                           | **Defensive Security**                                                                                   |
| ------------------------- | ------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------- |
| **Approach**              | Ethical hacking, “hacker powered security” (e.g., HackerOne and Bugcrowd)                        | Diligence, SDLC/agile security, DevSecOps/security-by-design, best practices, IA (Information Assurance) |
| **Mindset**               | Attacker, adversarial, damage, break, deceive, trick                                             | Defender, ally, protect, prevent, mitigate                                                               |
| **Skillsets**             | How to penetrate an information system                                                           | How to protect an information system (risk assessment, risk mitigation, governance skills)               |
| **Conflict of Interests** | Less conflict of interests (hired external ethical hackers)                                      | Conflict of interests (hackers are typically employees)                                                  |
| **Related Paradigms**     | Red teaming                                                                                      | Hygiene culture, security culture, blue teaming                                                          |
| **Permission of Owner**   | Authorized, legal                                                                                | Authorized, legal                                                                                        |
| **Testing Approaches**    | <p>Blackbox testing</p><p></p><p>Third party audit/auditor perspective of infosec governance</p> | White box testing                                                                                        |
| **Authentication**        | Unauthenticated scan (outsider attack)                                                           | Authenticated scan (simulation of insider attack)                                                        |

### Blue teaming core functions

The blue team refers to the defensive security side of an organization. Blue teaming is a functional concept (what they do) rather than a formal team name like SOC and CSIRT. Blue teaming is a broader concept that includes roles outside SOC/CSIRT, such as security engineers and threat hunters. By analogy, the blue team is akin to Military Defense Forces (all defensive roles), SOC is akin to Radar Operators and Patrol Units (constant monitoring), and CSIRT is akin to SWAT Team (activated for critical incidents).

The activities of blue teams focus on preventing attacks, detecting threats, and responding to incidents.

**Summary of Blue Team Activities**

|Core Function|Key Activities & Processes|Primary Security Tools|
|---|---|---|
|**Prevent**|**Vulnerability Management:** Identifying, prioritizing, and remediating software vulnerabilities through systematic patching.  <br>  <br>**System Hardening:** Securing systems by configuring them for maximum security and minimal attack surface (e.g., disabling unused services, enforcing least-privilege access).|Firewalls, Intrusion Prevention Systems (IPS)|
|**Detect**|**Continuous Monitoring & Log Analysis:** Actively reviewing logs and security alerts from across the network and systems to identify potential malicious activity.  <br>  <br>**Threat Hunting:** The proactive search for hidden threats or anomalies within the environment, based on hypotheses and intelligence, rather than waiting for alerts.|SIEM, Endpoint Detection and Response (EDR), Intrusion Detection Systems (IDS)|
|**Respond**|**Incident Response:** Containing the impact of a security incident, eradicating the threat, and recovering systems to a known good state.  <br>  <br>**Digital Forensics:** Analyzing systems and artifacts post-incident to determine the root cause, scope of the breach, and attacker tactics.|Endpoint Detection and Response (EDR), Forensics Tools|

#### Typical Blue Team Structure in Companies

The composition and focus of a blue team vary significantly depending on the organization's size, maturity, and security needs.

| Organization Size / Type                | Team Composition & Focus                                              | Key Characteristics                                                                                                                                                                                              |
| --------------------------------------- | --------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Small / Medium Companies**            | **Blue Team = SOC + Incident Response (IR)**                          | • No formal, dedicated CSIRT.  <br>• SOC analysts handle both monitoring and response tasks.  <br>• A lean, consolidated security model.                                                                         |
| **Large Enterprises**                   | **Blue Team = SOC + CSIRT + Threat Intel + Vulnerability Management** | • Clear separation of duties and specialized roles.  <br>• SOC handles 24/7 monitoring; CSIRT handles major incidents.  <br>• Includes dedicated functions for threat intelligence and vulnerability management. |
| **Elite / Advanced  organizations (e.g., FAANG)** | **Blue Team = Proactive Defense Unit**                                | • Focus shifts from reactive to proactive measures.  <br>• Heavy emphasis on **threat hunting**, adversary simulation, and intelligence-led defense.  <br>• Often involves developing custom security tooling.   |

### SOC (Security Operations Center)

SOC (Security Operations Center) analysts and engineers are essentially the operational arm of the Blue Team. 

* **Primary Role:** 
  * Monitor, detect, analyze, and respond to security incidents.
  * Handle alerts from SIEM (Security Information and Event Management), EDR (Endpoint Detection & Response), firewalls, etc.
  * Perform **threat hunting** (proactively searching for undetected threats).
  * Work closely with **Incident Response (IR)** teams when breaches occur.
* **Focus**: Operational security—handling alerts, triaging threats, and performing initial analysis.
* **Tools**: SIEM, EDR/XDR, threat intelligence feeds, and automation.
* **Typical Output**: Alerts, tickets, and initial containment actions.

A SOC is often the first line of defense, working 24/7 to identify and mitigate threats in real time. However, whether they are in-house employees or contracted depends on the organization's structure.

#### In-House vs. Contracted/MSSP SOCs

| Type                      | Description                                                        | Pros                                                                                               | Cons                                                                                |
| ------------------------- | ------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------- |
| **In-House SOC**          | Employees directly hired by the company.                           | <p>- Better knowledge of internal systems.<br>- Faster coordination with IT/other teams.</p>       | <p>- Expensive to maintain 24/7.<br>- Requires hiring skilled analysts.</p>         |
| **Contracted SOC (MSSP)** | Managed by a third-party MSSP (Managed Security Service Provider). | <p>- Cost-effective (no need for full-time staff).<br>- Access to broader threat intelligence.</p> | <p>- Less familiarity with internal networks.<br>- Possible delays in response.</p> |

**Clarifications:**

* The Blue Team includes SOC, Incident Response (IR), vulnerability management, and security hardening teams.
* The SOC is the 24/7 monitoring & initial response unit within the Blue Team.
* Some companies have hybrid models. A company might have an in-house SOC for critical systems but outsource lower-priority monitoring to an MSSP.
* Some firms hire temporary SOC analysts through staffing agencies (neither fully in-house nor full MSSP).

### SIRT/CSIRT (Security Incident Response Team/Computer SIRT)

SIRT and CSIRT are activated for high-severity incidents (e.g., breaches, ransomware). In practice, the terms SIRT and CSIRT are often used interchangeably. However, SIRT might focus on broader security incidents (physical, insider threats) while CSIRT is more explicitly IT/digital-focused (e.g., malware, hacking).

* Primary Role: Incident response—investigating, containing, and recovering from confirmed incidents.
* Focus (especially CSIRT): Post-detection actions (forensics, root cause analysis, remediation).
* Typical Output: Incident reports, lessons learned, and coordination with legal/PR.

#### How SOC and CSIRT/SIRT Fit Together in Organizations:

* **SOC + CSIRT/SIRT**: Common in larger companies. The SOC handles day-to-day monitoring; the CSIRT/SIRT takes over for serious incidents.
  * Example: SOC detects unusual lateral movement → escalates to CSIRT for investigation.
* **SOC Only**: Some  organizations rely solely on a SOC, with analysts handling both detection and response (common in mid-sized companies).
* **CSIRT/SIRT Only**: Rare—usually in  organizations that outsource monitoring (MSSP SOC) but keep internal response.
* Many companies have both SOC and C/SIRT, but smaller  organizations might only have a SOC (or outsource CSIRT functions).

**Key Differences:**

| Feature      | SOC                    | CSIRT/SIRT                         |
| ------------ | ---------------------- | ---------------------------------- |
| **Scope**    | Monitoring & alerting  | Incident investigation             |
| **Activity** | Continuous (24/7)      | On-demand (activated per incident) |
| **Skills**   | Triage, basic analysis | Forensics, malware analysis        |

#### When SOC Handles CSIRT/SIRT Tasks (Without a Dedicated Team)

1. **SOC Analysts Wear Multiple Hats**
   * Tier 1 SOC: Monitors alerts, performs initial triage.
   * Tier 2/Tier 3 SOC: Acts as de facto *incident responders*—investigating, containing, and remediating incidents (normally CSIRT’s role).
   * Example: A SOC analyst investigates a phishing campaign, traces compromised accounts, and coordinates remediation—all without escalating to a separate CSIRT.
1. **No Formal "CSIRT" Branding**
   * The organization may document incident response processes (e.g., playbooks) but won’t designate a standalone CSIRT.
   * Roles like "SOC Incident Responder" or "Senior Security Analyst" cover CSIRT duties.
1. **Why This Happens**
   * Cost/Resources: Maintaining a 24/7 SOC is expensive; adding a separate CSIRT isn’t always justified.
   * Workflow Simplicity: Smaller incident volumes may not require a specialized team.
   * Outsourcing: Some  organizations rely on an MSSP’s SOC for monitoring and keep a tiny internal team for response (effectively a mini-CSIRT without the name).**

#### Key Differences: Dedicated CSIRT vs. SOC-Only Approach

|                    | Dedicated CSIRT/SIRT                    | SOC-Only (With CSIRT Responsibilities)   |
| ------------------ | --------------------------------------- | ---------------------------------------- |
| **Team Structure** | Separate team, often senior specialists | SOC tiers handle end-to-end incidents    |
| **Activation**     | Engaged for major incidents             | SOC escalates internally (no handoff)    |
| **Skills**         | Deep forensics, legal/PR coordination   | SOC analysts trained in basic IR         |
| **Common in**      | Large enterprises, regulated industries | Mid-sized companies, lean security teams |

**When Does a Company Need a Dedicated CSIRT?**

1. **High Incident Volume**: SOC is overwhelmed by false positives and lacks time for deep investigations.
2. **Regulatory Requirements**: Industries like finance/healthcare may mandate a formal IR team.
3. **Complex Attacks**: Advanced threats (APT, ransomware) need specialized skills beyond SOC analysts.

**Hybrid Approach (Common in Growing Companies)**

Some  organizations start with a SOC-only model, then evolve:

* **Phase 1**: SOC handles everything.
* **Phase 2**: Senior SOC members are designated as _"IRT leads"_ (still part of SOC).
* **Phase 3**: Formal CSIRT splits off as the security program matures.

Example: A tech startup’s SOC might handle IR until a breach occurs, prompting the creation of a CSIRT.

### Ethical hacking vs red teaming cybersecurity roles/activities 

Both functions aim to improve security by exposing weaknesses before malicious actors exploit them. Both roles require technical skills in penetration testing, social engineering, and attack simulations. Both roles involve authorized attempts to identify vulnerabilities in systems, networks, or organizations.
#### 1. White Hat Hackers (Ethical Hackers)

* **Typically Contracted Professionals (but not always):**
  * Many white hat hackers work as **independent consultants** or are employed by **cybersecurity firms** that provide penetration testing, bug bounty hunting, or security audits to multiple clients.
  * Some may also be **full-time employees** of a company, especially in large organizations with dedicated security teams.
* **Common Roles:**
  * **Bug bounty hunters** (freelancers who find vulnerabilities for rewards).
  * **Penetration testers** (hired to simulate attacks).
  * **Security researchers** (may work for firms or independently).

#### 2. Red Teams

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

However, there are no necessarily clear cut lines distinguishing the activities or roles of ethical hackers and read teams. Some **white hats** are employees (e.g., in-house security teams). Some **red teams** are external contractors (e.g., hired for a specific engagement). Purple Teams (a blend of red + blue teams) further blur the lines, as they involve collaboration between attackers and defenders.

#### **Key Differences:**

| **Aspect**         | **Ethical Hacking**                         | **Red Teaming**                                                                   |
| ------------------ | ------------------------------------------- | --------------------------------------------------------------------------------- |
| **Scope**          | Often focuses on specific systems or apps.  | Broader, simulating real-world adversaries (including physical & social attacks). |
| **Objective**      | Find and fix vulnerabilities.               | Test detection & response capabilities (not just tech flaws).                     |
| **Duration**       | Short-term, targeted engagements.           | Longer, multi-phase operations (like espionage).                                  |
| **Stealth**        | May or may not avoid detection.             | Often prioritizes stealth to mimic real attackers.                                |
| **Team Structure** | Usually individual testers or small groups. | Larger, multidisciplinary teams (cyber, physical, social).                        |
| **Reporting**      | Detailed technical remediation guidance.    | Focuses on strategic security gaps & organizational resilience.                   |

### Key takeaways

* Blue Team ≠ SOC or CSIRT—it’s the umbrella for defensive security
* SOC is operational (monitoring), CSIRT is reactive (incidents), Blue Team is cultural/philosophical (defense-in-depth)
* Not all companies use "Blue Team" as a formal name—many just say SOC/CSIRT
* Interchangeability depends on context:
  * In a startup? "Blue Team" might mean 1–2 people doing everything
  * In a bank? "Blue Team" could refer to a 100-person division
