# NIST SP 800-61 (IR framework)

A standard Incident Response (IR) process follows a lifecycle. NIST Special Publication 800-61 Rev. 2: "Computer Security Incident Handling Guide" is a widely cited and adopted standard for IR. It provides a comprehensive set of guidelines and best practices for building and managing an IR capability.

IR open source stack: Wazuh + TheHive + Suricata → Full SIEM + IR + NIDS.

IR in the context of this tool stack builds a capability that supports this entire NIST 800-61 lifecycle.

#### The NIST SP 800-61r2 Incident Response Lifecycle

The framework outlines a cyclical process with four main phases. This lifecycle is the core of any mature IR program, and tools like TheHive are explicitly designed to facilitate it. Here are the four phases in detail:

**1. Preparation**

This is the most critical phase. The goal is to establish and maintain the capabilities needed to effectively respond to an incident _before it happens_.

**Key Activities:**

* **Policies & Plans:** Developing an IR policy, charter, and a detailed handling plan.
* **Team:** Forming a Computer Security Incident Response Team (CSIRT) with clearly defined roles and responsibilities.
* **Tools:** Procuring and configuring the necessary technology (e.g., your **Wazuh + TheHive + Suricata** stack, forensic software, communication systems).
* **Training & Awareness:** Conducting training for the IR team and general security awareness for all staff.
* **Exercises:** Running tabletop exercises and simulations to test the plan.

> **How the stack fits:** Setting up the integrations between Wazuh, TheHive, and Suricata is a core _Preparation_ activity.

**2. Detection & Analysis**

This phase involves discovering potential security incidents and determining their scope and impact.

**Key Activities:**

* **Monitoring:** Continuously monitoring systems (**Wazuh**), networks (**Suricata**), and users for indicators of compromise.
* **Analysis:** Triage alerts, validate true positives, and determine the attack's root cause, scope (what systems are affected), and impact (what data was accessed).
* **Documentation:** Recording all initial findings and steps taken.
* **Prioritization:** Ranking the incident based on its impact on the business (e.g., a low-priority malware infection vs. a high-priority ransomware event).

> **How the stack fits:** **Wazuh** and **Suricata** are the primary _Detection_ engines. Their alerts are fed into **TheHive** to begin the _Analysis_ and _Documentation_ process.

**3. Containment, Eradication & Recovery**

This is the "action" phase where the incident is stopped, removed, and systems are returned to normal operation.

**Key Activities:**

* **Containment:** Taking immediate, short-term actions to limit damage (e.g., disconnecting a machine from the network, blocking a malicious IP). This is often split into short-term and long-term containment.
* **Eradication:** Removing the root cause of the incident (e.g., deleting malware, disabling compromised user accounts, patching vulnerabilities).
* **Recovery:** Restoring systems and data from clean backups and returning to normal business operations, while verifying that the systems are no longer compromised.

> **How the stack fits:** An analyst in **TheHive** can create a task to "Contain Host X" and trigger an integrated playbook that uses **Wazuh's** active response feature to isolate the endpoint.

**4. Post-Incident Activity**

Often called the "lessons learned" phase, this is a crucial feedback loop that improves future response efforts.

**Key Activities:**

* **Blameless Retrospective:** Holding a meeting with all involved parties to discuss what happened, what was done well, and what could be improved.
* **Final Report:** Writing a detailed report for management that includes the incident's impact, cost, and root cause.
* **Evidence Retention:** Securely storing all logs, notes, and evidence from the case for future reference or legal needs.
* **Process Improvement:** Updating IR plans, policies, and procedures based on lessons learned. This often leads back to the **Preparation** phase (e.g., "We need a new Wazuh rule to detect this TTP earlier next time").

> **How the stack fits:** **TheHive** is invaluable here. The entire timeline of the case—every alert, note, action, and task—is automatically documented, providing a perfect auditable record for the retrospective and final report.

The IR process is a continuous cycle. The output of **Phase 4** directly feeds improvements back into **Phase 1**, making the organization more prepared and resilient for the next incident.

Resources:

Incident Handler's Handbook (PDF, 1.97MB)\
Published: 21 Feb, 2012\
Created by:\
Patrick Kral
