# NIST SP 800-61 (IR framework)

NIST Special Publication 800-61 Rev. 2: "Computer Security Incident Handling Guide" is a widely cited and adopted standard for Incident Response (IR). It provides a comprehensive set of guidelines and best practices for building and managing an IR capability.

**IR open source stack: Wazuh + TheHive + Suricata → Full SIEM + IR + NIDS.**

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

#### How The Stack Enables IR

The proposed stack is a classic, powerful, and open-source combination that covers the entire IR lifecycle. Here's how each piece fits in:

**1. Wazuh (The SIEM & EDR Core)**

Wazuh is the central data aggregation and correlation engine. It's the "brains" that detects potential incidents.

* **IR Role: Detection & Analysis**
  * **Data Collection:** It gathers logs from endpoints, servers, network devices, and cloud environments (fulfilling the **SIEM** function).
  * **Behavioral Analysis:** Its built-in **Endpoint Detection and Response (EDR)** capabilities monitor for malicious process execution, file changes, and other suspicious activities on hosts.
  * **Correlation:** Wazuh's rules engine correlates disparate events (e.g., a failed login from Suricata + a successful login from a strange location on a host) to generate high-fidelity **alerts**. These alerts are the primary _triggers_ for starting an IR process.

**2. Suricata (The NIDS)**

Suricata is the **Network Intrusion Detection System (NIDS)**. It monitors network traffic for malicious activity.

* **IR Role: Detection & Initial Evidence**
  * **Threat Detection:** It identifies known attack patterns (signatures), policy violations, and anomalous behavior on the network (e.g., C2 callbacks, exploit attempts, port scans).
  * **Evidence Gathering:** It provides crucial network-level evidence. If Wazuh detects a compromised host, Suricata's logs can show what other internal systems it was talking to, what data was exfiltrated, and what external IPs it contacted. This is vital for the **Containment** phase.

**3. TheHive (The IR Platform & Case Management)**

TheHive is the orchestrator and workflow engine for the IR team. It's where the actual response is managed.

* **IR Role: Orchestration, Coordination, and Documentation**
  * **Case Management:** When Wazuh generates a high-priority alert, it can be automatically forwarded to TheHive to create a new **incident case**. This becomes the single pane of glass for the entire investigation.
  * **Collaboration:** Multiple analysts can work on the same case, assigning tasks, adding notes, and sharing findings in real-time.
  * **Automation & Playbooks:** TheHive can execute pre-defined response playbooks (e.g., "isolate host," "block IP," "collect forensic data") often through integrations with other tools like Cortex (its usual analysis engine).
  * **Documentation:** It automatically logs all actions, findings, and timelines. This is critical for the **Post-Incident Activity** phase, ensuring you have a complete report for management, compliance, and improving future responses.

#### The IR Workflow in Practice

Here’s how the IR process flows through your stack:

1. **Detection:** Suricata sees an exploit attempt against a web server. Simultaneously, Wazuh on that server detects a new, suspicious process spawning.
2. **Alerting:** Wazuh correlates these two events and generates a high-severity alert: "Potential Web Server Compromise."
3. **Case Creation:** This alert is automatically sent to TheHive via an integration (like TheHive4py), creating a new case.
4. **Investigation (Analysis):** The IR team uses TheHive to:
   * **Triage:** Review the alert details from Wazuh.
   * **Enrich:** Use integrated tools (like VirusTotal or Shodan via Cortex) to analyze the malicious IP and file hashes.
   * **Scope:** Query Wazuh and Suricata to see if other systems are affected (lateral movement).
5. **Response (Containment/Eradication):** The team executes actions from within TheHive:
   * **Task:** "Isolate compromised server from network." This might be a manual task or an automated one triggering a script on the firewall.
   * **Task:** "Initiate forensic disk image for later analysis."
6. **Closure & Learning (Post-Incident):** TheHive's complete case log is used to write a report, leading to recommendations like: "Update our Wazuh rules to detect this specific TTP earlier" or "Patch all web servers against this vulnerability."

#### Conclusion

IR in the stack is the capability enabled by the seamless integration of all three technologies, supporting this entire NIST 800-61 lifecycle.

* **Wazuh** finds the badness.
* **Suricata** provides the network context.
* **TheHive** manages the human response to it.

Together, they transform isolated alerts into a managed, efficient, and documented Incident Response process, moving your security posture from passive monitoring to active defense. It's a fantastic open-source setup.

#### Resources

[Incident Handler's Handbook by Patrick Kral (SANS, Published: 21 Feb, 2012. PDF, 1.97MB)](https://www.sans.org/white-papers/33901)

[NIST SP 800-61 Rev. 2 (Computer Security Incident Handling Guide)](https://csrc.nist.gov/pubs/sp/800/61/r2/final)
