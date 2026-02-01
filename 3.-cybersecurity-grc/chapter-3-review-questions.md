---
hidden: true
---

# Chapter 3 review questions

### Key cybersecurity regulations and standards

**1. Define the difference between a cybersecurity regulation and an industry standard, and provide an example of each.**\
**Answer:**\
A cybersecurity regulation is a statutory law created and enforced by a governmental body. Compliance is mandatory, and non-compliance results in legal penalties. Example: The EU General Data Protection Regulation (GDPR). An industry standard is a framework or set of controls developed by industry groups or standards bodies. Its authority is contractual or voluntary, becoming binding when included in an agreement. Example: The Payment Card Industry Data Security Standard (PCI DSS).

**2. Explain the purpose of the General Data Protection Regulation (GDPR) and describe one of its key principles.**\
**Answer:**\
The GDPR is a comprehensive EU data privacy law designed to protect the personal data and privacy of individuals in the European Union. Its purpose is to give individuals control over their personal data and to harmonize data privacy laws across Europe. One of its seven key principles is purpose limitation, which means personal data can only be collected for specified, explicit, and legitimate purposes and not further processed in a manner incompatible with those purposes.

**3. Describe the primary goal of the NIST Cybersecurity Framework (CSF) and list its six core functions.**\
**Answer:**\
The primary goal of the NIST Cybersecurity Framework (CSF) is to provide a voluntary, risk-based framework to help organizations manage and reduce their cybersecurity risk. It helps organizations align their security activities with business needs, risk tolerances, and resources. Its six core functions are: Govern, Identify, Protect, Detect, Respond, and Recover.

**4. Explain what a SOC 2 Type II report assesses and who its primary intended audience is.**\
**Answer:**\
A SOC 2 Type II report assesses the operational effectiveness of a service organization's controls over a specified period of time, typically 6 to 12 months. It evaluates whether the controls are not only suitably designed but also functioning correctly over that period. Its primary intended audience is the organization's management, existing clients, and prospective clients, who receive the detailed report under a non-disclosure agreement.

**5. Describe the tiered structure of the Cybersecurity Maturity Model Certification (CMMC) 2.0 and what each level is designed to protect.**\
**Answer:**\
CMMC 2.0 has a three-level tiered structure. Level 1 (Foundational) is designed to protect Federal Contract Information (FCI) and requires 17 basic practices. Level 2 (Advanced) is designed to protect Controlled Unclassified Information (CUI) and aligns with the 110 security controls from NIST SP 800-171. Level 3 (Expert) is designed to protect CUI within high-priority programs and adds controls from NIST SP 800-172 to defend against advanced persistent threats.

### The GRC approach to cybersecurity management

**1. Define the three core components of the integrated GRC model and describe the primary focus of each.**\
**Answer:**\
The three core components are Governance, Risk Management, and Compliance. Governance focuses on establishing strategic direction, policies, and oversight to align cybersecurity with business objectives. Risk Management focuses on identifying, assessing, treating, and monitoring cybersecurity risks within the organization's risk appetite. Compliance focuses on validating that security controls and practices meet legal, regulatory, and internal policy obligations.

**2. Explain the primary purpose of the GOVERN (GV) Function in the NIST Cybersecurity Framework (CSF) 2.0 and name one of its key Categories.**\
**Answer:**\
The primary purpose of the GOVERN (GV) Function is to establish, communicate, and monitor the strategy, policy, and oversight mechanisms that inform how an organization makes and executes its cybersecurity risk management decisions. It serves as the foundation for all other CSF functions (Identify, Protect, Detect, Respond, Recover). One of its key Categories is Risk Management Strategy (GV.RM), which involves establishing and communicating the organization's cybersecurity risk appetite and tolerance.

**3. Describe the four common options for treating a cybersecurity risk identified during the risk management process.**\
**Answer:**\
The four common treatment options are Mitigate, Accept, Avoid, and Transfer. Mitigate involves implementing security controls to reduce the likelihood or impact of the risk. Accept is the conscious decision to take no action after determining the risk falls within the organization's established risk appetite. Avoid entails eliminating the risk entirely by discontinuing the risky activity. Transfer shifts the financial burden of the risk to a third party, typically through cybersecurity insurance.

**4. List the five typical steps in a formal compliance audit process and describe one key activity in the first step.**\
**Answer:**\
The five typical steps are: 1) Planning & Scoping, 2) Evidence Collection, 3) Evaluation & Testing, 4) Reporting & Documentation, and 5) Management Response & Follow-up. A key activity in the first step (Planning & Scoping) is defining the audit objective, scope, and criteria, which involves identifying the specific regulations, systems, and controls to be evaluated (e.g., "Audit access controls against PCI DSS Requirement 8").

**5. Distinguish between a Key Performance Indicator (KPI) and a Key Risk Indicator (KRI) in the context of GRC program measurement, and provide an example of each.**\
**Answer:**\
A Key Performance Indicator (KPI) measures the performance and efficiency of security processes and controls, indicating how well GRC activities are being executed. An example is the mean time to patch critical vulnerabilities. A Key Risk Indicator (KRI) is a forward-looking metric that measures changes in the organization's risk exposure, serving as an early warning signal. An example is the number of high-risk vulnerabilities exceeding the remediation SLA.

### The information security risk assessment

**1. Describe the fundamental purpose of an information security risk assessment and explain its value within a GRC program.**  
**Answer:**  
The fundamental purpose of a risk assessment is to systematically identify, analyze, and evaluate risks to information assets to answer key questions about what is valuable, what could go wrong, how bad it would be, and what to do about it. Its value within a GRC program is that it provides the evidence-based foundation for informed decision-making, guiding control selection, prioritizing compliance efforts, justifying security investments, and measuring changes in risk posture over time.

**2. Compare and contrast qualitative and quantitative risk assessment methodologies, including one primary advantage of each.**  
**Answer:**  
Qualitative risk assessment uses subjective scales (e.g., High, Medium, Low) based on expert judgment and consensus. Its primary advantage is that it is faster and easier to perform, making it effective for communication. Quantitative risk assessment uses numerical values and calculations (e.g., financial loss expectations). Its primary advantage is that it provides objective data for cost-benefit analysis, which is useful for justifying budgets and making precise financial decisions.

**3. List and briefly define the four primary risk treatment options. Provide a distinct example for the "Mitigate" option.**  
**Answer:**  
The four primary risk treatment options are:

- **Mitigate:** Implement controls to reduce the likelihood or impact of the risk.
- **Accept:** Formally acknowledge and consciously take no action, as the risk falls within the organization's risk appetite.
- **Avoid:** Eliminate the risk entirely by discontinuing the risky activity.
- **Transfer:** Shift the financial burden to a third party (e.g., via cyber insurance).  
    **Example of Mitigate:** To mitigate the risk of credential theft from phishing, implement a mandatory multi-factor authentication (MFA) control.

**4. Outline the key steps in a standardized risk assessment process, from preparation through to treatment recommendation.**  
**Answer:**  
A standardized risk assessment process typically includes these key steps:

1. Prepare for Assessment (scoping, planning, and team assembly).
2. Identify Assets and characterize the system.
3. Identify Threats and Vulnerabilities.
4. Analyze existing or planned Controls.
5. Determine the Likelihood and Impact for each threat-vulnerability pair.
6. Calculate and Prioritize the level of risk.
7. Recommend and Document risk Treatment options.

**5. Explain the role of the Risk Register in the risk management lifecycle and list three key pieces of information it should contain for a documented risk.**  
**Answer:**  
The Risk Register is the central, living document that tracks identified risks through their entire lifecycle. It connects the assessment phase to treatment and monitoring, enabling continuous risk management by recording a risk's status, owner, and treatment plan over time.  
**Three key pieces of information it contains for a risk are:**

1. Risk Description (including affected assets and threat-vulnerability pair).
2. Risk Rating (both Inherent and Residual, based on likelihood and impact).
3. Risk Owner and Recommended Treatment/Action Plan.

### The compliance audit

**1. Define a cybersecurity compliance audit and explain how it differs fundamentally from a risk assessment.**  
**Answer:**  
A cybersecurity compliance audit is a systematic, independent process for obtaining and evaluating objective evidence to determine the extent to which an organization meets defined compliance criteria (e.g., regulations, standards, internal policies). Unlike a risk assessment, which is forward-looking to _identify_ potential vulnerabilities and threats, an audit is backward-looking to _validate_ that specific, mandated controls are correctly implemented and operating effectively.

**2. Describe the key difference between an internal audit and a third-party audit, including a typical objective for each.**  
**Answer:**  
An internal audit is conducted by or for the organization itself (e.g., by an internal audit department) to provide management with independent assurance and to prepare for external scrutiny. A third-party audit is performed by an independent, accredited organization (e.g., a PCI QSA) to provide objective certification or attestation to external stakeholders. An internal audit's objective might be to evaluate control effectiveness for management review, while a third-party audit's objective is often to achieve a formal certification like ISO 27001.

**3. Outline the five-phase audit process and state the primary goal of the "Follow-up" phase.** 
**Answer:**  
The five-phase audit process is: 1) Planning & Scoping, 2) Evidence Collection, 3) Testing & Evaluation, 4) Reporting & Documentation, and 5) Management Response & Follow-up. The primary goal of the "Follow-up" phase is to verify that the corrective actions outlined in the management's Corrective Action Plan (CAP) have been effectively implemented, thereby closing the audit loop and ensuring findings are remediated.

**4. Explain two common methodologies an auditor uses during the Evidence Collection phase and provide an example of each.**  
**Answer:**  
Two common methodologies are:

- **Document Review:** Examining written records for evidence of control operation. _Example:_ Reviewing system configuration change logs to verify a formal change management process was followed.
- **Technical Testing:** Using tools to independently verify control settings. _Example:_ Running a CIS-CAT benchmark scan on a server to confirm its configuration matches the hardened security baseline.

**5. Explain the role of the Corrective Action Plan (CAP) and why it must include Preventive Actions, not just Corrective Actions.**  
**Answer:**  
The Corrective Action Plan (CAP) is the auditee's formal project plan for addressing audit findings. It must include Preventive Actions to address the root cause of a finding and prevent its recurrence, rather than just Corrective Actions which fix the immediate symptom. For example, a CAP would not only correct a specific orphaned user account (corrective action) but also implement an automated user lifecycle management tool to prevent future orphaned accounts (preventive action). This ensures long-term compliance and closes the control gap.