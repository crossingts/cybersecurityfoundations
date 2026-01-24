---
description: >-
  This lesson provides an implementable framework for designing an enterprise
  cybersecurity risk management program, the GRC program framework, based on the
  GRC governance framework
hidden: true
---

# The GRC approach to cybersecurity management

## Learning objectives

* Define the integrated GRC model and its role in aligning cybersecurity with business strategy, risk appetite, and legal obligations
* Explain the purpose of cybersecurity governance in establishing strategic direction, policy, and oversight mechanisms per the NIST CSF GOVERN function
* Distinguish between governance artifacts such as policies, standards, and procedures, and map them to frameworks like NIST SP 800-53 and 800-37
* Describe the cybersecurity risk management process of identifying, assessing, treating, and monitoring risks within an organization’s risk appetite
* Identify common risk management frameworks, including NIST SP 800-37 (RMF) and ISO/IEC 27001, and how they can be combined
* Outline the compliance function, focusing on validating controls through audits to meet regulatory and internal policy requirements
* Summarize the three-phase GRC program framework (Foundation, Risk Execution, Validation) and map it to the NIST CSF and RMF
* Articulate the continuous GRC lifecycle (Plan, Assess, Implement, Monitor, Review) as an operational model for cybersecurity management
* Describe the role of performance measures as a method to assess and improve GRC programs

This lesson explains the Governance, Risk, and Compliance (GRC) approach to cybersecurity management—an integrated model that aligns security activities with business strategy, systematically addresses cyber risk, and validates adherence to legal and internal obligations. It explores how these three disciplines converge to form a structured, risk-informed management system and provides an implementable framework for designing and operating a continuous enterprise cybersecurity program.

## Topics covered in this lesson

* **Introduction**&#x20;
* **Cybersecurity governance (G)**&#x20;
* **Cybersecurity risk management (R)**&#x20;
* **Cybersecurity compliance (C)**&#x20;
* **The GRC program framework**&#x20;
* **The GRC lifecycle in practice: A continuous process**&#x20;
* **The role of performance measures in GRC programs**

#### Introduction

GRC is an integrated capability that enables an organization to effectively achieve its strategic objectives (governance), address uncertainty (risk management), and act with integrity (compliance). GRC ensures that daily activities and strategic decisions are aligned with business goals through a structured, risk-informed approach to prioritizing and managing all risks, while simultaneously meeting legal and regulatory obligations. GRC is a comprehensive framework for enterprise risk management, of which cybersecurity risk is one critical category. Other categories include operational, financial, legal, and strategic risk.

The GRC approach to cybersecurity management (cybersecurity GRC) means applying this integrated enterprise model specifically to the domain of cybersecurity. It ensures cybersecurity activities are aligned with business strategy (Governance), that cyber risks are identified and treated in context with other business risks (Risk Management), and that security practices meet legal, regulatory, and internal policy obligations (Compliance).

#### Cybersecurity governance (G)

Cybersecurity governance defines the strategic direction, policies, and decision-making structures to ensure cybersecurity efforts—IT infrastructure, operations, and services—are aligned with business objectives and properly overseen.&#x20;

Via the executive leadership, cybersecurity governance defines roles and responsibilities and oversight mechanism to ensure that an organization's cybersecurity strategy, investments, and operations are aligned with business objectives, manage cyber risk to an acceptable level, and comply with relevant laws and regulations.

Governance answers the questions: "Who decides what? How do we ensure it happens? And how do we know it's working?" In this vein, it helps to outline key differences between governance and management.

**GRC Governance vs Management (Adapted From Educause.edu)**

| GRC Governance                                                                                                            | GRC Management                                                           |
| ------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------ |
| Governance: Doing the right thing                                                                                         | Management: Doing things right                                           |
| Oversight: Ensures risk management has an effective review and implementation structure                                   | Implementation: Eensures that controls are implemented to mitigate risks |
| Authorizes decision rights                                                                                                | Authorized to make decisions to mitigate risks                           |
| Enact policy (setting a course)                                                                                           | Enforce policy (steering)                                                |
| Accountability–specifies the accountability framework                                                                     | Responsibility                                                           |
| Strategic planning: Ensures that security strategies are aligned with business objectives and consistent with regulations | Project planning: Recommends security strategies                         |
| Resource allocation                                                                                                       | Resource utilization                                                     |

**Governance aligned with NIST CSF 2.0**

In the context of cybersecurity GRC, governance is the function of establishing, communicating, and monitoring the strategy, policy, and oversight mechanisms to ensure an organization's cybersecurity risk management decisions align with its business objectives and risk appetite.

The NIST Cybersecurity Framework (CSF) 2.0 defines this as the **GOVERN (GV)** Function, which is the foundation for all other functions (Identify, Protect, Detect, Respond, Recover). Its core purpose is to inform how an organization will make and execute its risk management decisions.

**Key NIST CSF Governance Categories:**

* **Organizational Context (GV.OC):** Integrating cybersecurity into business strategy and legal requirements. For example, the Governing Board declaring that "protecting customer data is a strategic priority."
* **Risk Management Strategy (GV.RM):** Establishing and communicating the organization's cybersecurity risk appetite, tolerance, and priorities. For example, leadership defining acceptable levels of financial or reputational risk from a data breach.
* **Roles, Responsibilities, and Authority (GV.RR):** Defining and assigning accountability for cybersecurity decisions, policies, and execution. Cybersecurity roles, responsibilities, and authorities are established, communicated, and enforced. This may involve formally assigning business unit leaders as data owners responsible for the security of their applications, and holding them accountable for outcomes.
* **Policy Management (GV.PO):** Creating, communicating, and maintaining the cybersecurity policy framework that guides actions and controls. Cybersecurity policies are established, communicated, and enforced. This may involve developing and issuing an **Acceptable Use Policy** or a **Data Classification Policy** that provides mandatory guidance for all personnel.
* **Oversight (GV.OV):** Implementing structures for reviewing, reporting, and adjusting the organization's cybersecurity strategy, policy, and risk posture. For example, the CISO may be required to present a quarterly risk report to the Board's Audit Committee and using it to direct resources or adjust strategy.

In essence, governance provides the direction, rules, and accountability that enable effective risk management and compliance.

NIST defines CSF as a set of cybersecurity activities, desired outcomes, and applicable informative references common across critical infrastructure sectors. In general, the CSF is a good starting point for organizations that are new to cybersecurity or that are looking to improve their overall cybersecurity posture.

NIST CSF 2.0 gives a high-level definition of governance. The CSF's GOVERN (GV) function provides the strategic outcomes (e.g., "policy is established," "roles are assigned"). But it leaves specific artifacts like policies, standards, and baselines as implementation details for the organization to define.

Governance flows from strategic outcomes to concrete artifacts. To bridge from the CSF governance outcomes to the concrete governance artifacts of policies, standards, and procedures, we need to look at the frameworks that provide the control language and implementation processes. The two most popular and directly relevant NIST frameworks for this are:

* NIST SP 800-53 (Security and Privacy Controls)
* NIST SP 800-37 (Risk Management Framework)

The NIST 800 series is a set of documents that describe U.S. federal government computer security policies, procedures, and guidelines.

[Which of the NIST SP 800-Series Publications Should You Follow?](https://www.schellman.com/blog/nist-sp-800-series-publications-follow) (Doug Stonier and Tim Walsh, 2022)

**From strategic outcomes to concrete artifacts**

NIST SP 800-53 (the controls) and NIST SP 800-37 (the process for implementing them) are the two frameworks that provide the critical bridge from CSF's strategic governance to the tangible, actionable artifacts.

Governance establishes the strategic direction and rules. A core part of this is defining commitments and requirements. This is done through a hierarchy of documents:

* **Policies**: High-level statements of management intent, derived from business objectives and risk appetite. They answer "What must we do and why?" For example, "We shall protect customer data confidentiality and comply with all applicable laws."
  * NIST Link: This fulfills CSF GV.PO ("Cybersecurity policies are established..."). The CIS/MS-ISAC NIST Cybersecurity Framework Policy Template Guide provides a practical resource for developing such policies, mapping CSF requirements directly to template documents.
* **Standards**: Mandatory, detailed requirements that must be followed to comply with the policy. They often reference external frameworks. For example, "To protect data, all systems handling sensitive data shall adhere to the CIS Critical Security Controls (CIS CSC) v8 and the relevant NIST SP 800-53 control baselines."
  * NIST Link: SP 800-53 is the definitive standard for control requirements. Your governance body selects, tailors, and supplements controls from it. Choosing "CIS or STIG" as your configuration baselines is an act of governance that defines your technical standards.
* **Procedures**: Step-by-step instructions for personnel to implement standards and configure technologies. For example, "Procedure P-001: Installing a Windows Server in accordance with STIG benchmarks."
  * NIST Link: SP 800-53 controls (like `CM-6 Configuration Settings`) require procedures for implementation. SP 800-37's IMPLEMENT step is where these procedures are executed.
* **Guidelines**: Recommended, non-mandatory approaches for meeting standards, offering flexibility. For example, "Guideline for selecting multi-factor authentication solutions."
  * NIST Link: Can be considered part of the organizational security and privacy architecture informed by governance.

**Mapping Governance Artifacts to Popular NIST Frameworks**

| **Governance Artifact**                | **Purpose**                                        | **Which NIST Framework(s) Define/Use It?**                                                                                                                                                                                                                                                                               |
| -------------------------------------- | -------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Policy**                             | States commitment & "what" must be done.           | <p><strong>NIST CSF (GV.PO):</strong> Requires it as an outcome.<br><strong>CIS/MS-ISAC NIST Cybersecurity Framework Policy Template Guide:</strong> Provides policy templates and structure.</p>                                                                                                                        |
| **Standards**                          | Defines mandatory rules & control sets.            | <p><strong>NIST SP 800-53:</strong> <strong>The primary source.</strong> It <strong>is</strong> the control standard. Governance selects from it.<br><strong>NIST SP 800-37 (Prepare):</strong> The process where controls (standards) are selected and tailored.</p>                                                    |
| **Procedures**                         | Provides step-by-step implementation instructions. | <p><strong>NIST SP 800-53:</strong> Individual controls (e.g., <code>AC-2 Account Management</code>) require "procedures" to implement.<br><strong>NIST SP 800-37 (Implement):</strong> The process step where procedures are executed.</p>                                                                              |
| **Guidelines & Baselines (CIS, STIG)** | Provides recommended configurations & benchmarks.  | <p><strong>NIST SP 800-53:</strong> References industry best practices. Controls like <code>CM-6</code> explicitly require using security configuration baselines.<br><strong>NIST SP 800-70:</strong> National Checklist Program – the repository for benchmarks like STIGs, showing how they map to NIST controls.</p> |

In practice, governance is the process of defining requirements and commitments, then specifying how to achieve them. It begins with establishing high-level policies that state strategic intent (the "what and why"). To fulfill these policies, governance mandates specific standards, often by selecting control sets from authoritative sources like NIST SP 800-53. These standards are then made actionable through detailed procedures (the "how") and supported by recommended guidelines and technical baselines.

This flow creates a clear governance cascade: from the strategic outcomes of the NIST CSF GOVERN function, to a written policy, to chosen control standards, and finally to implemented procedures. This entire process—selecting control catalogs, tailoring them, and defining implementation steps—is itself governed by the structured workflow of the NIST SP 800-37 Risk Management Framework. Thus, governance encompasses the full spectrum from declaring a commitment to protecting data, to defining the exact rules and configurations that make that commitment a reality.

#### Cybersecurity risk management (R)

Managing cybersecurity is about managing risk to information assets valued by an organization. Risk can be understood as the likelihood of a security breach compromising the confidentiality, integrity, or availability of information assets multiplied by the potential impact of the breach.

According to NIST SP 800-30 (Guide for Conducting Risk Assessments), risk assessment is a process of identifying, estimating, and prioritizing risks to organizational operations, assets, and individuals. It starts with identifying what the organization values (assets). NIST SP 800-30 defines risk as a function of:

* Likelihood of Occurrence: The probability that a given threat source will exploit a vulnerability.
* Impact of Occurrence: The magnitude of harm resulting from the exploitation of a vulnerability.

As discussed, governance is the overarching discipline, and a key component of governance is establishing a risk management strategy. In a cybersecurity context, this entails establishing, agreeing to, and communicating the organization's cybersecurity risk appetite (the amount of financial or reputational risk an organization is willing to accept from a potential data breach) and priorities.

Risk management is a process of identifying, assessing, prioritizing, and treating organizational cybersecurity risks within the organization's risk appetite. An identified risk can be mitigated, accepted, avoided, or transferred. Risk management entails having a structured and comprehensive cybersecurity risk management process that is integrated into an organization's enterprise risk management (ERM) program. Frameworks such as COBIT and ISO/IEC 27005 provide models for integrating cybersecurity risk management with overall ERM.

* COBIT (Control Objectives for Information and Related Technologies), published by ISACA, is a holistic governance and management framework for enterprise IT. It explicitly integrates enterprise risk management (from the COBIT `APO12` – Manage Risk process) with cybersecurity and IT objectives.
* ISO/IEC 27005 is the specialized standard for the process of information security risk management. It fits within the larger ISMS structure of ISO/IEC 27001. Using this standard ensures your cybersecurity risk process aligns with international best practices and can be audited for certification.

A NIST Risk Management Framework (RMF) is commonly used to quantify operational risk – to help “ensure that an enterprise understands the true risks to the key assets behind its day-to-day operations and how best to mitigate them” (Cobb, 2019).

The RMF NIST SP 800-37 was developed to provide federal agencies and contractors with guidance on implementing risk management programs. NIST Special Publication 800-37 Rev2 (Risk Management Framework for Information Systems and Organizations: A System Life Cycle Approach for Security and Privacy) provides a structured seven-step process for integrating security and privacy into enterprise systems: Prepare, Categorize, Select, Implement, Assess, Authorize, and Monitor.

NIST SP 800-37 Rev2 is a prime example of a structured methodology that operationalizes the principles of Governance, Risk Management, and Compliance (GRC) for cybersecurity. NIST SP 800-53 provides the catalog of security and privacy controls that are selected in Step 3 (Select) of NIST SP 800-37 Rev2.

A risk management process helps companies predict potential problems and minimize losses. For example, you can use risk assessment to find security loopholes in your computer system and apply a fix. Information security testing is used to identify and assess the risks to an organization's information assets. This information is then used to develop and implement security controls to mitigate those risks.

NIST SP 800-30 and NIST SP 800-115 (Technical Guide to Information Security Testing and Assessment) work together exceptionally well. They are complementary tools in the risk management and security assessment toolkit. NIST SP 800-30 is the process for identifying, estimating, and prioritizing risks. NIST SP 800-115 is the how-to manual for the actual technical activities (testing, review, examination) that gather the vulnerability data.

Risk management frameworks (RMFs) are frequently combined to streamline and integrate compliance controls into daily operations and the organizational structure. For example, organizations often implement the NIST SP 800-37 RMF process and select the appropriate subset of security controls from the NIST SP 800-53 control catalog. Others use the NIST Cybersecurity Framework (CSF) as their overarching RMF and employ NIST SP 800-30 to conduct the detailed risk assessments that inform it. Similarly, a common approach is to adopt ISO/IEC 27001 as the certifiable RMF and use ISO/IEC 27002 as the essential reference guide for implementing its required controls. Frameworks can also be integrated with industry standards, such as aligning an ISO/IEC 27001 Information Security Management System (ISMS) with the requirements of the Payment Card Industry Data Security Standard (PCI DSS).

#### Cybersecurity compliance (C)

Compliance is the function of developing and implementing procedures and controls to ensure that business activities adhere to external regulations, industry standards, and internal policies. In cybersecurity GRC, this specifically means validating that IT systems and data are secured according to these mandated requirements. For example, a healthcare organization must comply with laws like HIPAA to protect patient privacy, while a retailer processing credit cards must follow the PCI DSS standard.

Compliance is demonstrated and assured through systematic auditing and reporting. These processes provide evidence of due care to oversight bodies—such as an internal board or external regulators—and help the organization avoid legal penalties and reputational damage. Compliance audits verify that the defined controls and procedures are correctly implemented and effective. In essence, while governance sets the rules and risk management identifies the threats, compliance answers the critical question: "Are we following the rules effectively?" Compliance determines: "We have audited the 157 controls for Regulation X. 150 are operating effectively and 7 are failing. Here is the report for the board."

**The compliance audit process**

A compliance audit is a formal, structured review to verify that security controls are **correctly implemented and operating effectively**. The process typically follows a cycle aligned with general audit standards and frameworks such as NIST SP 800-53A (Assessing Security and Privacy Controls) and ISO/IEC 27007 (Guidelines for Information Security Management Systems Auditing). The key steps are:

1. **Planning & Scoping**: The audit team defines the objective, scope, and criteria (e.g., "Audit access controls against PCI DSS Requirement 8"). This involves identifying the specific systems, policies, and regulations in scope.
2. **Evidence Collection**: Auditors gather objective evidence through interviews, document reviews (policies, procedures), technical testing (vulnerability scans, configuration checks), and observation of activities.
3. **Evaluation & Testing**: The collected evidence is evaluated against the audit criteria. Auditors test whether controls are present and function as intended, not just documented.
4. **Reporting & Documentation**: Findings are documented in a formal report. This includes detailing compliant areas, identifying non-conformities (failures), and providing evidence-based conclusions.
5. **Management Response & Follow-up**: Management addresses the audit findings by creating a corrective action plan. A follow-up audit is often conducted to verify that identified issues have been remediated.

This cyclical process transforms compliance from a static checklist into a dynamic mechanism for continuous validation and improvement, closing the loop within the broader GRC lifecycle.

**The compliance management lifecycle**

Achieving compliance is a continuous cycle integrated into business operations. This lifecycle manages compliance from initial scoping through to ongoing maintenance:

1. **Scope Definition**: Identifying which regulations, standards (e.g., HIPAA, PCI DSS, GDPR), and internal systems/data are in scope for the compliance program.
2. **Readiness/Gap Assessment**: Comparing current security controls and procedures against the requirements of the in-scope frameworks to identify deficiencies ("gaps").
3. **Gap Remediation**: Prioritizing and implementing new controls, updating processes, and modifying configurations to close the identified gaps.
4. **Testing and Validation**: Verifying that remediated controls work as intended. This phase often culminates in a formal **compliance audit** (as described above) to obtain independent assurance and certification.
5. **Ongoing Monitoring and Recertification**: Continuously monitoring controls for effectiveness, managing changes, and preparing for periodic re-audits to maintain certification status.

This lifecycle is formalized in standards like **ISO/IEC 27001**, which requires establishing, implementing, maintaining, and continually improving an Information Security Management System (ISMS). It demonstrates that compliance is a managed business process within the GRC model, directly informed by governance rules and driven by risk management priorities.

#### The GRC program framework

The first, foundational step in risk management is establishing the GRC program framework. Here are the three main phases of the framework.

**Phase 1: Foundation & Strategy (Governance)**

• Define who is involved/stakeholders: Oversight (Board), decision makers (CISO, Risk Committee), employees, IT crew, etc.). Their input is critical for defining what is valuable and what level of risk is acceptable.

• Set the organization's risk appetite. Leadership defines "how much risk are we willing to accept?"

• Identify relevant regulations and standards. Based on business model and geography (e.g., GDPR, HIPAA, NIST CSF, PCI DSS). This defines the "rules of the road" you must follow. This identifies the mandatory and voluntary frameworks that will shape the program.

• Define commitment in policy ("We shall protect data in accordance with FISMA and design a risk management program guided by NIST CSF").

• Set the organization's risk tier:

* Risk Appetite & Tolerance: Define the amount and type of risk the organization is willing to accept. This sets the bar for all subsequent risk evaluations.
* Taxonomy & Criteria: Agree on definitions (e.g., scales for impact and likelihood) so a "High" risk means the same thing to everyone.

• Select the assessment methodology, e.g., NIST RMF (NIST SP 800-37 Rev2).

At this phase, you select the overarching methodology (e.g., the NIST RMF) and identify the control catalogs you will reference (e.g., NIST SP 800-53). You are not yet choosing specific controls.

**Phase 2: Risk Management Execution (The "R" Cycle)**

• Assess risk. Using your chosen methodology, identify and analyze risks (threats & vulnerabilities). Prioritize them using your risk tiers and appetite.

• Treat risk: mitigate, accept, avoid, transfer. If mitigating:

• Select suitable controls (e.g., "To mitigate this data breach risk, we will implement specific controls so and so from the NIST SP 800-53").

**Phase 3: Implementation & Validation (Compliance)**

This is the execution and verification of risk treatment decisions.

• Implement controls (technical, procedural, physical).

• Audit compliance (compliance is one way to treat risks; compliance validates a subset of the risk appetite).

Monitor and test that the implemented controls are working as designed. Internal or external audits validate that your controls meet the requirements of the relevant regulations/standards, thereby proving you are operating within your risk appetite.

Here is a mapping of the GRC management framework phases to the NIST CSF 2.0 and the NIST SP 800-37 Rev2 RMF.

| **GRC Framework Phase & Step**                                                       | **Mapping to NIST CSF (Functions & Categories)**                                                | **Mapping to NIST SP 800-37 RMF (Steps)**                                                         |
| ------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------- |
| **PHASE 1: Foundation & Strategy (Governance)**                                      | **Function: GOVERN (GV)**                                                                       | **Step 1: PREPARE**                                                                               |
| • Define Stakeholders & Oversight                                                    | **GV.001:** Organizational context is established and communicated.                             | • Essential activities at the Org, Mission, and System Level.                                     |
| • Set Risk Appetite & Tolerance                                                      | **GV.002:** Cybersecurity risk management strategy is established, agreed to, and communicated. | • Establish context and priorities.                                                               |
| • Identify Regulations & Standards                                                   | **GV.014:** Cybersecurity requirements are identified, prioritized, and resourced.              | • **Step 2: CATEGORIZE**                                                                          |
| • Define Commitment in Policy                                                        | **GV.001, GV.013:** Policies, processes, and procedures are established.                        | • **SP 800-37 Task P-1:** Prioritize and scope risk management activities.                        |
| • Define Risk Taxonomy & Criteria                                                    | **GV.008:** Risk assessment processes are established.                                          | • **SP 800-37 Task P-8:** Prepare for control selection.                                          |
| • Select Assessment Methodology & Control Catalogs                                   | **GV.004:** Governance and risk management processes address cybersecurity risks.               | • **SP 800-37 Task P-9:** Select, tailor, and supplement controls. (High-level catalog selection) |
| **PHASE 2: Risk Management Execution (The "R" Cycle)**                               | **Function: IDENTIFY (ID)** & **RESPOND (RS)**                                                  | **Step 3: SELECT** & **Step 4: IMPLEMENT**                                                        |
| • **Assess Risk:** Identify, analyze, prioritize                                     | **ID.RA:** Risk Assessment. Assets, threats, vulnerabilities, likelihood, impact are analyzed.  | • **Step 3: SELECT** Controls.                                                                    |
| • **Treat Risk:** Mitigate, accept, avoid, transfer. Select controls for mitigation. | **RS.RP:** Response Planning. Processes are executed.                                           | • **SP 800-37 Task S-2:** Select controls.                                                        |
|                                                                                      |                                                                                                 | • **Step 4: IMPLEMENT** Controls.                                                                 |
|                                                                                      |                                                                                                 | • **SP 800-37 Task I-1:** Implement controls in plans.                                            |
| **PHASE 3: Implementation & Validation (Compliance)**                                | **Functions: PROTECT (PR), DETECT (DE), GOVERN (GV)** & **RECOVER (RC)**                        | **Step 5: ASSESS, Step 6: AUTHORIZE, Step 7: MONITOR**                                            |
| • **Implement Controls** (technical, procedural, physical)                           | **PR.IP:** Protective Technology & Processes are maintained.                                    | • **Step 4 (cont.): IMPLEMENT** Controls (execution).                                             |
| • **Audit & Monitor Compliance;** Test controls                                      | DE.CM: Security continuous monitoring.                                                          | • **Step 5: ASSESS** Controls.                                                                    |
|                                                                                      | **GV.011:** Cybersecurity compliance is verified and reported.                                  | • **SP 800-37 Task A-1:** Assess controls.                                                        |
|                                                                                      |                                                                                                 | • **Step 6: AUTHORIZE** System/Operation.                                                         |
|                                                                                      |                                                                                                 | • **SP 800-37 Task R-1:** Accept risk.                                                            |
|                                                                                      |                                                                                                 | • **Step 7: MONITOR** Controls & Risks.                                                           |
|                                                                                      |                                                                                                 | • **SP 800-37 Task M-1:** Monitor system & environment.                                           |

NIST CSF provides the broad risk management structure and outcomes. The GOVERN function encapsulates Phase 1. The execution and validation phases map to the other CSF Functions (Identify, Protect, Detect, Respond, Recover), showing what needs to be achieved. NIST SP 800-37 provides the specific process for implementing the GRC program. Its PREPARE and  CATEGORIZE steps fulfill the foundational governance activities of Phase 1. The core risk management actions of Phase 2 are carried out in the RMF's SELECT and  IMPLEMENT steps. Finally, the compliance validation of GRC Phase 3 is achieved through the ASSESS, AUTHORIZE, and MONITOR steps of the RMF.

In essence:

* Phase 1 (Governance) sets the strategy, rules, and context that feed directly into the NIST CSF GOVERN function and the RMF PREPARE and CATEGORIZE steps.
* Phase 2 (Risk Management) is the core of the RMF SELECT and IMPLEMENT steps, guided by the CSF IDENTIFY function.
* Phase 3 (Validation) is realized through the RMF ASSESS, AUTHORIZE, and MONITOR steps, achieving outcomes in the CSF PROTECT, DETECT, and GOVERN functions.

#### The GRC lifecycle in practice: A continuous process

The GRC lifecycle can be seen as a Plan-Do-Check-Act (PDCA) model. A more concrete way to view this is as a process of "plan, assess, implement, monitor, review".

In plan: Identify/define the governance elements (strategic direction, policies, and decision-making structures). In assess: Understand the threat landscape/assess cybersecurity risk. Identify what you need to protect and from whom. In implement: Deploy controls. In monitor: Check logs, compliance audits. In review: Assess need for efficiency/improvement.

These phases can be mapped to the risk assessment process within the cybersecurity risk management tenet of GRC.

**The GRC Lifecycle in Practice**

| **GRC Lifecycle Phase**                   | **Application to Cybersecurity (GRC Approach)**                                       | **Example Artifacts & Activities**                                                                                                                                                                                                                                                                                             |
| ----------------------------------------- | ------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **1. Plan (Align, Plan, Strategize)**     | Identify/define decision making structure and policies.                               | <p>• <strong>Cybersecurity Strategy Document</strong><br>• <strong>Board-level charter for the CISO</strong><br>• <strong>Inventory of applicable regulations</strong> (e.g., NYDFS, PCI DSS, HIPAA).</p>                                                                                                                      |
| **2. Assess (Assess & Analyze)**          | **Understand the threat landscape.** Identify what you need to protect and from whom. | <p>• <strong>Asset Inventory</strong> (data, systems, devices)<br>• <strong>Threat Modeling</strong><br>• <strong>Vulnerability Assessments &#x26; Penetration Tests</strong><br>• <strong>Cybersecurity Risk Register</strong> (rated by likelihood/impact).</p>                                                              |
| **3. Implement (Design & Implement)**     | **Build and deploy your defenses.** Translate assessed risks into concrete controls.  | <p>• <strong>Security Policies &#x26; Standards</strong> (e.g., password policy, encryption standard)<br>• <strong>Security Architecture &#x26; Tool Deployment</strong> (firewalls, EDR, SIEM)<br>• <strong>Security Awareness Training Programs</strong><br>• <strong>Incident Response Plan (IRP) development.</strong></p> |
| **4. Monitor (Monitor, Test, Report)**    | **Ensure defenses are working.** Detect incidents and provide assurance.              | <p>• <strong>24/7 Security Operations Center (SOC) monitoring</strong><br>• <strong>SIEM alerts and dashboards</strong><br>• <strong>Regular control testing</strong> (e.g., phishing simulations)<br>• <strong>Compliance audit reports &#x26; KRIs</strong> (e.g., mean time to detect).</p>                                 |
| **5. Review (Review, Optimize, Improve)** | **Learn and adapt.** Evolve your program based on lessons learned and new threats.    | <p>• <strong>Post-Incident Review (PIR) reports</strong><br>• <strong>Updates to the IRP based on tabletop exercises</strong><br>• <strong>Adjusting risk ratings after a major new vulnerability</strong> (e.g., Log4Shell)<br>• <strong>Maturity assessments against frameworks like NIST CSF or CMMC.</strong></p>          |

#### The role of performance measures in GRC programs

An effective GRC program requires continuous evaluation and refinement. Performance measures serve as the essential feedback mechanism, providing quantifiable data to assess the effectiveness of the program. They are the critical link between daily activities and strategic objectives, enabling informed decision-making during the Review (Review, Optimize, Improve) phase of the GRC lifecycle.

Defined metrics allow an organization to objectively determine if its GRC program is achieving its intended goals. Performance measures answer pivotal questions:

* Is our governance effective? (e.g., Are policies being adopted?)
* Is our risk management working? (e.g., Are we reducing our exposure?)
* Are we in compliance? (e.g., Are controls operating effectively?)
* Where should we optimize resources?

Two primary categories of metrics are used to assess GRC programs:

Key Performance Indicators (KPIs): Measure the performance and efficiency of security processes and controls. They indicate how well the organization is executing its GRC activities. Example: Percentage of systems configured according to security baselines, mean time to patch critical vulnerabilities, employee completion rate for security awareness training.

Key Risk Indicators (KRIs): Measure changes in the organization's risk exposure. They are forward-looking metrics that signal a potential increase in risk likelihood or impact, serving as an early warning system. Example: Number of high-risk vulnerabilities exceeding SLA for remediation, volume of phishing attempts detected, frequency of policy exceptions requested.

Performance measures are integral to the "Check" and "Act" components of the Plan-Do-Check-Act (PDCA) model embodied in the GRC lifecycle.

* **Monitor (Check):** During this phase, KPIs and KRIs are collected and reported through dashboards and compliance audits. This continuous monitoring provides the raw data on program performance and risk posture.
* **Review (Act):** This is where performance measures realize their full value. Leadership and the GRC team analyze the metrics to:
  * **Assess:** Compare current performance against targets and risk appetite.
  * **Identify Gaps:** Pinpoint ineffective controls, inefficient processes, or emerging risk trends.
  * **Optimize & Improve:** Make data-driven decisions to reallocate resources, update policies, enhance controls, or revise the risk management strategy. For instance, a consistent KPI showing slow patch deployment would trigger a review and improvement of the vulnerability management process.

Performance measures close the loop in the continuous GRC process. They provide the evidence needed to move from simply **having** a program to **continuously improving** one, ensuring that cybersecurity GRC remains aligned with, and responsive to, the evolving business and threat landscape.

#### References

CIS Center for Internet Security. (2024). NIST Cybersecurity Framework: Policy Template Guide. Retrieved January 24, 2026, from https://www.cisecurity.org/-/media/project/cisecurity/cisecurity/data/media/files/uploads/2024/08/cis-ms-isac-nist-cybersecurity-framework-policy-template-guide-2024.pdf

Cobb, M. (June 2019). 5 ways to achieve a risk-based security strategy. Retrieved December 20, 2019, from https://searchsecurity.techtarget.com/tip/5-ways-to-achieve-a-risk-basedsecurity-strategy

[GRACE-IT – The “Critical Six” disciplines of GRC](https://www.oceg.org/about/people-like-you/) (oceg.org)

[Information Security Governance](https://www.educause.edu/focus-areas-and-initiatives/policy-and-security/cybersecurity-program/resources/information-security-guide/toolkits/information-security-governance) (EDUCAUSE, 2022)

[NIST SP 800-37 Rev. 2](https://csrc.nist.gov/pubs/sp/800/37/r2/final) (Risk Management Framework)

[NIST Special Publications](https://itlaw.fandom.com/wiki/NIST_Special_Publications) (Repo by The IT Law Wiki)

[The GRC approach to managing cybersecurity](https://www.coursera.org/learn/grc-approach-to-managing-cybersecurity) (Coursera course)
