# FISMA compliance roadmap

What compliance frameworks can be helpful for organizations who want to comply with FISMA (to help them translate requirements into actionable technical controls)?

For organizations needing to comply with the **Federal Information Security Management Act (FISMA)**, the primary goal is to protect federal information and systems. FISMA itself doesn't provide a detailed checklist; it mandates the use of **standards and guidelines developed by the National Institute of Standards and Technology (NIST)**.

Therefore, the most direct and helpful "frameworks" are the NIST publications. These are not just helpful—they are the **required roadmap** for FISMA compliance. Other frameworks can be used as complementary or structuring tools.

Here are the key compliance frameworks and publications, categorized by their role:

#### 1. The Mandatory & Foundational Framework: NIST Special Publication (SP) 800 Series

This is the non-negotiable core. You build your technical controls directly from here.

* **NIST SP 800-53 (Security and Privacy Controls for Information Systems and Organizations):** This is the **master control catalog**. It contains hundreds of specific, actionable technical, operational, and management controls (e.g., AC-2: Account Management, SI-4: System Monitoring). FISMA compliance requires agencies to select and implement the appropriate controls from SP 800-53 based on their system's categorization.
* **NIST SP 800-37 (Risk Management Framework for Information Systems and Organizations):** This is the **implementation process**. It provides the step-by-step lifecycle (Categorize, Select, Implement, Assess, Authorize, Monitor) for applying the controls from SP 800-53. It's the "how-to" guide for achieving and maintaining compliance.
* **NIST SP 800-60 (Guide for Mapping Types of Information and Information Systems to Security Categories):** This is the **starting point**. It helps you categorize your information systems as Low, Moderate, or High impact—a critical step that determines the stringency of controls required from SP 800-53.

#### 2. The Primary Organizing & Communication Framework: NIST Cybersecurity Framework (CSF)

While not a FISMA requirement, the **NIST CSF (Identify, Protect, Detect, Respond, Recover)** is an incredibly valuable tool.

* **How it helps:** It provides a business-friendly, risk-based structure to organize and communicate your FISMA compliance activities. You can **map your SP 800-53 controls to the CSF's five core functions**. This helps translate technical compliance into an executive-friendly risk management story and can identify gaps in your program.

#### 3. Essential Complementary Framework for Cloud: FedRAMP

If your organization uses or provides cloud services to the U.S. federal government, FedRAMP is critical.

* **How it helps:** **FedRAMP is essentially "FISMA for the cloud."** It standardizes the security assessment and authorization process for Cloud Service Offerings (CSOs) by building directly upon the NIST SP 800-53 control baseline. Using a FedRAMP-authorized cloud provider is often the most efficient path to compliance for cloud-based systems.

#### 4. Supplementary & Structuring Frameworks (Very Helpful for Certain Organizations)

These can help structure the broader compliance program and are often used in parallel.

* **ISO/IEC 27001 (Information Security Management System - ISMS):** This international standard provides a top-down, process-oriented framework for establishing, implementing, and maintaining an ISMS. An organization can **integrate its SP 800-53 control implementation into an ISO 27001-certified ISMS**. This is common for contractors and organizations wanting an internationally recognized certification alongside FISMA compliance.
* **NIST SP 800-171 (Protecting Controlled Unclassified Information in Nonfederal Systems and Organizations):** If your organization is a **federal contractor** handling CUI (Controlled Unclassified Information), this is your direct control set. It's a derived subset of NIST SP 800-53 controls, tailored for non-federal systems. Complying with SP 800-171 is a key step toward FISMA compliance for contractor systems that support agencies.

#### Summary & Practical Application:

To translate FISMA requirements into actionable technical controls, an organization would typically:

1. **Start with the Law:** Understand FISMA's mandate.
2. **Follow the Mandatory Path:** Use **NIST SP 800-60** to categorize systems, then apply the **NIST RMF (SP 800-37)** process to select and implement controls from the **NIST SP 800-53** catalog. This is the core compliance work.
3. **Use Organizing Tools:** Structure and communicate the program using the **NIST Cybersecurity Framework (CSF)**.
4. **Leverage Specialized Paths:** If using cloud, follow **FedRAMP**. If a contractor with CUI, implement **NIST SP 800-171**. If building a top-down management system, align with **ISO 27001**.
