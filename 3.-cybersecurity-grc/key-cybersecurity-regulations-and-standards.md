---
description: This section covers salient cybersecurity regulations, such as GDPR and HIPAA, and industry standards, such as PCI DSS
hidden: true
---

# Key cybersecurity regulations and standards

## Learning objectives

- Understand the strategic, ethical, and legal importance of cybersecurity regulations and standards for businesses
- Describe the challenges organizations face which require compliance and regulation
- Describe the key privacy and data protection requirements of GDPR
- Describe the differences between SOC1, SOC2, and SOC3 controls and reporting
- Define the three rules established as standards for the Health Insurance Portability and Accountability Act (HIPAA)
- Describe the Payment Card Industry Data Security Standard (PCI DSS)
- Describe the differences between basic, foundational, and organizational Center for Internet Security (CIS) controls

Cybersecurity regulations and standards are designed to protect sensitive data and ensure organizational compliance. 

This section covers salient cybersecurity regulations and standards.

Key cybersecurity **regulations (statutory and regulatory)** include HIPAA/HITECH, FACTA, GLBA, CCPA, SOX, Data Protection Act (UK), NIST800-171/CMMC (FAR & DFARS), FedRAMP, EU GDPR, and other data protection regulations. 

Key cybersecurity **industry standards (contractual requirements or legally-binding obligations)** include CMMC (CMMC can be both contractual and regulatory), PCI DSS, SOC2 Certification, ISO27001 Certification, NIST Cybersecurity Framework, and other contractual requirements.

This section covers salient cybersecurity regulations and standards, including NIST, GDPR, ISO, SOC, HIPAA, and PCI.

## Topics covered in this section

- **Lesson 1. Compliance and Regulation for Cybersecurity**
- **Lesson 2. System and Organization Controls Report (SOC) Overview**
- **Lesson 3. Industry Standards**
- **Lesson 4. Critical Security Controls**

### Lesson 1. Compliance and Regulation for Cybersecurity

- What Cybersecurity Challenges do Organizations Face?
- Compliance Basics
- Overview of US Cybersecurity Federal Law
- National Institute of Standards and Technology (NIST) Overview
- National Institute of Standards and Technology (NIST) Special Publication 800-53 Catalog of Security Controls
- General Data Protection Regulation (GDPR) Overview
- Examples of GDPR Fines
- International Organization for Standardization (ISO) 2700x

#### 1.1. What Cybersecurity Challenges do Organizations Face?

About 45% of hackers are outsiders. The other 55% represent insiders comprised of malicious insiders and inadvertent actors. To manage hacking risks, organizations design and implement procedural, technological, and physical controls. “We need security protocols, and controls, and tooling, and processes in place to try to address the different types of security incidents we can have, as well as the different sources they can come from.”

#### 1.2. Compliance Basics

Security, privacy, and compliance.

“**Security** is designed to focus on protecting your environment and your systems from theft, from damage, from disruption.” Security “comes in **three** main categories.”

**Physical** **controls**: how do you physically keep your systems that you’re operating – servers, data centers, the cloud – contained. “Then there’s **technical** **controls**. Technical controls or tooling or software or features and functions that restrict or control the security of the data or the processes. So you can think of encryption, you think of logging, you can think of password software, all of those are examples of technical controls.” **Operational** **controls**: “how servers are configured. What are your rules for how often you patch a system? Who’s responsible for monitoring the logs and reviewing them? How your staff are trained and what activities they perform. These are operational or procedural controls.”

**Privacy** “is strongly focused on the data. So how the information is being used. Who has access to it? How is it stored? How is it transferred? How that information may be used to track people or things?”

**Compliance** focuses on testing the security and privacy measures are in place. “Compliance will typically identify a specific subset of all of the controls based on a particular goal. And then the idea is you validate those specific controls to that standard. It can also cover a lot of non-security things that you wouldn’t typically think of as security. So business practices, vendor agreements, you don’t typically think of vendor agreements … related to security. But certainly if you don’t build your product and run your product on your own, you have vendors that participate with you. You need to ensure that they’re providing the security and privacy controls that you’re expecting of them.”

“There can be anywhere from 50 to 500 controls out there that are involved in securing your environment, your system, your product, your application. So depending on which compliance you’re going after, you may be choosing a specific subset of that 500. So once you’ve identified that, you’re going to want to validate … with either an external auditor or another assessor inside your own company.”

There are two main categories for compliances. First, foundational or general. “They’re not specific to any particular industry. They are broad spectrum. They go over a number of different topics be it physical or the technical or the operational examples. Like that would be ISO 27001, SOC.” Second, “classifications that are more industry-specific or governmental even. And they are particular to a specific subject matter … we’ve got HIPAA which focuses on U.S. Healthcare. We have PCI DSS which focuses on payment card information, so credit card data storage.”

**A typical compliance process**

*The scope: “you want to establish the scope – very clear boundaries of what is in your compliance and what is not.” “So if we want to go after ISO, I want to go after this particular set of systems.”

*Readiness assessment: “you go through all of the compliance requirements for that particular standard. You look at the controls, you look at the specific subset of the 50 to 500. You want to understand how each of those controls applies to your environment that you’ve established scope on. Then you want to assess how well do you perform that function. I perform that function well, I don’t perform that function at all. I perform it sort of a not great. So you’ll identify gaps as part of that readiness assessment.”

*Gap remediation: “once you’ve identified the list of gaps … you want to address those gaps. “So if you don’t have encryption everywhere that you want to have encryption according to the standard, well, then you’ll go you’ll add it. If you haven’t got your user IDs, they haven’t got the individual least privilege. Maybe you want to go through and review who has access to your system and trim that up.”

*Testing: “and then you’ll enter a testing period. If you’re testing it through your self-assessment or internal assessment, you’ll work with experts in that area. You may also be engaging external auditors if that’s the appropriate thing.”

*Recertifying: “then you’ll be recertifying, right? So depending on the nature of the certification sometimes you’re recertifying quarterly, recertifying annually.”

#### 1.3. Overview of U.S. Cybersecurity Federal Law

Describe the Computer Fraud and Abuse Act (CFAA).

“The Computer Fraud and Abuse Act has been around since 1984. It’s basically what makes cybercrime a crime. So it is a law that identifies that access to a computer without authorization or in excess of your authorization is against the law. It is against the law to interfere. It is against the law to acquire, to disrupt your systems, and it’s punishable.”

U.S. federal laws, such as CFAA, FISMA, and FedRAMP “will base their subset of their requirements off of something called NIST, the National Institute of Standards and Technology.”

#### 1.4. National Institute of Standards and Technology (NIST) Overview

Describe the importance of the National Institute of Standards and Technology, NIST.

“The National Institute of Standards and Technology is focused on cyber security and privacy. They will identify literally hundreds of individual standards that are related. There will be pages and pages of details on passwords, on encryption, on network communications, and how to assure security and privacy.”

“There is not generally an expectation that you will implement how many (standards) … but that you’ll institute a practice within your business to do as many of them as makes sense for your business.”

#### 1.5. National Institute of Standards and Technology (NIST) Special Publication 800-53 Catalog of Security Controls

[Security and Privacy Controls for Information Systems and Organizations SP 800-53 Rev. 5](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)

#### 1.6. General Data Protection Regulation (GDPR) Overview

* **Region**: EU (applies globally to organizations handling EU citizens' data)
* **Focus**: Privacy and data protection
* **Key Requirements**:
  * Consent for data collection
  * Right to access, correct, and delete personal data
  * Data breach notifications within 72 hours
  * Privacy by design
* **Penalties**: Up to **€20 million or 4% of global revenue**

Describe the General Data Protection Regulation, GDPR. Describe the key privacy and data protection requirements of GDPR.

“The General Data Protection Regulation laws are a European standard that came out recently. They are laws governed at privacy of European data. So they focus on compliance, data protection, and personal data of EU residents in particular. So if your business is going to host EU residents data or do business with the EU then this is an important regulation for you to understand.”

“From a compliance perspective, they’re looking at regulating how you manage the data associated with people, and making sure you have policies and processes in place. They are specifically looking at data encryption, data security, access and monitoring … and how to ensure that the data is there lawfully. You’ll also see laws here around the right to forget. They also come with incredibly stiff penalties.”

“Fines can be huge, four percent or up to €20 million depending on your company’s revenue … I’ve seen fines in excessive €100 million.”

​[Understanding the 7 Principles of the GDPR](https://www.onetrust.com/blog/gdpr-principles/)​

“Key terms here that you’ll want to understand is the data **subject** – must be an identifiable, natural living person, so that’s the EU resident.” Personal data is any information related to the subjects. “The **controller**, this is the person or entity that is responsible for the handling of that data … The **processor** could be an actor on behalf of the controller that is processing the data.”

#### 1.7. Examples of GDPR Fines

​[ICO statement: Intention to fine British Airways £183.39m under GDPR for data breach](https://www.databreaches.net/ico-statement-intention-to-fine-british-airways-183-39m-under-gdpr-for-data-breach/)​

​[Marriott Faces $123 Million GDPR Fine for 2018 Data Breach](https://www.bleepingcomputer.com/news/security/marriott-faces-123-million-gdpr-fine-for-2018-data-breach/)​

​[Polish DPA fines Virgin Mobile Polska €460,000: Incidental safeguards review is not regular testing of technical measures](https://www.databreaches.net/polish-dpa-fines-virgin-mobile-polska-e460000-incidental-safeguards-review-is-not-regular-testing-of-technical-measures/)

#### 1.8. International Organization for Standardization (ISO) 2700x

Describe the basics of the ISO 27001 standards.

ISO has many different standards, several of them are applicable for cyber security. The most common one is ISO 27001, an information security management standard. “It focuses on requirements for establishing and implementing, maintaining and improving your security management system. It’s risk-based.” ISO 27018 is focused on privacy and ISO 27017 is focused on Cloud security. A combination of these three standards could be used in an enterprise information assurance strategy.

“ISO does develop standards but they don’t themselves issue the certification. You find an authorized, qualified, accredited, certified auditor to come in and perform that assessment on your behalf.”

### Lesson 2. System and Organization Controls Report (SOC) Overview

- SOC Reports
- SOC Reports – Auditor Process Overview
- American Institute of CPAs (AICPA) Website research

#### 2.1. SOC Reports

Describe the differences between SOC 1, SOC 2 and SOC 3 controls. Describe the benefits of SOC Reports.

“In the difference about design and the nature or scope,” “if I compare with ISO … SOC 2 is focused on fiscal, logical security and, in specific … do what you say you’ll do, whereas the ISO 27001 is a little bit more focused on risk”; “a little more focused on best practices.”

“ISO is focusing on the design effectiveness at a point in time whereas the SOC 2 also looks at operating effectiveness over a period of time. So Type 2 would be 6-12 months and would look at how effective you are in performing those functions over that entire period of time.”

“You get a single page from an ISO certification, there’s a detailed report that’s considered confidential, internal, but otherwise, it’s a single-page and doesn’t provide a lot of detail to the reader or to your customer about what you’re doing. In the case of SOC 2, you get a fairly detailed report. It can be many pages long. It describes the controls, it describes how they tested them, it describes the results or the testing. So it’s very detailed and can provide a lot of insight for your customers and confidence your customers that of how you operate.”

“ISO is managed by the ISO, and an ISO accredited agency would do the consulting and certifying.” SOC 2 is “almost always performed by CPA because it’s governed, inspected by the AICPA.” “ISO is internationally recognized. SOC 2 has traditionally been more North American but it is becoming more known internationally.” Some organizations prefer SOC 2 over ISO. “Some organizations, or some clients, or some industries will accept SOC 2 in lieu of the right to audit.”

“There’s actually three SOC reports. SOC 1, 2, and 3 … they’re all based on the same core set of controls but they subset it out and report it differently. So SOC 1 uses a subset of the controls, and it specifically is looking at situations where your system is being used for financial reporting. So if you are using your system to hold your sales ledger data and you then are going to turn around and use that data to generate reports for your financial reporting.”

“SOC 2 is a little more general, and it’s going to look at more controls, superset of the ones that are looked at for SOC 1. The SOC 2 report is restricted “because of the detail that is in there around the system, the security, processes, and methodologies. If you achieve this for your environment, you would get to a keep a copy of it yourself. You would only send it to clients or prospective clients under a non-disclosure agreement, because of the level of detail in there. If it fell into the wrong hands, somebody could use that to try to mount a malicious attack.”

“For people who do want to have something short and sweet and something you can put on your web page, like the ISO certification, there is a SOC 3 report. It is considered an executive summary of your SOC 2. It provides the opinion and the description of the system but it does not get into the details of the security practices or the testing methodology results. It’s just a high level one.”

“A Type 1 report, consider that as your starting line. That is the closest equivalent to an ISO as well. So basically, it tests the design effectiveness of your controls and that you have performed those controls at least once.”

“The Type 2 is now looking at operational effectiveness over a period of time. Typically, that is six months or 12 months. The auditor will come in and they will test over the interval of that period of time.”

“On top of the complexity of Type 1s and Type 2s and SOC 1s and SOC 2s, there are different principles or chapters within SOC 2 and they each come with a set of controls or requirements. The most typical and sort of the foundational one that everybody would get would be security and they’re looking specifically at how you’re protecting your physical and logical access and systems. So they have controls related to user provisioning, change management, inventory management, things like that.”


IMAGE 1

SOC 2 trust service principles (image courtesy of imperva.com)


SOC 2 defines criteria for managing customer data based on five trust service principles – security, availability, processing integrity, confidentiality, and privacy.

#### 2.2. SOC Reports – Auditor Process Overview

Describe the audit elements for SOC reporting.

“This is a summary listing of the different controls that are used for audit. When auditors are testing … they’re testing for five main elements.”

“They’re looking at accuracy, or all the controls being addressed, looking for passes and fails and very clear distinction about whether or not the control is being completed.”

“Completeness. Do the controls cover the entire offering? So if, in case of a control looking at your systems, does it cover all your systems and all your inventory? If you’re looking at access management, does it cover all personnel, all people?”

“Looking at timeliness. Timeliness is a really big challenge for some teams. Making sure the controls are performed on time or early and that there’s no gaps in coverage.”

“Resiliency. They’re looking for checks and balances, so that if the control did fail, is there some secondary way that you can ensure that something happens on time.”

“They’re looking for consistency. So they want to ensure that there’s no gaps introduced by having too much variability. So often they’ll look at a primary control, they’ll test the primary control. They’re looking to ensure that you provide features, functions of the control. If for any reason that’s not working, they’re looking for support or backup to ensure that the primary control is effective.”

#### 2.3. American Institute of CPAs (AICPA) Website research

AICPA develops the guidelines for SOC reporting. Explore some of the resources available on the AICPA website for CPAs, users, and organizations.

​[Introduction to the AICPA’s Cybersecurity Risk Management Framework](https://www.aicpa.org/interestareas/frc/assuranceadvisoryservices/aicpacybersecurityinitiative.html) (video)

​[SOC for Cybersecurity](https://www.aicpa.org/content/dam/aicpa/interestareas/frc/assuranceadvisoryservices/downloadabledocuments/soc-for-cybersecurity-brochure.pdf) (brochure)

​[SOC 2® examinations and SOC for Cybersecurity examinations: Understanding the key distinctions](https://www.aicpa.org/content/dam/aicpa/interestareas/frc/assuranceadvisoryservices/downloadabledocuments/cybersecurity/soc-2-vs-cyber-whitepaper-web-final.pdf) (report)

### Lesson 3. Industry Standards

- Health Insurance Portability and Accountability Act (HIPAA)
- HIPAA Cybersecurity guidance
- Payment Card Industry Data Security Standard (PCI DSS)

#### 3.1. Health Insurance Portability and Accountability Act (HIPAA)

* **Region**: U.S. (applies to healthcare providers, insurers, and business associates)
* **Focus**: Protection of healthcare data
* **Key Requirements**:
  * Safeguarding **Protected Health Information (PHI)**
  * Administrative, physical, and technical safeguards
  * Breach notification within 60 days
* **Penalties**: Up to **$1.5 million per violation**

Describe key HIPAA terms. Describe why HIPAA compliance is important to an organization. Define the three rules established as standards for HIPAA.

“HIPAA is the U.S. federal law that identifies the control of personal healthcare information. So PHI, personal healthcare information, and it’s also related to the other law in this space called HITECH.”

HIPAA is defined and overseen by the U.S. Department of Health and Human Services, Office of Civil Rights, and they identify two main actors in this space.

First, “there’s the covered entity. So this is the company that manages the healthcare data for the customer, so it would be a hospital, it would be an insurance company, it could be your doctor’s office.” Second, “a business associate is any vendor that supports the covered entity. So if you are providing an application, if you are providing a cloud environment to the hospital, then you are a business associate of that covered entity.” “The protected health information is any information about the health status of the individual, and it is the responsibility of the covered entity or on their behalf through the business associates to ensure its safety and confidentiality.”

“In the case of GDPR, we talked about large fines, there are absolutely large fines here for violations of HIPAA. There’s also a Wall of Shame. You can go to the website there and they will produce that. So why is compliance here essential? So they’re our laws, the U.S. federal laws, and they have teeth and the HHS will come in and do unannounced audit either on the BA or the CE, the covered entity or the business associate. One or the other or both could find themselves under an audit situation. The fines can be in the millions of dollars. You can face criminal prosecution.”

“So although it’s a U.S. regulation, the other thing to be aware of is that other countries will have a similar law. We talked about GDPR. In Canada, there’s the Personal Information Protection and Electronic Documents Act (PIPEDA). So just about every geography is going to have a similar law or regulation on the books. Many states in the U.S. will have even more strict laws or additional requirements that are laid out on top of the U.S. federal law for HIPAA. So you need to be aware of that as you’re choosing your jurisdictions who you’re doing business in and the types of compliances that you’re aligning with.

“The privacy rule associated with HIPAA (identifies) the right to an individual’s medical records and health information that is accessed … It applies to health insurance companies to healthcare providers, and anyone who might have access or need to share healthcare records.” The security rule establishes “a set of standards for protecting that data, and they must be in place in both the covered entity and the business associate.” The third rule is the breach notification rule.

“HIPAA security rule will cover physical entities, technical controls, administrative safeguards, all with that focus on protecting health information. They look at confidentiality, integrity, availability, and they want to ensure that we’ve taken all stuff and actions to reasonably anticipate threats to the security and integrity of the information. You want to protect against impermissible uses, accidental disclosures, and ensure compliance by all of the workforce.”

“Administrative Safeguards, they take the form of these are the non-technical, or operational controls, you’re looking at your management process, your personnel process, you’ll look at hiring practices, workforce training, background checks.”

“Technical Safeguards, again like the general term, technical, they’re looking at access control, audit control, integrity control, transmission, encryption, in use … at rest, in transit. You use different technical controls to make sure that the software is performing as it’s expected.”

“Then the physical safeguards are around the facility access that where the devices are. So if your data is stored on disk somewhere, where are those disks, are they appropriately under access control and are they secure?”

#### 3.2. HIPAA Cybersecurity guidance

[Cyber-Attack Quick Response Guide](https://www.hhs.gov/sites/default/files/cyber-attack-quick-response-infographic.gif) (U.S. Department of Health & Human Services)

#### 3.3. Payment Card Industry Data Security Standard (PCI DSS)

* **Region**: Global (applies to organizations handling credit card data)
* **Focus**: Securing cardholder data
* **Key Requirements**:
  * Encryption of stored card data
  * Regular vulnerability scans
  * Access controls and network segmentation
* **Penalties**: Fines up to **$100,000/month** for non-compliance

Describe the Payment Card Industry Data Standard Security, PCI DSS. Describe the goals and requirements of PCI DSS. Describe the scope of PCI DSS as it relates to people, process, and technology. Highlight new and key requirements for PCI DSS.

The Payment Card Industry Data Security Standard (PCI DSS) is an information security standard for organizations that issue credit cards or process credit card payments.

“In 2004, the largest credit card companies, American Express, Discovery, Mastercard, Visa, they banded together to define a standard for data security. The security standard gets revised periodically over the years as new standards and new technology become available.”

“These companies will require, if you’re going to be engaged in any business and involves storage or transmission of credit card data that you secure that data to these standards. So store process or transmit credit cardholder data, that’s credit card numbers, any of that sort of thing. It covers both technical and operational practices.”

“There are a total of 264 different individual requirements in 12 different groupings. If you’re engaged in an audit for PCI, one of the first things they do … defining scope, what is the scope of your environment, and how many of these 264 apply to you. So you’d go through the 12 different categories of these requirements from building and maintaining a secure network, protecting cardholder data, vulnerability management program, access control, monitoring, and testing your networks, and maintaining information security policy. You go through all of these different categories. You’ll do an assessment that’s that whole readiness assessment we talked about in the scope, where you identify these different requirements and say how many of them are applicable to your environment.”

“Cardholder data environment is the people, process, and technologies that store (cardholder data). In particular, looking at the primary account number or PAN data and it can be the cardholder name, the expiry date, the service code. They’re also looking at sensitive authentication data, so PINs … or anything else that is used to authenticate a credit card transaction. They’re looking at … ensuring that anything that processes, transmits, or stores this data, is considered in scope.”

“One of the things that’s unique about PCI is they have this concept of an Approved Scanning Vendor that scans quarterly, usually quarterly, and it’s usually an external third policy. It’s similar but not the same as a vulnerability scan or the penetration testing you might see, but it is a very specific.”

“One of the other things that we consider somewhat unique relative to other requirements are the details around Nessus, there’s particular configurations if you’re doing scanning for vulnerability for Nessus, and file integrity monitoring. File integrity monitoring is when you ensure that all the files that are running on your system are the ones that you intended to be there, and nobody’s replaced an executable with a different executable … So the checking for skimmers as an example here. Firewall review frequency is increased to six months. Some other certifications might only require once a year.”

“One of the document that gets produced from PCI is the responsibility matrix and that’s a really good document for you to review, because it clarifies what are the responsibilities of the entity providing the PCI support and the consumer.”

### Lesson 4. Critical Security Controls

- Center for Internet Security (CIS) Critical Security Controls
- Compliance and Industry Standards Summary
- Center for Internet Security (CIS) Critical Security Controls Research

#### 4.1. Center for Internet Security (CIS) Critical Security Controls

Describe the Center for Internet Security, CIS, Critical Security Controls. Describe the differences between basic, foundational, and organizational CIS controls.

The CIS produces a set of in depth best practices required to mitigate against common attack to systems and networks. “In particular, we look at their controls from a configuration perspective. How to best configure systems that are sitting on the public Internet so that they are reasonably protected. We see a lot of experts using these (controls) from retail, manufacturing, health care.”

CIS has a set of configuration benchmarks and one of the things they would govern, for example, is password complexity. “We see a lot of different basic foundational organizational controls,” for example, “around passwords … vulnerability management, boundary defense, application security, incident response and management.”

“CIS breaks their controls up into three implementation groups. They base them on the maturity or the significance of the controls and of the organizations using it. So if you’re a mature organization, enterprise, you’re going to look at group three. Small, single storefront, maybe group one is more appropriate to your business. Each of the controls is documented as to why you’re doing the control, what the different parts are, what the tools and procedures would be, and an example of how you would organize it.”

#### 4.2. Compliance and Industry Standards Summary


IMAGE 2

Cybersecurity compliance and industry standards summary (courtesy of IBM Security Learning Services)


#### 4.3. Center for Internet Security (CIS) Critical Security Controls Research

​[The CIS Critical Security Controls – CIS Controls V7.1](https://www.cisecurity.org/blog/v7-1-introduces-implementation-groups-cis-controls/)​

The CIS Critical Security Controls (CIS Controls) are internationally-recognized cybersecurity best practices for defense against common threats. They are a consensus-developed resource that brings together expert insight about cyber threats, business technology, and security. The CIS Controls are used by organizations with varying resources and risk exposure to build an effective cyber defense program.

### Footnote/FYI

This discussion focused on module 1 (week 1) of the Coursera course [Cybersecurity Compliance Framework & System Administration](https://www.coursera.org/learn/cybersecurity-compliance-framework-system-administration), course 3 of 4 of [IT Fundamentals for Cybersecurity Specialization](https://www.coursera.org/specializations/it-fundamentals-cybersecurity). The course also covers the following three modules:

- Module 2: Client System Administration, Endpoint Protection and Patching
- Module 3: Server and User Administration
- Module 4: Cryptography and Compliance Pitfalls

Modules 2, 3, and 4 focus on how technical and administrative controls and processes can help achieve compliance.

--
#### **1. General Data Protection Regulation (GDPR)**

#### **2. Health Insurance Portability and Accountability Act (HIPAA)**

#### **3. California Consumer Privacy Act (CCPA) & CPRA (amendment)**

* **Region**: California (affects businesses operating in CA)
* **Focus**: Consumer privacy rights
* **Key Requirements**:
  * Right to know what data is collected
  * Right to opt-out of data sales
  * Right to deletion of personal data
* **Penalties**: **$2,500–$7,500 per violation**

#### **4. Sarbanes-Oxley Act (SOX)**

* **Region**: U.S. (applies to publicly traded companies)
* **Focus**: Financial reporting and fraud prevention
* **Key Requirements**:
  * Internal controls over financial reporting (ICFR)
  * CEO/CFO accountability for financial statements
  * IT controls for data integrity
* **Penalties**: Fines and **criminal charges** for executives

#### **5. Payment Card Industry Data Security Standard (PCI DSS)**

#### **6. Federal Information Security Management Act (FISMA)**

* **Region**: U.S. (applies to federal agencies & contractors)
* **Focus**: Government IT security
* **Key Requirements**:
  * Risk assessments & security controls
  * Continuous monitoring
  * Incident reporting

#### **7. New York Department of Financial Services (NYDFS) Cybersecurity Regulation (23 NYCRR 500)**

* **Region**: New York (financial services firms)
* **Focus**: Financial sector cybersecurity
* **Key Requirements**:
  * CISO appointment
  * Multi-factor authentication (MFA)
  * Annual penetration testing

#### **8. NIST Cybersecurity Framework (CSF)**

* **Region**: U.S. (widely adopted globally)
* **Focus**: Risk management best practices
* **Key Requirements**:
  * Identify, Protect, Detect, Respond, Recover
  * Used alongside regulations like HIPAA & FISMA

#### **9. Cybersecurity Maturity Model Certification (CMMC)**

* **Region**: U.S. (Defense contractors)
* **Focus**: Protecting Controlled Unclassified Information (CUI)
* **Key Requirements**:
  * Five maturity levels (basic to advanced cybersecurity)

--
### Key takeaways


### References

​[ComplianceForge Reference Model: Hierarchical Cybersecurity Governance Framework (HCGF)](https://graphics.complianceforge.com/graphics/ComplianceForge%20Hierarchical%20Cybersecurity%20Governance%20Framework.pdf)​
​[Cybersecurity Compliance Framework & System Administration](https://www.coursera.org/learn/cybersecurity-compliance-framework-system-administration)​

​[IT Fundamentals for Cybersecurity Specialization](https://www.coursera.org/specializations/it-fundamentals-cybersecurity)
