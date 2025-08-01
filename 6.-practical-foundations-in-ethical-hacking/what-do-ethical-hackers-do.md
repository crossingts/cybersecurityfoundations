---
description: This section sheds light on key practices of ethical hackers
---

# What do ethical hackers do?

## Learning objectives

* List and describe key practices of ethical hackers
* Define risk assessment and penetration testing
* Explain key differences between vulnerability scan and penetration test

The term ethical hacking most formally refers to penetration testing, and less formally to vulnerability assessments (security assessments or security audits) and risk assessment practices. The role of ethical hackers within organizations can be seen as analysts collecting and analyzing vulnerability and threat data and giving actionable recommendations to mitigate any vulnerabilities and security risks. This section sheds light on key practices of ethical hackers.

## Topics covered in this section

* **Introduction**
* **Vulnerability assessment**
* **Risk assessment**
* **Penetration testing**

### Introduction

Key practices of ethical hackers include:

* Performing vulnerability and risk assessments (usually against known vulnerabilities).
* Discovering unknown vulnerabilities and identifying threats. This includes tracking vulnerabilities over time for metrics purposes and disclosing vulnerabilities to national repositories (e.g., the National Vulnerability Databases).
* Performing compliance audits against security regulations and standards. This includes government regulations (e.g., Privacy Act, 1983; PIPEDA, 2000), industry regulations (e.g., PCI DSS, ISO/IEC 27001, NIST SP 800-115), and in-house standard procedures and best practices.

These activities are not mutually exclusive. A risk assessment can be performed to achieve compliance with a certain regulation, and vulnerability assessments are performed as part of risk assessments. "Penetration testing", strictly speaking, is the act of exploiting known/discovered vulnerabilities (or testing a hypothesis about the existence of a vulnerability) but in reality the term penetration testing is used in a more broader sense, variably, and the act of exploiting vulnerabilities is typically and ideally performed as part of a more comprehensive risk assessment exercise.&#x20;

### Vulnerability assessment

A vulnerability assessment is the process of identifying, quantifying, and prioritizing (ranking) the vulnerabilities in a system. Vulnerability assessments can include passive and active scanning of networks, hosts (including OS-level vulnerabilities) and services (ports and applications). Passive scanning involves monitoring network traffic or configurations without actively probing systems, while active scanning involves sending probes to identify vulnerabilities (e.g., port scanning).

### Risk assessment

The goal of risk assessment is “to identify which investments of time and resources will best protect the organization from its most likely and serious threats” (Reynolds, 2012, p. 103).&#x20;

The NIST Risk Management Guide defines risk assessment as “the process of identifying the risks to system security and determining the probability of occurrence, the resulting impact, and additional safeguards that would mitigate this impact” (Landoll & Landoll, 2005, p. 10).&#x20;

According to the General Security Risk Assessment Guidelines, ASIS International (2003), the essential components of a risk assessment plan include, identifying assets, specifying loss events (threats), assessing the frequency and impact of events, recommending mitigation options, conducting a cost/benefit analysis, and making decisions. Risk assessments help risk managers select appropriate security control measures to lower the risk to an acceptable level (Engebretson, 2011; Landoll & Landoll, 2005; Peltier, 2005).&#x20;

The concepts of acceptable risk and reasonable assurance guide the decision making process. Managers must use their judgement to ensure that the cost of control does not exceed the system’s benefits or the risks involved. The risk management process “supports executive decision-making, allowing managers and owners to perform their fiduciary responsibility of protecting the assets of their enterprises” (Peltier, 2005, p. 10).

Their primary goal is to improve cybersecurity by identifying and fixing vulnerabilities before malicious actors can exploit them. Unlike gray or black hats, ethical hackers adhere to contracts and responsible disclosure policies. Ethical hackers address both systemic vulnerabilities as well as preventive measures (Harris, 2007; Palmer, 2001).&#x20;

“Many hacking books and classes are irresponsible. If these items are really being developed to help out the good guys, they should be developed and structured that way.” For Harris (2007), responsible hacking books should give information about how to break into systems as well as about defence and prevention measures.

This means more than just showing how to exploit a vulnerability. These educational components should show the necessary countermeasures required to fight against these types of attacks, and how to implement preventive measures to help ensure that these vulnerabilities are not exploited. (Harris, 2007, The Controversy of Hacking Books, para. 3).

### Penetration testing&#x20;

Penetration testing includes probing for vulnerabilities as well as giving proof of concept for an attack--that is, testing or verifying a hypothesis (verifying vulnerability assessment results). A penetration test is,

a proactive and authorized attempt to evaluate the security of an IT infrastructure by safely attempting to exploit system vulnerabilities, including OS, service and application flaws, improper configurations, and even risky or illegal end-user behaviour. (Rodger, 2013, p. 41)

Tests are typically performed to systematically compromise servers, endpoints, web applications, wireless networks, network devices, mobile devices and other potential points of exposure. Testers may even attempt to use the compromised system to launch subsequent attacks at other internal resources, specifically by trying to incrementally achieve higher levels of security clearance and deeper access to electronic assets and information via privilege escalation. (Rodger, 2013, p. 41)

The magic part of a penetration test is exploiting a vulnerability discovered during the vulnerability assessment phase (Harper et al., 2011; Walker, 2017). A penetration test “is when ethical hackers do their magic. They can test many of the vulnerabilities identified during the vulnerability assessment to quantify the actual threat and risk posed by the vulnerability” (Harper el al., 2011, p. 11).&#x20;

Ethical hacking may be a contracted outside service. An ethical hacker may be an independent computer security professional who attempts to break into an organization’s computer system, similar to having independent auditors verify an organization’s bookkeeping records (Palmer, 2001).

Several major regulatory frameworks (such as HIPAA, PCI DSS, SSAE 16, FFIEC, and GLBA) require businesses to perform penetration testing and vulnerability scanning periodically.

**Vulnerability Scan and Penetration Test Comparison**

<figure><img src="../.gitbook/assets/image (17).png" alt="Vulnerability Scan and Penetration Test Comparison"><figcaption><p>Table 15: Vulnerability Scan and Penetration Test Comparison (Rodger, 2013, p. 49)</p></figcaption></figure>

Vulnerability scans are automated assessments of computers, networks, and applications, and are typically done on an ongoing basis, especially following the installation of new equipment or software. They are typically done by in-house staff, and cost about U.S. $1,200/year plus staff time. Their purpose is detection of exploitable vulnerabilities.

Penetration testing may be done once a year. It identifies what data was compromised (discovers unknown exposures to normal business processes). It is typically done by an independent outside service, costing about U.S. $10K/year. Its purpose is preventive control, used to reduce exposure.
