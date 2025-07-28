# Copy of What do ethical hackers do?

This is an analysis of what ethical hackers do - their practices.

Penetration testing is applied in risk assessment and design implementation (verifying the implementation of the recommended security design).

* **Penetration testing**
* **Vulnerability assessment vs penetration testing**
* **Risk assessment**
* **Security assessment vs security audit**
* **Responsibilities of ethical hackers**
* **Roles of ethical hackers**

### Penetration testing

Penetration testing involves “launching real attacks on real systems and data using tools and techniques commonly used by hackers” (NIST SP 800-115, p. 5-2). (**4.3.1.** Steps of the penetration testing process)

The technical risks of penetration testing on computer systems to an organization include damaging the system infrastructure or data assets (CIA), downtime, and exploits may remain in the system. Given the potential side effects of penetration testing, the work of penetration testers is often conducted on a defined schedule and focuses on specific aspects of a network or computer infrastructure rather than being an ongoing overall security. The penetration tester may have limited access to the system that is subject to testing and only for the duration of the testing. - **discussed in 4.3.1**

**The penetration testing process** - **discussed in 4.3.1**

* Steps of the penetration testing process
* Open source penetration testing methodologies
* The penetration test report

The penetration testing process can be broken down into several stages: planning, reconnaissance, scanning and enumeration, gaining access, maintaining access, covering tracks, and analysis. The planning phase is followed by a phase of intelligence gathering, what NIST (2008) calls the discovery phase, spanning OSINT (open source intelligence) or recon (reconnaissance) or footprinting, and network enumeration and scanning.

In OSINT, “the penetration tester uncovers possible weaknesses and entry points within the security posture of the organization, including the network, applications, website and wireless networks, physical facilities, cloud-based systems, and employees” (cipher.com). Open source information on the Internet and from other public sources can be used to build a profile of the target user or system to determine entry points into a computer system.

Each phase within the discovery phase can be either active or passive. Active recon involves social engineering and “anything that requires the hacker to interact with the organization” (Walker, 2017, p. 45). Passive reconnaissance involves gathering information from the public domain in places like Internet registries, Google, newspapers, and public records. At this stage “the target does not even know generally that they are the subject of surveillance.” The vast majority of OSINT activity is passive in nature.

Automated OSINT is used by hackers and penetration testers to gather and analyze intelligence about a specific target from social networks, including names, online handles, jobs, friends, likes/dislikes/interactions, locations, pictures, etc. (McLaughlin, 2012). Recon-ng and Maltego are intelligence gathering and data management tools designed to facilitate the process of gathering, analyzing, and organizing OSINT.

Attackers will scan networks to discover open ports and network services. Enumeration is the process of extracting user names, machine names, network resources, and other services from a network. Nmap is a popular tool used for port scanning and network enumeration.

### Vulnerability assessment vs penetration testing

Penetration tests have a tightly defined scope, are time sensitive, and usually involve discovery of unknown vulnerabilities. Their scope is often external systems (outsider perspective). In comparison, vulnerability assessments typically entail an in-depth view, focus on technical flaws, and typically do not involve exploitation of discovered weaknesses. Their scope is often both external and internal systems.

Businesses need to evaluate information security risks for the purposes of insurance underwriting and resource allocation. Several major regulatory frameworks (such as HIPAA, PCI DSS, SSAE 16, FFIEC, and GLBA) require businesses to perform penetration testing and vulnerability scanning periodically.

Vulnerability scans are automated assessments of computers, networks, and applications, and are typically done on an ongoing basis, especially following the installation of new equipment or software. They are typically done by in-house staff, and cost about U.S. $1,200/year plus staff time. Their purpose is detection of exploitable vulnerabilities.

Penetration testing may be done once a year. It identifies what data was compromised (discovers unknown exposures to normal business processes). It is typically done by an independent outside service, costing about U.S. $10K/year. Its purpose is preventive control, used to reduce exposure (see Table 15: Vulnerability Scan and Penetration Test Comparison).

Table 15: Vulnerability Scan and Penetration Test Comparison (Rodger, 2013, p. 49)

### Risk assessment

A vulnerability assessment is a process of identifying, quantifying, and prioritizing (ranking) the vulnerabilities in a system. Vulnerability assessments usually cover network and computer infrastructure testing, including operating systems. A network assessment may include assessing the vulnerability of a network (network devices, including configuration, bugs, applications, and how users sign in).

Risk assessment “identifies risks generated by the possibility of threats acting on vulnerabilities, and what can be done to mitigate each one” (PCI DSS Risk Assessment Guidelines, 2005). Penetration tests are performed in risk assessments to identify and evaluate the risk of an attack on an information asset and how best to mitigate the risk. The goal of risk assessment is “to identify which investments of time and resources will best protect the organization from its most likely and serious threats” (Reynolds, 2012, p. 103).

Risk is “a threat that exploits some vulnerability that could cause harm to an asset” (Peltier, 2005, p.16). “One instance of risk within a system is represented by the formula (asset\*threat\*vulnerability)” (Landoll & Landoll, 2005, p. 8). The NIST Risk Management Guide defines risk assessment as “the process of identifying the risks to system security and determining the probability of occurrence, the resulting impact, and additional safeguards that would mitigate this impact” (Landoll & Landoll, 2005, p. 10).

According to the General Security Risk Assessment Guidelines, ASIS International (2003), the basic components of a risk assessment plan include, identifying assets, specifying loss events (threats), assessing the frequency and impact of events, recommending mitigation options, conducting a cost/benefit analysis, and making decisions.

Risk assessments help risk managers select appropriate control measures or countermeasures to lower the risk to an acceptable level (Engebretson, 2011; Landoll & Landoll, 2005; Peltier, 2005). The concept of reasonable assurance guides the decision making process: managers must use their judgement to ensure that the cost of control does not exceed the system’s benefits or the risks involved. The risk management process “supports executive decision-making, allowing managers and owners to perform their fiduciary responsibility of protecting the assets of their enterprises” (Peltier, 2005, p. 10).

Threat assessments and risk assessments overlap in scope and operations, but threat assessments are generally a more reactive approach to IT security than risk assessments, concerned with assessing immediate threats.

### Security assessment vs security audit

Security assessments determine the effectiveness of information security controls and rate an organization’s overall cyber maturity. A security audit is a point-in-time evaluation which verifies that specific security controls – technical, physical and administrative/procedural – are in place.

Security compliance audits assess the performance of security controls – verification of compliance with privacy and security regulations and standards: government regulations (e.g., Privacy Act, 1983; PIPEDA, 2000), industry regulations (e.g., PCI DSS, ISO/NIST), and in-house standard procedures and best practices.

The difference between a security assessment and a security audit can be understood as the difference between doing the right thing (to protect valued assets) and doing things right (by adhering to policy/honoring commitments).

### Responsibilities of ethical hackers

Key responsibilities of ethical hackers include,

* routinely test IT systems looking for flaws (assess vulnerabilities and report them)
* test software/ensure apps are tested
* stay abreast of ransomware and emerging computer viruses
* stay abreast of emerging threats
* compile and track vulnerabilities over time for metrics purposes
* track and disclose vulnerabilities to national repositories (e.g., the National Vulnerability Databases)

**Ethical hacking techniques (from techtarget.com)**

* scanning ports to find vulnerabilities with port scanning tools, such as [Nmap](https://en.wikipedia.org/wiki/Nmap), [Nessus](https://www.techtarget.com/searchnetworking/definition/Nessus), [Wireshark](https://www.linkedin.com/pulse/how-get-started-wireshark-baha-abu-shaqra-phd-dti-uottawa-/) and others, looking at a company’s systems, identifying open ports, studying the vulnerabilities of each port and recommending remedial action;
* scrutinizing patch installation processes to be sure that the updated software doesn’t introduce new vulnerabilities that can be exploited;
* performing network traffic analysis and sniffing by using appropriate tools;
* attempting to evade intrusion detection systems, intrusion prevention systems, [honeypots](https://www.techtarget.com/searchsecurity/definition/honey-pot) and [firewalls](https://www.techtarget.com/searchsecurity/definition/firewall); and
* testing methods to detect [Structured Query Language injection](https://www.techtarget.com/searchsoftwarequality/definition/SQL-injection) to ensure malicious hackers can’t introduce security exploits that expose sensitive information contained in SQL-based [relational databases](https://www.techtarget.com/searchdatamanagement/definition/relational-database).

### Roles of ethical hackers

Key roles of ethical hackers include cybersecurity analyst, OSINT analyst, GRC analyst/manager, SOC analyst, threat analyst, and incident responder.

### References

Reference
