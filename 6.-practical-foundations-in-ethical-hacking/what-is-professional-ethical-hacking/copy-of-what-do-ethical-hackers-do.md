---
hidden: true
---

# Copy of What do ethical hackers do?

This is an analysis of what ethical hackers do - their practices.

Penetration testing is applied in risk assessment and design implementation (verifying the implementation of the recommended security design).

* **Penetration testing**
* **Vulnerability assessment vs penetration testing**
* **Risk assessment**
* **Responsibilities of ethical hackers**

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

### Vulnerability assessment vs penetration testing - discussed in 4.2.3. What do ethical hackers do?

Penetration tests have a tightly defined scope, are time sensitive, and usually involve discovery of unknown vulnerabilities. Their scope is often external systems (outsider perspective). In comparison, vulnerability assessments typically entail an in-depth view, focus on technical flaws, and typically do not involve exploitation of discovered weaknesses. Their scope is often both external and internal systems.

**Table 15: Vulnerability Scan and Penetration Test Comparison (Rodger, 2013, p. 49):**

Businesses need to evaluate information security risks for the purposes of insurance underwriting and resource allocation. Several major regulatory frameworks (such as HIPAA, PCI DSS, SSAE 16, FFIEC, and GLBA) require businesses to perform penetration testing and vulnerability scanning periodically.

Vulnerability scans are automated assessments of computers, networks, and applications, and are typically done on an ongoing basis, especially following the installation of new equipment or software. They are typically done by in-house staff, and cost about U.S. $1,200/year plus staff time. Their purpose is detection of exploitable vulnerabilities.

Penetration testing may be done once a year. It identifies what data was compromised (discovers unknown exposures to normal business processes). It is typically done by an independent outside service, costing about U.S. $10K/year. Its purpose is preventive control, used to reduce exposure.

### Risk assessment&#x20;

The goal of risk assessment is “to identify which investments of time and resources will best protect the organization from its most likely and serious threats” (Reynolds, 2012, p. 103). - **Table 10:** Professional Ethical Hackers Coding Table

According to the General Security Risk Assessment Guidelines, ASIS International (2003), the basic components of a risk assessment plan include, identifying assets, specifying loss events (threats), assessing the frequency and impact of events, recommending mitigation options, conducting a cost/benefit analysis, and making decisions.

Risk assessments help risk managers select appropriate control measures or countermeasures to lower the risk to an acceptable level (Engebretson, 2011; Landoll & Landoll, 2005; Peltier, 2005). The concept of reasonable assurance guides the decision making process: managers must use their judgement to ensure that the cost of control does not exceed the system’s benefits or the risks involved. The risk management process “supports executive decision-making, allowing managers and owners to perform their fiduciary responsibility of protecting the assets of their enterprises” (Peltier, 2005, p. 10).

### Responsibilities of ethical hackers

Key responsibilities of ethical hackers include,

* routinely test IT systems looking for flaws (assess vulnerabilities and report them)
* test software/ensure apps are tested
* stay abreast of ransomware and emerging computer viruses
* stay abreast of emerging threats
* compile and track vulnerabilities over time for metrics purposes
* track and disclose vulnerabilities to national repositories (e.g., the National Vulnerability Databases)

### References

Reference
