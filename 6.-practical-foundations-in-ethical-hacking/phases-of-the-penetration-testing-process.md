---
description: >-
  This section describes the phases of the penetration testing process, the
  goals of each phase and key technologies used
---

# Phases of the penetration testing process

## Learning objectives

* Describe the phases of the penetration testing process
* Point 2&#x20;

This section covers steps of the penetration testing process--planning, reconnaissance, scanning and enumeration, exploitation, post-exploitation, and reporting--and best practices for writing the penetration test report.

## Topics covered in this section

* **Steps of the penetration testing process**
* **The penetration test report**

### Steps of the penetration testing process

Penetration tests have a tightly defined scope and are time sensitive. Penetration tests should be seen as targeted exercises. The scope of test activities and test objectives, a schedule for the test activities, and the specific machines or applications to be tested are all specified upfront in a contractual agreement. Each test objective will have its own set of parameters and processes. The contractual agreement specified what is to be tested and how it is to be tested. It,

provides a precise description, usually in the form of network addresses or modem telephone numbers, of the systems to be evaluated. Precision on this point is of the utmost importance, since a minor mistake could lead to the evaluation of the wrong system at the client’s installation or, in the worst case, the evaluation of some other organization’s system. (Palmer, 2001, p. 775)

The penetration testing process can be broken down into several **stages**: planning, reconnaissance, scanning and enumeration, gaining access (exploitation), maintaining access, covering tracks, and analysis.&#x20;

In the planning phase, rules are identified, management approval is finalized and documented, and testing goals are set. The planning phase sets the groundwork for a successful penetration test. No actual testing occurs in this phase. (NIST SP 800-115, 2008, p. 5-2)

The planning phase is followed by a phase of intelligence gathering, what NIST (2008) calls the **discovery** phase, spanning OSINT (open source intelligence) or recon (reconnaissance) or footprinting, and network enumeration and port scanning.

Walker (2017) proposes five main stages for a penetration test or “act of hacking”: 1) Reconnaissance involves the steps taken to gather evidence and information on the target, 2) scanning and enumeration takes the information gathered in reconnaissance and applies tools and techniques to gather more in-depth information on the targets, 3) gaining access where “true attacks are leveled against the targets enumerated in the second phase,” 4) maintaining access, where hackers attempt to ensure they have a way back into the compromised system, and 5) covering tracks, where “attackers attempt to conceal their success and avoid detection by security professionals” (p. 36).&#x20;

Faircloth (2011) proposes an iterative five stage reconnaissance phase: Intelligence Gathering, Footprinting, Human Recon, Verification, and Vitality. Table 17: Five Phases of Reconnaissance outlines the intelligence objectives, output (deliverables), and intelligence resources and tools for each phase. The last phase (Vitality) can be omitted in passive reconnaissance.

There are two types or techniques of attacks: An active attack threatens the confidentiality and integrity of data, and a passive attack threatens the confidentiality of data. The three key steps or phases of footprinting (reconnaissance), network enumeration, and port scanning (what NIST SP 800-115 calls the discovery phase) are intelligence gathering processes to prepare for an exploit strategy against a target.&#x20;

Each of the three phases of the discovery phase (NIST SP 800-115, 2008) can be either passive or active.&#x20;

Table 17: Five Phases of Reconnaissance (Faircloth, 2011, p. 33)

<table data-header-hidden><thead><tr><th valign="top"></th><th valign="top"></th><th valign="top"></th><th valign="top"></th></tr></thead><tbody><tr><td valign="top">Phase</td><td valign="top">Objectives</td><td valign="top">Output</td><td valign="top">Tools</td></tr><tr><td valign="top"><p>Intelligence</p><p>Gathering</p></td><td valign="top">To learn as much about the target, its business, its organizational structure, and its business partners as possible.</td><td valign="top">The output of this phase is a list of company names, partner organization names, and DNS names which reflect the entire target organization including all of its brands, divisions, and local representations.</td><td valign="top"><p># Search engines</p><p># Financial databases</p><p># Business reports</p><p># WHOIS</p><p># RWHOIS</p><p># Domain name registries and registrars</p><p># Web archives</p><p># Data mining tools</p></td></tr><tr><td valign="top">Footprinting</td><td valign="top">To mine as many DNS host names as possible from the domains or company names collected and translate those into IP addresses or IP address ranges.</td><td valign="top">The output of this phase is a list of DNS host names, IP addresses, and IP address ranges.</td><td valign="top"><p># DNS</p><p># WHOIS</p><p># DIG</p><p># SMTP</p><p># Data mining tools</p></td></tr><tr><td valign="top"><p>Human</p><p>Recon</p></td><td valign="top">To analyze the human perspective of the target and gain as much intelligence as possible about the people associated with the organization.</td><td valign="top">The output of this phase is a list of names, job titles, contact information, and other personal details about the people associated with the organization.</td><td valign="top"><p># Search engines</p><p># Email lists and web site posts</p><p># Social networking services</p><p># Publicly available records</p></td></tr><tr><td valign="top">Verification</td><td valign="top">To confirm the validity of information collected in the prior phases.</td><td valign="top">This phase rarely produces new output, but can clean up existing output by removing invalid data. Some additional information can sometimes be gathered as a side-product of the verification.</td><td valign="top"><p># DNS</p><p># WHOIS</p><p># DIG</p></td></tr><tr><td valign="top">Vitality</td><td valign="top">To confirm the reachability of the IP addresses identified in prior phases. This is a phase which spreads between reconnaissance and enumeration.</td><td valign="top">The output of this phase is a list of IP addresses from prior phases which have been confirmed as reachable.</td><td valign="top"><p># PING</p><p># Port scanners</p><p># Mapping tools</p></td></tr></tbody></table>

NIST SP 800-115 divides penetration testing into four main phases: Planning phase, Discovery phase (addressing Target Identification and Analysis Techniques), Attack phase (addressing Target Vulnerability Validation Techniques), and Reporting (see NIST SP 800-115, p. 5-2 for an in-depth discussion of the discovery phase).&#x20;

The three steps of the discovery phase represent successive stages of escalation in network access privileges. Reconnaissance uncovers information about a target company, such as its name and the identity of its partners, employee numbers, primary top-level domain names, and email address structure. Enumeration produces a narrowed-down list of specific IP addresses, port numbers, hostnames, and bulk lists of email addresses. Scanning gathers client-server level intelligence.

Key risk thresholds or milestones within the three-step penetration testing framework: 1) From footprinting to network enumeration mark a change in network access authorization level (what is public and “open” and what is not) (e.g., lawful DNS-based data exfiltration from public sources vs unauthorized network access); 2) from network enumeration to active port scanning–active interference in network communication processes may **cause delay or downtime** (e.g., consumption of bandwidth during continuous active enumeration or monitoring, or during continuous penetration testing or to ensure network awareness within IT security governance), and traceability to penetration testers becomes a concern; and 3) from vulnerability assessment to “proof of concept” or the testing of security hypotheses regarding exploitable vulnerabilities within an information system.&#x20;

Most “ethical hacking” activities are in practice vulnerability assessment activities.&#x20;

Penetration testing involves “launching real attacks on real systems and data using tools and techniques commonly used by hackers” (NIST SP 800-115, p. 5-2). &#x20;

Performing real attacks on real systems carries a higher risk that must be weighed carefully against the intended benefits. It must be justified on a cost-benefit basis by a security analyst with broad and interdisciplinary knowledge about the social threat landscape, human behavior, sociopolitical conflicts, in addition to the technical knowledge. Penetration testing can compromise data integrity or availability (accidental damage) or confidentiality (the penetration tester sees confidential information just by virtue of performing the test).

The technical risks of penetration testing on computer systems to an organization include damaging the system infrastructure or data assets, or exposing confidential information, downtime, and exploits may remain in the system. Given the potential **side effects** of penetration testing, the work of penetration testers is often conducted on a defined schedule and focuses on specific aspects of a network or computer infrastructure rather than being an ongoing overall security. The penetration tester may have only limited access to the system that is subject to testing and only for the duration of the testing.

Each phase within the discovery phase (NIST) can be either active or passive.&#x20;

**Footprinting passive and active methods/tools**

Active recon involves social engineering and “anything that requires the hacker to interact with the organization” (Walker, 2017, p. 45). Passive reconnaissance involves gathering information from the public domain in places like Internet registries, Google, newspapers, and public records. At this stage “the target does not even know generally that they are the subject of surveillance.” The vast majority of OSINT activity is passive in nature.

In OSINT, “the penetration tester uncovers possible weaknesses and entry points within the security posture of the organization, including the network, applications, website and wireless networks, physical facilities, cloud-based systems, and employees” (cipher.com). Open source information on the Internet and from other public sources can be used to build a profile of the target user or system to determine entry points into a computer system.

Automated OSINT is used by hackers and penetration testers to gather and analyze intelligence about a specific target from social networks, including names, online handles, jobs, friends, likes/dislikes/interactions, locations, pictures, etc. (McLaughlin, 2012). Recon-ng and Maltego are intelligence gathering tools designed to facilitate the process of gathering, analyzing, and organizing OSINT.

Penetration tests begin with an extensive information gathering phase. Open source information on the Internet can be used to build a profile of the target user or system. The vast majority of footprinting activity, also called OSINT, is passive in nature.&#x20;

Active recon involves social engineering and “anything that requires the hacker to interact with the organization” (Walker, 2017, p. 45).&#x20;

Social engineering is a threat that can exploit an ignorance (skill/knowledge gap) or credulity (lack of critical thinking) of the technology user (i.e., a gap in end-user security awareness) regarding the safe and ethical use of technology. Passive reconnaissance involves gathering information from the public domain in places like Internet registries, Google, newspapers, and public records.&#x20;

At this stage “the target does not even know generally that they are the subject of surveillance.” The first step involves collating technical information on an organization’s public-facing systems. “Internet registries, coupled with services such as Shodan or VPN Hunter, can highlight and identify an organization’s Web servers, mail servers, remote access endpoints and many other Internet-facing devices.” Methods include “gathering of competitive intelligence, using search engines, perusing social media sites, participating in the ever-popular dumpster dive, gaining network ranges, and raiding DNS for information” (Walker, 2017, p. 44). A key argument is that there is no clear cutoff point between passive and active intelligence gathering techniques. Wheeler (2011) notes, “Although passive testing sounds harmless, beware that the definition of passive is not always consistent across the field. There are definitely gray areas to be aware of.” The confusion includes whether the use of third parties for services is considered passive testing (e.g., Passive Information Gathering (Part 1), Ollmann, 2007), whether the process of testing can be traced back to the tester, and whether the information gathering can be performed without the knowledge of the organization under investigation (i.e., stealthy–the key emphasis here is that intelligence gathering does not draw attention and remains undetected).

**Network enumeration and port scanning passive and active methods/tools**

Network enumeration involves the discovery of active devices on a network and mapping them to their IP addresses.&#x20;

Network enumeration involves gathering information about a network such as connected devices and usernames using protocols like ICMP and SNMP.&#x20;

Once available hosts on a network have been found via network enumeration, port scanning can be used to discover the services in use on specific ports.

Port scanning refers to the process of sending packets to specific ports on a host in the network and analyzing the responses to learn details about its running network services and operating systems, software applications, thus locating potential vulnerabilities.&#x20;

Network enumeration and port scanning help testers map network services and topology to fine-tune their assault tactics. A tool like Nmap usually performs enumeration and scanning by launching custom TCP, UDP or ICMP packets against a given target. The target responds to the information requests in the form of a digital signature. This signature is key to identifying what software, protocols and OS is running the target device. Nmap scans can identify network services, operating system number and version, software applications, databases, and configurations, all with high probability.&#x20;

p0f is a passive monitoring alternative to Nmap, a passive fingerprinting tool that does not generate network traffic, used to analyze network traffic and identify patterns behind TCP/IP-based communications often blocked for Nmap active fingerprinting techniques.&#x20;

Passive fingerprinting uses sniffer traces from the remote system to determine the operating system of the remote host. p0f uses a fingerprinting technique “based on analyzing the structure of a TCP/IP packet to determine the operating system and other configuration properties of a remote host.” It includes powerful network-level fingerprinting features, and the ability to analyze application-level payloads such as HTTP, and can be used for detecting NAT, proxy and load balancing setups&#x20;

(see **Table** 18: Pen Source/Free Tools—for Network Penetration Testing).

Table 18: Pen Source/Free Tools—for Network Penetration Testing (Shah & Mehtre, 2015, p. 45)

<figure><img src="../.gitbook/assets/image.png" alt="open-source-penetration-testing-tools"><figcaption><p>Table 18: Pen Source/Free Tools—for Network Penetration Testing (Shah &#x26; Mehtre, 2015, p. 45)</p></figcaption></figure>

Network penetration testing and exploitation techniques typically include: Bypassing firewalls, Router testing, IPS/IDS evasion, DNS footprinting, Open port scanning and testing, SSH attacks, Proxy Servers, Network vulnerabilities, and Application penetration testing (Cipher, n.d.).

Passive network sniffers can monitor and capture data packets passing through a given network in real time. “Sniffers operate at the data link layer of the network. Any data sent across the LAN is actually sent to each and every machine connected to the LAN. This is called passive since sniffers placed by the attackers passively wait for the data to be sent and capture them.” “The most fundamental approaches to detecting cyber intrusions are to monitor server logs for signs of unauthorized access, to monitor firewall or router logs for abnormal events, and to monitor network performance for spikes in traffic” (EDUCAUSE, 2020). Placing a packet sniffer on a network in promiscuous mode allows a malicious intruder to capture and analyze all of the network traffic such as payloads containing confidential information. Treurniet (2004) used a proprietary tool developed at DRDC to analyze network traffic in 1999 to investigate whether “the information obtained through active methods may also be obtained by passively listening to traffic.” A network sniffer was “strategically placed on the network and the traffic is examined as it passes by. The behaviour of the traffic can be compared to an established policy for deviations” (p. 2). “Good agreement was found between the test program results and the documented network attributes” showing how passive scanning methods can be used in achieving network awareness without introducing unnecessary traffic (Treurniet, 2004, p. 2).&#x20;

See **Table** 19: Properties of a Network and Whether they Can Be Discovered Passively.

Effective network security requires real time awareness of the activities taking place on the network, to verify that the network policy is not being violated by any user or misconfiguration. A network can be periodically scanned to obtain real-time awareness. Active techniques to periodically scan the network have two disadvantages. First, they are intrusive, they introduce traffic into the network which consumes considerable bandwidth. Second, scanning can miss an activity, for example, when a specific port is probed with a specific protocol, because these look for a particular activity. These drawbacks can be addressed by using passive techniques where no traffic is introduced into the network. “Passive techniques have been in use in both defensive and offensive approaches for years but have only appeared recently in commercial products” (Treurniet, 2004, p. 1). “A sniffer is strategically placed on the network and the traffic is examined as it passes by. The behaviour of the traffic can be compared to an established policy for deviations” (Treurniet, 2004, p. iv). The passive technique can also identify information leaking form the network that could be used by malicious hackers. Attackers expect that active methods are used by organizations to test their own networks, so it “stands to reason, then, that more experienced attackers would also employ passive methods to obtain network information” (Treurniet, 2004, p. 2). Thus continuous surveillance or monitoring can be achieved using passive network sniffers to assess the security of a network.

Table 17: Five Phases of Reconnaissance\
Table 18: Pen Source/Free Tools—for Network Penetration Testing\
Table 19: Properties of a Network and Whether they Can Be Discovered Passively

### The penetration test report

A vulnerability scanner “actively communicates with the target system, sends the malicious packets and analyses the results, which can then be exported to PDF, HTML, CSV and other formats” (Rasskazov, 2013, p. 58). Typical vulnerability management software obtains the results and provides a comprehensive dashboard to present the results. “It can build trends, sort the results by criticality, and keep additional records, for example business purpose of the system or location” (Rodger, 2013, p. 48). The software’s reporting component can generate the compliance reports against widely used standards, for example PCI DSS, ISO 27001, or against the corporate policies, for example the percentage of computers with outdated software or weak password policy. Nexpose and other vendors include the vulnerability management software in the package with vulnerability scanners, while other vendors (e.g., Nessus) sell the software separately.

The penetration test report typically two sections: The executive summary and the technical report. “Primarily, the pentesters and their work is judged by their report” (Velu, 2013, p. 7). Pen test report writers address key considerations: Who is the audience of the report (e.g., senior management or IT staff), the purpose of testing, necessary procedures are justified, and required actions stated clearly. “A report should present outcome of the whole project by including objectives, used methodology, successful exploits, root cause of those exploits and recommendations” (Chaudhary, 2013, p.18). The report will offer an assessment of technical risk, business risk, reputational risk, and compliance risk. The key part of a penetration testing is the findings: Customers will want to prioritize the remediation activities according to classification of the findings.

The final report is a collection of all of the ethical hacker’s discoveries made during the evaluation. Vulnerabilities that were found to exist are explained and avoidance procedures specified. If the ethical hacker’s activities were noticed at all, the response of the client’s staff is described and suggestions for improvements are made. If social engineering testing exposed problems, advice is offered on how to raise awareness. This is the main point of the whole exercise: it does clients no good just to tell them that they have problems. The report must include specific advice on how to close the vulnerabilities and keep them closed. The actual techniques employed by the testers are never revealed. This is because the person delivering the report can never be sure just who will have access to that report once it is in the client’s hands. (Palmer, 2001, p. 779)

The final report is typically delivered directly to an officer of the client organization in hard-copy form. The ethical hackers would have an ongoing responsibility to ensure the safety of any information they retain, so in most cases all information related to the work is destroyed at the end of the contract. (Palmer, 2001, p. 779)

### Key takeaways

* Phases of the penetration testing process are planning and reconnaissance, scanning and enumeration, exploitation, post-exploitation, and reporting

### References

Abu-Shaqra, B. (2020). Technoethics and sensemaking: Risk assessment and knowledge management of ethical hacking in a sociotechnical society (2020-04-17T20:04:42Z) \[Doctoral dissertation, University of Ottawa]. uO Research.
