---
description: >-
  This section describes the phases of the penetration testing process, the
  goals of each phase, and key technologies used
---

# Phases of the penetration testing process

## Learning objectives <a href="#learning-objectives" id="learning-objectives"></a>

* Describe the phases of the penetration testing process
* Describe best practices for writing the penetration test report

This section describes the phases of the penetration testing process—planning, reconnaissance, scanning and enumeration, gaining access (exploitation) and privilege escalation, maintaining access, covering tracks, and reporting—including the goals of each phase and key technologies used. Further, this section describes best practices for writing the penetration test report.

## Topics covered in this section <a href="#topics-covered-in-this-section" id="topics-covered-in-this-section"></a>

* **Introduction**
* **Reconnaissance**
* **Scanning and enumeration**
* **Gaining access**
* **Maintaining access**
* **Covering tracks**
* **The penetration test report**

### Introduction <a href="#phases-of-the-penetration-testing-process" id="phases-of-the-penetration-testing-process"></a>

The penetration testing process can be broken down into several phases: planning or preparation, reconnaissance, scanning and enumeration, gaining access (exploitation) and privilege escalation, post-exploitation (maintaining access and covering tracks), and reporting (NIST SP 800-115, 2008; Walker, 2012, 2017).

<figure><img src="../../.gitbook/assets/Ethical-hacking-phases.jpg" alt="Ethical-hacking-phases"><figcaption><p>Ethical hacking phases</p></figcaption></figure>

In the planning phase, rules are identified, management approval is finalized and documented, and testing goals are set. The planning phase sets the groundwork for a successful penetration test. No actual testing occurs in this phase. (NIST SP 800-115, 2008, p. 5-2)

In the words of Walker (2012, 2017),

There are three main phases to a pen test—preparation, assessment, and conclusion—and they are fairly easy to define and understand. (Walker, 2012, p. 8)

The preparation step defines the timeline and scope of the penetration test, "the types of attacks allowed, and the individuals assigned to perform the activity" (Walker, 2012, p. 8).

The assessment phase (sometimes also known as the security evaluation phase) is exactly what it sounds like—the actual assaults on the security controls are conducted during this time. Lastly, the conclusion (or post-assessment) phase defines the time when final reports are prepared for the customer, detailing the findings of the tests (including the types of tests performed) and many times even providing recommendations to improve security. (Walker, 2012, p. 8)

Penetration tests should be seen as targeted exercises. Test objectives and the specific machines or applications to be tested are all specified upfront in a contractual agreement between the client and the ethical hacker during the planning phase. Each test objective will have its own set of parameters and processes. The agreement provides a precise description, typically in the form of specific IP addresses, domain names, or cloud instance identifiers, of the systems to be evaluated.

Precision is critical, as a minor error could lead to testing the wrong system or, in the worst case, the systems of an unrelated organization. (Palmer, 2001, p. 775)

For Walker (2017), the the assessment step or “act of hacking” is comprised of five main phases: 1) Reconnaissance, which involves the steps taken to gather evidence and information on the target; 2) scanning and enumeration, which takes the information gathered in reconnaissance and applies tools and techniques to gather more in-depth information on the targets; 3) gaining access, where “true attacks are leveled against the targets enumerated in the second phase”; 4) maintaining access, where hackers attempt to ensure they have a way back into the compromised system; and 5) covering tracks, where “attackers attempt to conceal their success and avoid detection by security professionals” (p. 36). In practice, assessment phases run concurrently and continuously throughout a penetration test (Walker, 2017).

For the purposes of this section, ethical hacking refers to the overarching process of 1) preparing for or planning for a penetration test, 2) performing a penetration test (what Walker, 2012/2017, and EC-Council identify as the assessment phase of the penetration test and which is common to both malicious and ethical hackers), and 3) reporting on the findings of the penetration test.

### Reconnaissance

Penetration tests begin with an extensive information gathering phase to build a profile of the target user or system to determine entry points.

Reconnaissance can be passive or active. Passive reconnaissance involves gathering information from the public domain (OSINT) in places like Internet registries, Google, newspapers, and public records. At this stage “the target does not even know generally that they are the subject of surveillance.” Active reconnaissance involves social engineering and “anything that requires the hacker to interact with the organization” (Walker, 2017, p. 45). Most reconnaissance activities are passive in nature.

OSINT involves collating technical information on an organization’s public-facing systems. “Internet registries, coupled with services such as Shodan or VPN Hunter, can highlight and identify an organization’s Web servers, mail servers, remote access endpoints and many other Internet-facing devices.” During OSINT, the penetration tester "uncovers possible weaknesses and entry points within the security posture of the organization, including the network, applications, website and wireless networks, physical facilities, cloud-based systems, and employees” (cipher.com).

Automated OSINT is used by hackers and penetration testers to gather and analyze intelligence about a specific target from social networks, including names, online handles, jobs, friends, likes/dislikes/interactions, locations, pictures, etc. (McLaughlin, 2012). Recon-ng and Maltego are intelligence gathering tools designed to facilitate the process of gathering, analyzing, and organizing OSINT.

Faircloth (2011) proposes an iterative five stage reconnaissance phase: Intelligence Gathering, Footprinting, Human Recon, Verification, and Vitality. Building on Faircloth (2011), follows is a table summarizing the stages of the reconnaissance phase. The Verification phase is implied, and the Vitality phase can be omitted in passive reconnaissance.

**Table: Phases of Reconnaissance (Adapted from Faircloth, 2011)**

<table><thead><tr><th valign="top">Phase</th><th valign="top">Objectives</th><th valign="top">Output</th><th valign="top">Tools</th></tr></thead><tbody><tr><td valign="top"><p>Intelligence</p><p>Gathering</p></td><td valign="top">To learn as much about the target, its business, its organizational structure, and its business partners as possible.</td><td valign="top">The output of this phase is a list of company names, partner organization names, and DNS names which reflect the entire target organization including all of its brands, divisions, and local representations.</td><td valign="top"><p># Search engines</p><p># Financial databases</p><p># Business reports</p><p># WHOIS</p><p># RWHOIS</p><p># Domain name registries and registrars</p><p># Web archives</p><p># Data mining tools</p></td></tr><tr><td valign="top">Footprinting</td><td valign="top">To mine as many DNS host names as possible from the domains or company names collected and translate those into IP addresses or IP address ranges.</td><td valign="top">The output of this phase is a list of DNS host names, IP addresses, and IP address ranges.</td><td valign="top"><p># DNS</p><p># WHOIS</p><p># DIG</p><p># SMTP</p><p># Data mining tools</p></td></tr><tr><td valign="top"><p>Human</p><p>Recon</p></td><td valign="top">To analyze the human perspective of the target and gain as much intelligence as possible about the people associated with the organization.</td><td valign="top">The output of this phase is a list of names, job titles, contact information, and other personal details about the people associated with the organization.</td><td valign="top"><p># Search engines</p><p># Email lists and web site posts</p><p># Social networking services</p><p># Publicly available records</p></td></tr><tr><td valign="top">Vitality</td><td valign="top">To confirm the reachability of the IP addresses identified in prior phases. This is a phase which spreads between reconnaissance and enumeration.</td><td valign="top">The output of this phase is a list of IP addresses from prior phases which have been confirmed as reachable.</td><td valign="top"><p># PING</p><p># Port scanners</p><p># Mapping tools</p></td></tr></tbody></table>

A key argument is that there is no clear cutoff point between passive and active intelligence gathering techniques. The definition of passive is not always consistent across the field. The confusion includes whether the information gathering can be performed without the knowledge of the organization under investigation (i.e., remains stealthy), and whether the process of testing can be traced back to the tester's location or IP address.

### Scanning and enumeration

Security analysts now apply the information they gathered in reconnaissance towards gathering more in-depth information on the targets. Scanning and enumeration can be,

something as simple as running a ping sweep or a network mapper to see what systems are on the network, or as complex as running a vulnerability scanner to determine which ports may be open on a particular system. For example, whereas recon may have shown the network to have 500 or so machines connected to a single subnet inside a building, scanning and enumeration would tell me which ones are Windows machines and which ones are running FTP. (Walker, 2012, p. 9)

**Scanning vs Enumeration**

| **Scanning**                              | **Enumeration**                                             |
| ----------------------------------------- | ----------------------------------------------------------- |
| _"What's alive and what ports are open?"_ | _"What can I extract from those services?"_                 |
| Broad, network-level discovery            | Targeted, service-specific probing                          |
| Tools: `nmap`, `masscan`, `arp-scan`      | Tools: `enum4linux`, `Metasploit aux modules`, `ldapsearch` |

Both passive and active techniques exist for scanning and enumeration. There are three major types of scanning—network scanning, port scanning, and vulnerability scanning. Enumeration techniques include Banner Grabbing, NetBIOS Enumeration, SNMP Enumeration, using LDAP, and using NTP and SMTP.

A tool like Nmap usually performs scanning and enumeration by launching custom TCP, UDP or ICMP packets against a given target. The target responds to the information requests in the form of a digital signature. This signature is key to identifying what software, protocols and OS is running the target device. Nmap scans can identify network services, OS number and version, software applications, databases, and configurations, all with high probability.

p0f is a passive monitoring Nmap alternative. p0f is a passive fingerprinting tool that does not generate network traffic. It is used to analyze network traffic and identify patterns behind TCP/IP-based communications often blocked for Nmap active fingerprinting techniques. Passive fingerprinting uses sniffer traces from the remote system to determine the operating system of the remote host. p0f uses a fingerprinting technique based on analyzing the structure of a TCP/IP packet to determine the OS and other configuration properties of a remote host. It includes powerful network-level fingerprinting features, and the ability to analyze application-level payloads such as HTTP, and can be used for detecting NAT, proxy and load balancing setups.

**Passive vs Active Discovery Techniques**

| **Type**           | **Passive**                  | **Active**            |
| ------------------ | ---------------------------- | --------------------- |
| **Interaction**    | No direct contact            | Direct probes         |
| **Detection Risk** | Low                          | High                  |
| **Speed/Accuracy** | Slower, less precise         | Faster, more detailed |
| **Use Case**       | Early recon, avoiding alerts | Post-recon, deep dive |

Passive network sniffers can monitor and capture data packets passing through a given network in real time. “Sniffers operate at the data link layer of the network. Any data sent across the LAN is actually sent to each and every machine connected to the LAN. This is called passive since sniffers placed by the attackers passively wait for the data to be sent and capture them.” Placing a packet sniffer on a network in promiscuous mode allows a malicious intruder to capture and analyze all of the network traffic such as payloads containing confidential information.

**Network Sniffers in the Penetration Testing Process**

Network sniffers are versatile tools whose function evolves across the penetration testing lifecycle, providing critical intelligence in both the Reconnaissance and Scanning & Enumeration phases. The same sniffer, deployed once, can fulfill different roles based on the analyst's focus—shifting from mapping the network's structure to probing its deepest vulnerabilities, all without sending a single packet and thus maintaining complete stealth.

During the **Reconnaissance** phase, a passively deployed sniffer acts as a powerful **footprinting** tool. It builds a foundational profile of the target by listening to network traffic, which allows the tester to compile a map of active hosts, their IP and MAC addresses, and the core network protocols in use. Furthermore, sniffers can also be deployed as powerful **fingerprinting** tools. Techniques used by tools like p0f analyze the subtle characteristics of TCP/IP packets—such as TCP window sizes and TTL values—to determine the operating system and other configuration properties of the communicating hosts. This passive fingerprinting can even detect network setups like NAT, proxy servers, and load balancers, significantly enriching the reconnaissance profile without any direct interaction.

As the assessment progresses into the **Scanning & Enumeration** phase, the sniffer's role deepens from mapping to detailed investigation. The analyst shifts from identifying _what assets exist_ to enumerating _what weaknesses and data they expose_. This involves a detailed analysis of the captured packet payloads to extract sensitive information like cleartext credentials, confidential data in transit, or specific application commands. The discovery of an unencrypted password within a packet, for instance, is no longer just information gathering; it is the direct identification of a critical vulnerability. This passive form of enumeration provides definitive evidence of security failures and often directly enables the subsequent phase of gaining access.

### Gaining access

Now true attacks are leveled against the targets enumerated in the second phase.

These attacks can be as simple as accessing an open and nonsecured wireless access point and then manipulating it for whatever purpose, or as complex as writing and delivering a buffer overflow or SQL injection against a web application. (Walker, 2012, p. 10)

### Maintaining access

Now hackers attempt to ensure they have a way back into the compromised system.

Back doors are left open by the attacker for future use—especially if the system in question has been turned into a zombie (a machine used to launch further attacks from) or if the system is used for further information gathering—for example, a sniffer can be placed on a compromised machine to watch traffic on a specific subnet. Access can be maintained through the use of Trojans, rootkits, or any number of other methods. (Walker, 2012, p. 10)

The concept of “escalation of privileges” between phases 3 and 4 refers to actions taken by a hacker to promote his access to root or administrative levels.

### Covering tracks

Now, in the final phase of security assessment, hackers attempt to conceal their presence in the compromised machines to avoid detection.

Steps taken here consist of removing or altering log files, hiding files with hidden attributes or directories, and even using tunneling protocols to communicate with the system. If auditing is even turned on and monitored, and often it is not, log files are an indicator of attacks on a machine. Clearing the log file completely is just as big an indicator to the security administrator watching the machine, so sometimes selective editing is your best bet. Another great method to use here is simply corrupting the log file itself—whereas a completely empty log file screams an attack is in progress, files get corrupted all the time and, chances are, the administrator won’t bother to try to rebuild it. In any case, good pen testers are truly defined in this phase. (Walker, 2012, p. 10)

The following table, Pen Source/Free Tools—for Network Penetration Testing (Shah & Mehtre, 2015, p. 45), offers a summary of common open source network penetration testing tools, including their function and operating system compatibility.

<figure><img src="../../.gitbook/assets/image (1) (1) (1) (1) (1).png" alt="Open-Source-Network-Penetration-Testing-Tools"><figcaption><p>Pen Source/Free Tools—for Network Penetration Testing (Shah &#x26; Mehtre, 2015, p. 45)</p></figcaption></figure>



### The penetration test report

A vulnerability scanner “actively communicates with the target system, sends the malicious packets and analyses the results, which can then be exported to PDF, HTML, CSV and other formats” (Rasskazov, 2013, p. 58). Typical vulnerability management software obtains the results and provides a comprehensive dashboard to present the results. “It can build trends, sort the results by criticality, and keep additional records, for example business purpose of the system or location” (Rodger, 2013, p. 48). The software’s reporting component can generate the compliance reports against widely used standards, for example PCI DSS, ISO 27001, or against the corporate policies, for example the percentage of computers with outdated software or weak password policy. Nexpose and other vendors include the vulnerability management software in the package with vulnerability scanners, while other vendors (e.g., Nessus) sell the software separately.

The penetration test report typically two sections: The executive summary and the technical report. “Primarily, the pentesters and their work is judged by their report” (Velu, 2013, p. 7). Pen test report writers address key considerations: Who is the audience of the report (e.g., senior management or IT staff), the purpose of testing, necessary procedures are justified, and required actions stated clearly. “A report should present outcome of the whole project by including objectives, used methodology, successful exploits, root cause of those exploits and recommendations” (Chaudhary, 2013, p.18). The report will offer an assessment of technical risk, business risk, reputational risk, and compliance risk. The key part of a penetration testing is the findings: Customers will want to prioritize the remediation activities according to classification of the findings.

The final report is a collection of all of the ethical hacker’s discoveries made during the evaluation. Vulnerabilities that were found to exist are explained and avoidance procedures specified. If the ethical hacker’s activities were noticed at all, the response of the client’s staff is described and suggestions for improvements are made. If social engineering testing exposed problems, advice is offered on how to raise awareness. This is the main point of the whole exercise: it does clients no good just to tell them that they have problems. The report must include specific advice on how to close the vulnerabilities and keep them closed. The actual techniques employed by the testers are never revealed. This is because the person delivering the report can never be sure just who will have access to that report once it is in the client’s hands. (Palmer, 2001, p. 779)

The final report is typically delivered directly to an officer of the client organization in hard-copy form. The ethical hackers would have an ongoing responsibility to ensure the safety of any information they retain, so in most cases all information related to the work is destroyed at the end of the contract. (Palmer, 2001, p. 779)

### Key takeaways

* Phases of the penetration testing process are planning, reconnaissance, scanning and enumeration, exploitation, post-exploitation, and reporting
* The two phases of reconnaissance, and scanning and enumeration are intelligence gathering phases that serve to prepare for an exploit strategy against a target. Each of the two phases can be either passive or active
* Reconnaissance can be passive (e.g., OSINT, WHOIS, social media) or active (e.g., DNS queries, network probing)
* Reconnaissance uncovers information about the target company:
  * Company structure (partners, subsidiaries).
  * Employee details (names, roles, email formats).
  * Network infrastructure (domains, subdomains, IP ranges).
  * Publicly exposed services (via search engines, Shodan).
* Scanning is more intrusive than reconnaissance, often active. Scanning techniques include:
  * Host discovery (ICMP, ARP, TCP/UDP probes).
  * Port scanning (TCP SYN, Connect, UDP scans).
  * OS & service fingerprinting (banner grabbing, version detection).
  * Vulnerability scanning (automated tools like Nessus, OpenVAS).
* Scanning discovers live hosts, open ports, running services, and potential vulnerabilities
* Enumeration represents deeper probing to extract usable attack surfaces:
  * User accounts (via LDAP, SMB, SMTP, RPC).
  * Network shares & services (NFS, Samba, NetBIOS).
  * Application-specific data (SQL databases, SNMP, DNS records).
  * Email lists (harvested from exposed directories or breaches).
  * Results in a refined target list (e.g., vulnerable services, weak credentials).

In practice, assessment phases run concurrently and continuously throughout a penetration test (Walker, 2017).

A key argument is that there is no clear cutoff point between passive and active intelligence gathering techniques.

### References

Cipher. (n.d.). Reconnaissance, Intelligence Gathering or Open Source Intelligence (OSINT) Gathering. Retrieved January 21, 2020, from https://cipher.com/blog/the-types-of-pentests-you-must-know-about/

Faircloth, J. (2011). _Penetration tester’s open source toolkit_. Penetration tester’s open source toolkit. Retrieved from www.scopus.com

NIST Special Publication 800-115: Technical Guide to Information Security Testing and Assessment (NIST 800-115). Retrieved January 21, 2020, from http://csrc.nist.gov/publications/nistpubs/800-115/SP800-115.pdf

Palmer, C. C. (2001). Ethical hacking. _IBM Systems Journal, 40_(3), 769-780.

Shah, S., & Mehtre, B. M. (2015). An overview of vulnerability assessment and penetration testing techniques. _Journal of Computer Virology and Hacking Techniques, 11_(1), 27-49. doi:10.1007/s11416-014-0231-x

Walker, M. (2012). Certified Ethical Hacker Exam Guide. Columbus: McGraw-Hill Osborne.

Walker, M. (2017). CEH Certified Ethical Hacker All-in-One Exam Guide, Second Edition. New York, NY: McGraw-Hill Education.
