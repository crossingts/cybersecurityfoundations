# Chapter 6 review questions

### What is professional ethical hacking

**1. What is the single most important characteristic that legally and ethically distinguishes a white hat hacker from a grey hat hacker?**\
**Answer:** The single most important characteristic is that a white hat hacker operates with **explicit, prior authorization** from the system owner, while a grey hat hacker does not.

**2. A professional ethical hacker is bound by a web of professional codes of conduct. Name three broad categories these authoritative codes and standards come from.**\
**Answer:** These codes and standards come from: (1) industry certifications and training authorities (e.g., EC-Council, (ISC)²), (2) professional associations (e.g., ACM, IEEE), and (3) industry standards/guidelines (e.g., OSSTMM, OWASP, NIST).

**3. While both grey hat and black hat hackers operate illegally, what key difference typically exists in their primary motivation?**\
**Answer:** The key difference is that a grey hat hacker's primary motivation is often to force a security fix or gain recognition, sometimes claiming to act in the public interest, whereas a black hat hacker's primary motivation is personal profit, destruction, or espionage.

**4. How do university accreditation bodies, like the Canadian Engineering Accreditation Board (CEAB), help instill a professional ethical mindset in future ethical hackers?**\
**Answer:** They require that ethics education be a mandatory part of the degree curriculum, ensuring students learn not only technical skills but also the professional codes of conduct and systematic, ethical decision-making they must follow in their careers.

**5. Trust is the currency of the profession for an ethical hacker. Why is trust considered so paramount?**\
**Answer:** Trust is paramount because ethical hackers are granted privileged access to an organization's most sensitive systems and data; without absolute trust, clients would not provide the necessary access, and the entire professional relationship would be impossible.

### The perils of unethical hacking

**1. What is the primary legal function of a contract that defines the "Scope of Work" for an ethical hacker?**\
**Answer:** The primary legal function is to provide explicit, prior authorization for the hacker's activities, creating a legal shield that distinguishes their security testing from unauthorized access, which is criminalized under laws like the CFAA.

**2. How can violating a responsible disclosure timeline, as outlined in a contract, negatively impact an ethical hacker?**\
**Answer:** Violating a responsible disclosure timeline is a breach of contract that can lead to the hacker being blacklisted from bug bounty platforms, facing civil liability for damages, and suffering severe reputational damage that ends their professional credibility.

**3. Beyond fines and imprisonment, what is a significant long-term consequence of a felony conviction for unethical hacking?**\
**Answer:** A significant long-term consequence is career destruction, which includes permanent blacklisting from the cybersecurity industry due to failed background checks, leading to long-term unemployment and an inability to rebuild a professional life.

**4. What is the key difference between the motivation of a hacktivist and that of a traditional black hat hacker?**\
**Answer:** The key difference is that a hacktivist is primarily motivated by political or social causes, e.g., promoting their ideology, whereas a black hat hacker is primarily motivated by personal profit, criminal intent, or malicious destruction.

**5. How do professional bodies like (ISC)² enforce accountability for certified ethical hackers?**\
**Answer:** They enforce accountability by maintaining and upholding a strict code of ethics, and they possess the authority to revoke certifications (like the CISSP) from members who engage in unethical or illegal behavior, thereby ending their credentialed status.

### What do ethical hackers do?

**1. Describe the purpose of a vulnerability assessment and list two key activities involved in the process.**\
**Answer**: The purpose of a vulnerability assessment is to systematically identify, quantify, and prioritize vulnerabilities in a system. Two key activities involved are asset discovery (using tools like Nmap to catalog hosts and services) and active or passive scanning (using tools like Nessus or Zeek to detect known vulnerabilities and misconfigurations).

**2. According to the NIST definition provided in the discussion, what are the three key elements a risk assessment process aims to identify regarding risks to system security?**\
**Answer**: A risk assessment aims to identify: (1) the risks to system security, (2) the probability of their occurrence, and (3) the resulting impact of those risks.

**3. A client needs to conduct a security evaluation. What are the three practical questions they must ponder, as defined by Palmer (2001), before beginning?**\
**Answer**: The client must determine: (1) What they are trying to protect (critical assets), (2) What they are trying to protect against (threats and loss events), and (3) How much time, effort, and money they are willing to expend to obtain adequate protection.

**4. Explain the key difference in purpose between a vulnerability scan and a penetration test.**\
**Answer**: A vulnerability scan serves as a detective control, aiming to identify and list known software vulnerabilities that may be exploited. A penetration test acts as a preventative control, aiming to actually exploit vulnerabilities to demonstrate what data can be compromised and discover unknown exposures.

**5. What is the role of penetration testing in relation to the findings of a vulnerability assessment, and what does this process provide for an organization?**\
**Answer**: The role of penetration testing is to act as a proof of concept by actively and safely exploiting vulnerabilities discovered during the vulnerability assessment. This process validates the vulnerability assessment results and provides tangible proof of the actual risk and business impact posed by the vulnerabilities.

### Network security testing

**1. The tools used for network security testing are loosely classified into two fundamental categories based on how they interact with the network. What are these two categories?**\
**Answer:** The two categories are (1) active scanners that send probe packets, and (2) passive packet analyzers that capture and analyze traffic.

**2. In a typical security testing workflow, Nmap and OpenVAS are used together. What is the primary function of each tool that makes them complementary?**\
**Answer:** Nmap's primary function is to discover live hosts, open ports, and running services, while OpenVAS's primary function is to automatically scan those discovered assets for known vulnerabilities.

**3. The section distinguishes between basic and deep packet inspection based on the OSI model layers they analyze. Which layers are primarily associated with each type of inspection?**\
**Answer:** Basic inspection primarily analyzes Layers 3 and 4 (Network and Transport), while deep packet inspection analyzes Layers 5 through 7 (Session, Presentation, and Application).

**4. According to the section's summary table, what is the fundamental analysis goal that distinguishes a communications protocol analyzer (like Wireshark) from a software analyzer (like Ghidra)?**\
**Answer:** A protocol analyzer aims to understand the _external_ communication behavior and find flaws in protocol implementation, while a software analyzer aims to understand the _internal_ logic and code execution to find memory corruption and logic flaws.

**5. The section differentiates between Penetration Testing and Vulnerability Research. What is the primary goal of each activity?**\
**Answer:** The primary goal of Penetration Testing is to find and exploit known vulnerabilities using established methodologies, while the primary goal of Vulnerability Research is to discover previously unknown vulnerabilities (zero-days) by deeply analyzing products.

### Defensive security vs offensive security

**1. The section distinguishes between the blue team as a functional concept and more formal team structures. What is the core function that defines a blue team, and what are two examples of formal teams that fulfill this function?**\
**Answer:** The core function is defensive security. Two examples of formal teams that fulfill this function are the Security Operations Center (SOC) and the Computer Security Incident Response Team (CSIRT/SIRT).

**2. The activities of a blue team are organized around three core functions. What are these three functions?**\
**Answer:** The three core functions are: (1) Prevent, (2) Detect, and (3) Respond.

**3. What is the key operational difference between a SOC and a CSIRT in terms of their activation and focus?**\
**Answer:** The key difference is that a SOC is a continuous, 24/7 operational unit focused on monitoring and alerting, while a CSIRT is an on-demand team that is activated for specific, major incidents to perform deep investigation and response.

**4. Both ethical hacking and red teaming involve authorized security testing. What is the primary objective that distinguishes a red team exercise from a standard ethical hacking engagement?**\
**Answer:** The primary objective of a red team exercise is to test the organization's overall detection and response capabilities, whereas a standard ethical hack focuses on finding and fixing technical vulnerabilities.

**5. The discussion introduces the concept of a "purple team" as an overlap between red and blue teams. What is the fundamental purpose of purple teaming?**\
**Answer:** The fundamental purpose of purple teaming is to facilitate collaboration and communication between the attackers (red team) and defenders (blue team) in order to maximize improvement of the organization's security posture.

### Defensive cybersecurity technologies

**1. Both UFW and iptables/nftables are host-based firewalls for Linux. What is the key characteristic that makes UFW the recommended choice for beginners over iptables?**\
**Answer:** The key characteristic is UFW's simplified command-line interface, which is designed to be uncomplicated and easier to use than the complex, granular syntax of iptables/nftables.

**2. Both Suricata and Zeek are popular open-source tools for analyzing network traffic. What is the primary functional objective that distinguishes Zeek from Suricata?**\
**Answer:** The primary objective of Zeek is to perform deep traffic analysis and generate detailed logs for forensic analysis, whereas Suricata is focused on real-time intrusion detection and prevention (IDS/IPS).

**3. Both Wazuh and Velociraptor provide capabilities for endpoint security. What is the primary focus that distinguishes Velociraptor's EDR functionality from Wazuh's?**\
**Answer:** The primary focus of Velociraptor is on endpoint hunting and live forensic investigation, while Wazuh focuses on being a unified SIEM platform with log analysis, file integrity monitoring, and compliance.

**4. Both Suricata and Zeek are used for network traffic analysis. What is the key operational difference in their real-time response capability that distinguishes Suricata from Zeek?**\
**Answer:** The key operational difference is that Suricata can function as an Intrusion Prevention System (IPS) for real-time, inline traffic blocking, whereas Zeek is primarily a passive Network Security Monitoring (NSM) tool for logging and analysis.

**5. Both packet-filtering firewalls (like iptables) and Web Application Firewalls (WAFs) control traffic. What is the key operational difference in the network layer at which they primarily operate?**\
**Answer:** Packet-filtering firewalls operate primarily at the network and transport layers (L3/L4), while WAFs operate at the application layer (L7) to protect specific web applications.

### Packet analyzers

**1. The section groups packet analyzers like Wireshark and tcpdump under a specific category of network monitoring technique. What is the fundamental characteristic of this technique that distinguishes it from active methods like port scanning?**\
**Answer:** The fundamental characteristic is that they are **passive** techniques; they capture and analyze traffic as it passes by on the network without introducing any probe packets or additional traffic.

**2. Wireshark and Zeek are both powerful analysis tools, but they have different primary outputs. What is the key difference in the analysis data each tool typically provides?**\
**Answer:** Wireshark's primary output is **raw or deeply dissected packets** (PCAP data), while Zeek's primary output is **structured, high-level log files** (e.g., for HTTP sessions, DNS queries) that summarize network activity.

**3. Both tcpdump and Snort can capture and analyze packets, but they are designed for different primary purposes. What is the primary function of each tool?**\
**Answer:** tcpdump's primary function is as a **packet sniffer** for capture and basic analysis, while Snort's primary function is as a **Network Intrusion Detection System (NIDS)** for real-time, rule-based threat detection and alerting.

**4. The Berkeley Packet Filter (BPF) syntax is a key feature for efficient packet capture. What is the primary performance benefit of using BPF filters during capture instead of applying filters afterward?**\
**Answer:** The primary benefit is **reduced CPU and memory usage** because BPF applies the filters at the kernel level, discarding unwanted packets before they are copied to user space, rather than capturing all packets and then filtering them.

**5. For a security team focused on threat hunting, a combination of Zeek and Suricata is recommended. What is the primary function of each tool in this complementary pairing?**\
**Answer:** Zeek's primary function is **behavioral analysis and structured traffic logging** for forensic investigation, while Suricata's primary function is **high-speed, real-time intrusion detection (IDS/IPS)** to alert on malicious activity.

### Phases of the penetration testing process

**1. According to the lesson, what is the single most important characteristic that distinguishes the reconnaissance phase from the scanning and enumeration phase?**\
**Answer:** The single most important characteristic is the objective: reconnaissance aims to build a profile of the target and identify entry points (the "what"), while scanning and enumeration aims to gather in-depth information on those specific targets to understand their characteristics and weaknesses (the "how" and "what can be extracted").

**2. The lesson describes two broad categories of intelligence gathering techniques. Name these two categories and the key behavioral characteristic that defines each.**\
**Answer:** The two categories are (1) Passive techniques, defined by gathering information without direct interaction with the target, and (2) Active techniques, defined by any activity that requires the hacker to interact with the target's systems or organization.

**3. A network sniffer is described as a tool that spans two phases. For what primary purpose is it used in the reconnaissance phase, and for what primary purpose is it used in the scanning and enumeration phase?**\
**Answer:** In the reconnaissance phase, it is used for footprinting and fingerprinting to map the network's structure (hosts, IPs, OS). In the scanning and enumeration phase, it is used to analyze packet payloads to extract sensitive information like credentials and identify specific vulnerabilities.

**4. The tool p0f is highlighted as a powerful alternative to active scanning. What specific type of technique does it represent, and what is one key advantage it holds over active tools like Nmap?**\
**Answer:** p0f represents a passive fingerprinting technique. A key advantage is that it does not generate any network traffic, making it undetectable to the target and allowing it to operate with a very low risk of detection.

**5. The penetration test report is the main deliverable of the entire process. What are the two primary sections this report is typically divided into?**\
**Answer:** The two primary sections are the Executive Summary, intended for management, and the Technical Report, which contains detailed findings for the IT staff.

### Types of penetration testing

**1. The approaches to penetration testing are often defined by the level of knowledge provided to the tester. What are the three primary categories based on this criterion?**\
**Answer:** The three primary categories are (1) White Box (full knowledge), (2) Black Box (zero knowledge), and (3) Grey Box (partial knowledge).

**2. A white box penetration test is considered less realistic but more thorough. Name two specific advantages it has over a black box test that contribute to this thoroughness.**\
**Answer:** Two advantages of a white box test are: (1) its ability to uncover logic flaws and hidden vulnerabilities that black box might miss, and (2) its speed, as no time is wasted on reconnaissance.

**3. A grey box penetration test provides a balanced approach. What kind of information is a tester typically given in this scenario to achieve this balance?**\
**Answer:** A tester in a grey box scenario is typically given partial knowledge, such as low-privilege user account credentials or limited documentation.

**4. The "Internal Network Testing" of a modern penetration test has a specific objective that differs from its external counterpart. What is the primary security goal of an internal network test?**\
**Answer:** The primary goal is to test the principles of Zero-Trust architecture by attempting to defeat internal segmentation, lateral movement controls, and privilege escalation mechanisms.

**5. The risks of penetration testing can be broadly categorized. Name the two main categories of risk discussed in the section.**\
**Answer:** The two main categories are (1) operational and data-related impacts (e.g., system crashes, data compromise), and (2) strategic risks (e.g., criminal eavesdropping on the test itself).

### Penetration testing methodologies and frameworks

**1. The OSSTMM 3.0 methodology moves away from "solution-based testing." What is its primary, alternative focus?**\
**Answer:** Its primary focus is on measuring the operational attack surface to generate a factual, data-driven security metric, rather than assuming the presence of specific security solutions.

**2. The NIST SP 800-115 methodology is structured around four main phases. Name them.**\
**Answer:** The four main phases are: (1) Planning, (2) Discovery, (3) Attack, and (4) Reporting.

**3. What is the specific and primary scope of the OWASP Web Security Testing Guide (WSTG), distinguishing it from broader methodologies?**\
**Answer:** Its specific scope is testing the security of web applications, APIs, and related services, providing a detailed checklist for vulnerabilities like the OWASP Top 10.

**4. The MITRE ATT\&CK framework is a knowledge base, not a full penetration testing methodology. What is its core purpose?**\
**Answer:** Its core purpose is to describe and categorize the real-world Tactics, Techniques, and Procedures (TTPs) used by adversaries.

**5. A penetration tester needs to conduct an assessment specifically to meet the mandatory requirements for protecting payment card data. Which standard or methodology must they follow?**\
**Answer:** They must follow the requirements outlined in the Payment Card Industry Data Security Standard (PCI-DSS).

### Penetration testing technologies

**1. Describe the primary purpose of the Nmap tool and list two of its core scanning capabilities.**\
**Answer:** The primary purpose of Nmap is network discovery, port scanning, and service enumeration. Two of its core capabilities are host discovery (using techniques like `-sn`) and service/version detection (using the `-sV` flag).

**2. According to the section's comparison, what are the primary purposes of OpenVAS and Nmap, and how do they complement each other in a typical workflow?**\
**Answer:** The primary purpose of Nmap is network discovery and service fingerprinting, while the primary purpose of OpenVAS is in-depth vulnerability detection and management. They complement each other as a security professional would use Nmap first for initial reconnaissance to find active hosts and open ports, and then use OpenVAS to perform a deep vulnerability scan against those discovered targets.

**3. Beyond simple traffic capture, what two key strengths of tcpdump make it indispensable for penetration testers, according to the section?**\
**Answer:** Two key strengths of tcpdump are its sophisticated filtering capabilities for isolating specific traffic from a high-volume stream, and its indispensability for forensic analysis and validating exploit delivery by capturing the exact sequence of network events.

**4. The Metasploit Framework is described as automating exploitation and post-exploitation workflows. What is a core feature of the Meterpreter payload that aids in the second phase?**\
**Answer:** A core feature of the Meterpreter payload that aids in post-exploitation is that it is a robust, in-memory agent that avoids writing to the disk, reducing the chance of detection.
