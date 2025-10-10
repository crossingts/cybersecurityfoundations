# Chapter 6 review questions

### What is professional ethical hacking

**1. What is the single most important characteristic that legally and ethically distinguishes a white hat hacker from a grey hat hacker?**
**Answer:** The single most important characteristic is that a white hat hacker operates with **explicit, prior authorization** from the system owner, while a grey hat hacker does not.

**2. A professional ethical hacker is bound by a web of professional codes of conduct. Name three broad categories these authoritative codes and standards come from.**
**Answer:** These codes and standards come from: (1) industry certifications and training authorities (e.g., EC-Council, (ISC)²), (2) professional associations (e.g., ACM, IEEE), and (3) industry standards/guidelines (e.g., OSSTMM, OWASP, NIST).

**3. While both grey hat and black hat hackers operate illegally, what key difference typically exists in their primary motivation?**
**Answer:** The key difference is that a grey hat hacker's primary motivation is often to force a security fix or gain recognition, sometimes claiming to act in the public interest, whereas a black hat hacker's primary motivation is personal profit, destruction, or espionage.

**4. How do university accreditation bodies, like the Canadian Engineering Accreditation Board (CEAB), help instill a professional ethical mindset in future ethical hackers?**
**Answer:** They require that ethics education be a mandatory part of the degree curriculum, ensuring students learn not only technical skills but also the professional codes of conduct and systematic, ethical decision-making they must follow in their careers.

**5. The lesson states that "trust is the currency of the profession" for an ethical hacker. Why is trust considered so paramount?**
**Answer:** Trust is paramount because ethical hackers are granted privileged access to an organization's most sensitive systems and data; without absolute trust, clients would not provide the necessary access, and the entire professional relationship would be impossible.

### The perils of unethical hacking

**1. What is the primary legal function of a contract that defines the "Scope of Work" for an ethical hacker?**
**Answer:** The primary legal function is to provide explicit, prior authorization for the hacker's activities, creating a legal shield that distinguishes their security testing from unauthorized access, which is criminalized under laws like the CFAA.

**2. How can violating a responsible disclosure timeline, as outlined in a contract, negatively impact an ethical hacker?**
**Answer:** Violating a responsible disclosure timeline is a breach of contract that can lead to the hacker being blacklisted from bug bounty platforms, facing civil liability for damages, and suffering severe reputational damage that ends their professional credibility.

**3. Beyond fines and imprisonment, what is a significant long-term consequence of a felony conviction for unethical hacking?**
**Answer:** A significant long-term consequence is career destruction, which includes permanent blacklisting from the cybersecurity industry due to failed background checks, leading to long-term unemployment and an inability to rebuild a professional life.

**4. What is the key difference between the motivation of a hacktivist and that of a traditional black hat hacker?**
**Answer:** The key difference is that a hacktivist is primarily motivated by political or social causes, e.g., promoting their ideology, whereas a black hat hacker is primarily motivated by personal profit, criminal intent, or malicious destruction.

**5. How do professional bodies like (ISC)² enforce accountability for certified ethical hackers?** **Answer:** They enforce accountability by maintaining and upholding a strict code of ethics, and they possess the authority to revoke certifications (like the CISSP) from members who engage in unethical or illegal behavior, thereby ending their credentialed status.

### What do ethical hackers do?

**1. Describe the purpose of a vulnerability assessment and list two key activities involved in the process.**
Answer: The purpose of a vulnerability assessment is to systematically identify, quantify, and prioritize vulnerabilities in a system. Two key activities involved are asset discovery (using tools like Nmap to catalog hosts and services) and active or passive scanning (using tools like Nessus or Zeek to detect known vulnerabilities and misconfigurations).

**2. According to the NIST definition provided in the lesson, what are the three key elements a risk assessment process aims to identify regarding risks to system security?**
Answer: A risk assessment aims to identify: (1) the risks to system security, (2) the probability of their occurrence, and (3) the resulting impact of those risks.

**3. A client needs to conduct a security evaluation. What are the three practical questions they must ponder, as defined by Palmer (2001), before beginning?**
Answer: The client must determine: (1) What they are trying to protect (critical assets), (2) What they are trying to protect against (threats and loss events), and (3) How much time, effort, and money they are willing to expend to obtain adequate protection.

**4. Explain the key difference in purpose between a vulnerability scan and a penetration test.** Answer: A vulnerability scan serves as a detective control, aiming to identify and list known software vulnerabilities that may be exploited. A penetration test acts as a preventative control, aiming to actually exploit vulnerabilities to demonstrate what data can be compromised and discover unknown exposures.

**5. What is the role of penetration testing in relation to the findings of a vulnerability assessment, and what does this process provide for an organization?**
Answer: The role of penetration testing is to act as a proof of concept by actively and safely exploiting vulnerabilities discovered during the vulnerability assessment. This process validates the vulnerability assessment results and provides tangible proof of the actual risk and business impact posed by the vulnerabilities.

Network security testing

1. The tools used for network security testing are loosely classified into two fundamental categories based on how they interact with the network. What are these two categories?  
    **Answer:** The two categories are (1) active scanners that send probe packets, and (2) passive packet analyzers that capture and analyze traffic.
    
2. In a typical security testing workflow, Nmap and OpenVAS are used together. What is the primary function of each tool that makes them complementary?  
    **Answer:** Nmap's primary function is to discover live hosts, open ports, and running services, while OpenVAS's primary function is to automatically scan those discovered assets for known vulnerabilities.
    
3. The lesson distinguishes between basic and deep packet inspection based on the OSI model layers they analyze. Which layers are primarily associated with each type of inspection?  
    **Answer:** Basic inspection primarily analyzes Layers 3 and 4 (Network and Transport), while deep packet inspection analyzes Layers 5 through 7 (Session, Presentation, and Application).
    
4. According to the lesson's summary table, what is the fundamental analysis goal that distinguishes a communications protocol analyzer (like Wireshark) from a software analyzer (like Ghidra)?  
    **Answer:** A protocol analyzer aims to understand the _external_ communication behavior and find flaws in protocol implementation, while a software analyzer aims to understand the _internal_ logic and code execution to find memory corruption and logic flaws.
    
5. The lesson differentiates between Penetration Testing and Vulnerability Research. What is the primary goal of each activity?  
    **Answer:** The primary goal of Penetration Testing is to find and exploit _known vulnerabilities_ using established methodologies, while the primary goal of Vulnerability Research is to discover _previously unknown vulnerabilities_ (zero-days) by deeply analyzing products.

Defensive security vs offensive security

**1. The lesson distinguishes between the blue team as a functional concept and more formal team structures. What is the core function that defines a blue team, and what are two examples of formal teams that fulfill this function?**
**Answer:** The core function is defensive security. Two examples of formal teams that fulfill this function are the Security Operations Center (SOC) and the Computer Security Incident Response Team (CSIRT/SIRT).

**2. The activities of a blue team are organized around three core functions. What are these three functions?**
**Answer:** The three core functions are: (1) Prevent, (2) Detect, and (3) Respond.

**3. According to the lesson, what is the key operational difference between a SOC and a CSIRT in terms of their activation and focus?**
**Answer:** The key difference is that a SOC is a continuous, 24/7 operational unit focused on monitoring and alerting, while a CSIRT is an on-demand team that is activated for specific, major incidents to perform deep investigation and response.

**4. Both ethical hacking and red teaming involve authorized security testing. What is the primary objective that distinguishes a red team exercise from a standard ethical hacking engagement?**
**Answer:** The primary objective of a red team exercise is to test the organization's overall detection and response capabilities, whereas a standard ethical hack focuses on finding and fixing technical vulnerabilities.

**5. The lesson introduces the concept of a "purple team" as an overlap between red and blue teams. What is the fundamental purpose of purple teaming?**
**Answer:** The fundamental purpose of purple teaming is to facilitate collaboration and communication between the attackers (red team) and defenders (blue team) in order to maximize improvement of the organization's security posture.
