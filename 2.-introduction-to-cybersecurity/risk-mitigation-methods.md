---
description: >-
  This section discusses network security risk mitigation methods, including
  technologies, network design, networking protocols, organizational polices,
  compliance frameworks, and risk assessment
---

# Risk mitigation methods

## Learning objectives

• Point 1\
• Point 2 \
• Point 3\
• Point 4 \
• Point 5

This section reviews main risk mitigation methods used to reduce the risk of a security breach or minimize the impact of an attack if it occurs. Risk mitigation methods explored span technologies, network design, networking protocols, organizational policies, compliance frameworks, risk assessment/security testing, professional conduct, and security training.

## Topics covered in this section

* **Risk mitigation technologies**
* **Risk mitigation via (re)design**
* **Networking protocols**
* **Organizational policies**
* **Compliance frameworks**
* **Risk assessment/security testing**
* **Professional conduct**
* **Security training**

### Risk mitigation technologies

Common risk mitigation technologies include: Firewalls, IDS/IPS, Next-Generation IPS, Next-Generation Firewalls, Web Proxies, VPN, Encryption, SIEM, EDR/XDR, Network Access Control, Anti-Virus.

#### Firewalls

Firewalls are network security systems that control incoming and outgoing network traffic based on predetermined security rules. In their most basic form, firewalls do the same kinds of work that routers do with ACLs (Access Control Lists). ACLs are configured on network devices such as routers to only allow specific traffic to pass through based on source and destination IP addresses, ports, and protocols. However, firewalls can perform packet filtering with more granularity and additional security functions.

While firewalls share some router-like features (such as packet forwarding and filtering), they provide stronger security controls than a traditional router. For example, most firewalls use the following logic to determine whether to allow or discard a packet:

* **Source/Destination IP Matching** – Like router ACLs, firewalls filter traffic based on source and destination IP addresses.
* **Static Port-Based Filtering** – Identifies applications by matching well-known TCP/UDP ports (e.g., blocking port 23 for Telnet or allowing port 80 for HTTP).
* **Dynamic Port Tracking** – Monitors application-layer flows to detect additional TCP/UDP ports used mid-session (e.g., FTP data connections) and filters accordingly.
* **Stateful Inspection** – Maintains state tables to track active connections, allowing only legitimate follow-up traffic (e.g., permitting return packets for an established outbound session while blocking unsolicited inbound traffic).
* **Basic URI Filtering (Limited in Traditional Firewalls)** – Some firewalls can inspect HTTP requests and match text in URIs (web addresses) to block access to specific websites.

The firewall needs to sit in the path of the packets so it can filter the packets, redirect them for collection and later analysis, or let them continue toward their destination.&#x20;

Unlike next-generation firewalls (NGFWs), traditional firewalls do not perform deep packet inspection (DPI), user-based authentication, or advanced application-layer analysis. Instead, they focus on **network-layer security** (IPs, ports, and connection states), making them efficient for basic traffic control but less effective against sophisticated threats.

#### IDS/IPS

Intrusion Detection Systems (IDS) monitor network traffic for signs of unauthorized access or malicious activity. A traditional intrusion prevention system (IPS) can sit in the path packets take through the network, and it can filter packets, but it makes its decisions with different logic. The IPS first downloads a database of exploit signatures. Each signature defines different header field values found in sequences of packets used by different exploits. Then the IPS can examine packets, compare them to the known exploit signatures, and notice when packets may be part of a known exploit. Once identified, the IPS can log the event, discard packets, or even redirect the packets to another security application for further examination.

A traditional IPS differs from firewalls in that instead of an engineer at the company defining rules for that company based on applications (by port number) and zones, the IPS applies the logic based on signatures supplied mostly by the IPS vendor. Those signatures look for these kinds of attacks: DoS, DDoS, Worms, Viruses.

#### Industry focus: Cisco Next-Generation IPS

Next-generation IPS (NGIPS): An IPS device with advanced features, including the capability to go beyond a comparison to known attack signatures to also look at contextual data, including the vulnerabilities in the current network, the capability to monitor for new zero-day threats, with frequent updates of signatures from the Cisco Talos security research group.

The following list mentions a few of the Cisco NGIPS features (p. 103):

■ Traditional IPS: An NGIPS performs traditional IPS features, like using exploit signatures to compare packet flows, creating a log of events, and possibly discarding and/or redirecting packets.

■ Application Visibility and Control (AVC): As with NGFWs, an NGIPS has the ability to look deep into the application layer data to identify the application.

■ Contextual Awareness: NGFW platforms gather data from hosts—OS, software version/level, patches applied, applications running, open ports, applications currently sending data, and so on. Those facts inform the NGIPS as to the often more limited vulnerabilities in a portion of the network so that the NGIPS can focus on actual vulnerabilities while greatly reducing the number of logged events.

■ Reputation-Based Filtering: The Cisco Talos security intelligence group researches security threats daily, building the data used by the Cisco security portfolio. Part of that data identifies known bad actors, based on IP address, domain, name, or even specific URL, with a reputation score for each. A Cisco NGIPS can perform reputation-based filtering, taking the scores into account.

■ Event Impact Level: Security personnel need to assess the logged events, so an NGIPS provides an assessment based on impact levels, with characterizations as to the impact if an event is indeed some kind of attack.

#### Industry focus: Cisco Next-Generation Firewalls

Next-generation firewall (NGFW): A firewall device with advanced features, including the ability to run many related security features in the same firewall device (IPS, malware detection, VPN termination), along with deep packet inspection with Application Visibility and Control (AVC) and the ability to perform URL filtering versus data collected about the reliability and risk associated with every domain name.

The following list summarizes a few key features of an NGFW (pp. 101-102):

■ Traditional firewall: An NGFW performs traditional firewall features, like stateful firewall filtering, NAT/PAT, and VPN termination.

■ Application Visibility and Control (AVC): This feature looks deep into the application layer data to identify the application. For instance, it can identify the application based on the data, rather than port number, to defend against attacks that use random port numbers.

■ Advanced Malware Protection: NGFW platforms run multiple security services, not just as a platform to run a separate service, but for better integration of functions. A network-based antimalware function can run on the firewall itself, blocking file transfers that would install malware, and saving copies of files for later analysis.

■ URL Filtering: This feature examines the URLs in each web request, categorizes the URLs, and either filters or rate limits the traffic based on rules. The Cisco Talos security group monitors and creates reputation scores for each domain known in the Internet, with URL filtering being able to use those scores in its decision to categorize, filter, or rate limit.

■ NGIPS: The Cisco NGFW products can also run their NGIPS feature along with the firewall.

#### Web Proxies

**Understanding Proxies: Forward vs. Reverse**

Proxies act as intermediaries between clients and servers, but their roles differ significantly. A **forward proxy** sits in front of clients (e.g., users on a corporate network) and forwards their requests to the internet while masking their IP addresses—common in VPNs or censorship bypassing. In contrast, a **reverse proxy** sits in front of servers, receiving client requests and routing them to the appropriate backend (e.g., Apache, Node.js). This setup improves security by hiding server infrastructure and enhances performance through load balancing, SSL termination, and caching. For example, Nginx is often used as a reverse proxy to distribute traffic across multiple Apache servers while handling HTTPS encryption.

**How Reverse Proxies Optimize Web Servers**

Reverse proxies like Nginx or Traefik are crucial for modern web architectures. They efficiently manage traffic by directing requests based on paths (e.g., `/api` to a backend service, `/static` to cached files) and offloading heavy tasks like SSL decryption. This allows backend servers (such as Apache) to focus on processing dynamic content without exposure to direct internet traffic. Additionally, reverse proxies provide security benefits—blocking malicious requests, mitigating DDoS attacks, and acting as a shield for vulnerable applications. A typical setup might involve Nginx serving static content at high speed while proxying PHP requests to Apache for processing.

**Choosing the Right Proxy for Your Needs**

The choice between forward and reverse proxies depends on the use case. Forward proxies are ideal for user privacy and bypassing restrictions, while reverse proxies excel in optimizing server performance and security. For instance, a company might use a forward proxy to monitor employee internet traffic, while a high-traffic website would deploy a reverse proxy like Nginx to balance loads between servers. Both types can coexist—Cloudflare, for example, acts as a reverse proxy for websites while also offering forward proxy-like features (e.g., WARP VPN). Understanding these distinctions helps in designing scalable, secure, and efficient network infrastructures.

• **Virtual Private Networks (VPNs)**: Creating a secure, encrypted connection between two or more networks over the Internet.

• **Encryption**: Converting plaintext data into unreadable ciphertext to protect it from unauthorized access.

### Risk mitigation via (re)design

Segmentation, DMZ, Honeypots, Defense in Depth

#### Cybersecurity Risk Mitigation via Network (Re)Design

Effective cybersecurity risk mitigation begins with a well-designed network architecture that prioritizes security at every layer. By strategically segmenting networks, organizations can limit the spread of malware and unauthorized access, ensuring that breaches in one area do not compromise the entire system. A zero-trust model, which requires continuous authentication and authorization for all users and devices, further enhances security by eliminating implicit trust. Designing networks with these principles in mind reduces attack surfaces and improves overall resilience against cyber threats.

Key strategies for secure network (re)design include:

* **Network Segmentation**: Dividing the network into smaller, isolated zones (e.g., VLANs, subnets) to contain breaches.
* **Zero-Trust Architecture (ZTA)**: Enforcing strict access controls and verifying every request before granting access.
* **Micro-Segmentation**: Applying granular security policies to individual workloads or applications for enhanced protection.
* **Defense-in-Depth**: Layering security controls (firewalls, IDS/IPS, encryption) to provide multiple barriers against attacks.

#### Enhancing Visibility and Threat Detection

A secure network design must incorporate robust monitoring to detect and respond to threats in real time. Deploying intrusion detection and prevention systems (IDS/IPS) helps identify malicious activity, while endpoint detection and response (EDR) solutions track suspicious behavior across devices. Network traffic analysis (NTA) tools provide visibility into data flows, helping detect lateral movement by attackers. By integrating these technologies, organizations can proactively identify vulnerabilities and mitigate risks before they escalate.

Essential tools for improved network visibility:

* **Intrusion Detection/Prevention Systems (IDS/IPS)**: Monitoring for and blocking malicious traffic.
* **Endpoint Detection and Response (EDR)**: Analyzing endpoint activities for signs of compromise.
* **Network Traffic Analysis (NTA)**: Identifying unusual patterns that may indicate an attack.
* **SIEM Solutions**: Aggregating and correlating logs for centralized threat detection.

### Networking protocols

IPsec/GRE over IPsec, Encryption protocols/IEEE 802.11, DTP/VTP

Vulnerable protocols that transmit data in plaintext (e.g., FTP, SNMP v1/v2c community strings, Telnet passwords). Credentials and configuration data can be exposed to anyone on the network.

Network Address Translation (NAT): Hiding internal IP addresses from the public Internet by translating them to a public IP address.

**Network security protocols**

Network security protocols are essentially the security guards of your data traveling across a network. These protocols act as a set of rules that ensure the data gets from point A to B safely, without unauthorized access or alteration. There are different types of security protocols, each focusing on a specific aspect of data protection. Here's a quick breakdown:

• Encryption protocols: These scramble data using algorithms, making it unreadable to anyone without the decryption key. Examples include SSL/TLS, which secures communication on websites (like the padlock symbol you see in the address bar).

• Authentication protocols: These verify the identity of users or devices trying to access a network resource. Imagine them checking IDs at the entrance. Common examples include username/password logins or multi-factor authentication.

• Integrity protocols: These make sure data hasn't been tampered with during transmission. They act like checksums, ensuring the data received is exactly what was sent.

• Tunneling protocols: Imagine wrapping a message in another secure package. Tunneling protocols create a secure connection within another network, like a VPN (Virtual Private Network) securing your data over public Wi-Fi.

• Wireless network security protocols such as WPA or WPA2 are considered more secure than WEP.

### Organizational policies

Usage policy, Security policy, Privacy policy

**An information security policy covering:**

* Software development and testing/software security
* Network design and testing/network security
* Hardware security policy
* Standard operating procedures/information command and control policy
* Ethical code of conduct
* Security awareness training
* User responsibility/usage policies (AUP)
* Information security risk governance (cybersecurity regulations and IT governance compliance frameworks)
* Backup and disaster recovery

An organization’s information security policy has to be clear—and regularly updated. Employee’s knowledge of and adherence to information security policy are critical to robust data security.

### Compliance frameworks

### Risk assessment/security testing

Information security testing is performed in risk assessments and compliance audits. In fact, it is an essential part of both processes.

• Risk assessment: Information security testing is used to identify and assess the risks to an organization's information assets. This information is then used to develop and implement security controls to mitigate those risks.&#x20;

• Compliance audits: Information security testing is used to verify that an organization's information security controls are effective and are in compliance with applicable regulations.&#x20;

There are a variety of information security testing methods that can be used, including:

• Vulnerability scanning: This method scans an organization's systems and networks for known vulnerabilities.&#x20;

• Penetration testing: This method simulates an attack on an organization's systems and networks to identify and exploit vulnerabilities.&#x20;

• Social engineering testing: This method tests the effectiveness of an organization's security controls against social engineering attacks.&#x20;

• Physical security testing: This method tests the security of an organization's physical assets, such as its buildings and data centers.&#x20;

The specific information security testing methods that are used will vary depending on the organization's specific risk assessment and compliance requirements.

Some of the benefits of information security testing include:

• It helps to identify and assess risks to an organization's information assets.&#x20;

• It helps to verify that an organization's information security controls are effective and are in compliance with applicable regulations.&#x20;

• It helps to identify and fix security vulnerabilities before they are exploited by attackers.&#x20;

• It helps to improve an organization's overall security posture.

### Professional conduct

### Security training

As technology evolves, so do the tactics of attackers, making continuous learning and adaptation paramount in maintaining robust cybersecurity defenses.

In order to have great data security, it is important to maintain security awareness among employees. Good security awareness among IT personnel and other employees will allow your enterprise’s technical controls to work effectively. Employees should receive continuous security education.

**Security awareness training/security program (formal security training)**

A security program is an enterprise’s set of security policies and procedures.&#x20;

User awareness programs are designed to make employees aware of potential security threats and risks. User awareness programs will help make employees aware of all of the cyber threats the company is facing. For example, a company might send out false phishing emails to make employees click a link and sign in with their login credentials. Employees who are tricked by the false emails will be informed that it is part of a user awareness program, and they should be more careful about phishing emails.

User training programs are more formal than user awareness programs. For example, dedicated training sessions which educate users on the corporate security policies, how to create strong passwords, and how to avoid potential threats. These should happen when employees enter the company, and also at regular intervals during the year.

Physical access control, which protects equipment and data from potential attackers by only allowing authorized users into protected areas such as network closets or data center floors. This is not just to prevent people outside of the organization from gaining access to these areas. Even within the company, access to these areas should be limited to those who need access.

Multifactor locks can protect access to these restricted areas. For example, a door that requires users to swipe a badge and scan their fingerprint to enter. That’s something you have, a badge, and something you are, your fingerprint. Badge systems are very flexible, and permissions granted to a badge can easily be changed. This allows for strict, centralized control of who is authorized to enter where.

### Key takeaways

• Point 1\
• Point 2\
• Point 3 \
• Point 4 &#x20;

### References

Odom, W. (2020). Chapter 5. Securing Network Devices, CCNA 200-301 Official Cert Guide (pp. 86-105), Volume 2. Cisco Press.
