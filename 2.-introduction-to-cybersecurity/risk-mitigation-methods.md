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

Risk mitigation methods reduce the risk of a security breach or minimize the impact of an attack if it occurs.

Risk mitigation methods spanning **technologies** (firewalls, IDS/IPS, encryption, VPN), **network design** (segmentation, DMZ, and honeypots), **networking protocols** (don't use DTP/VTP; use encryption protocols), **organizational policies** (e.g., usage policy, security policy, privacy policy), **compliance frameworks, risk assessment/security testing, professional conduct, and security training.**

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

Common risk mitigation technologies include: Firewalls, IDS/IPS, Next-Gen Firewalls, Encryption, VPN, SIEM, EDR/XDR, Web Proxies, Network Access Control, Anti-Virus.

#### Firewalls

Firewalls are network security systems that control incoming and outgoing network traffic based on predetermined security rules. In their most basic form, firewalls do the same kinds of work that routers do with ACLs (Access Control Lists). ACLs are configured on network devices such as routers to only allow specific traffic to pass through based on source and destination IP addresses, ports, and protocols. However, firewalls can perform packet filtering with more granularity and additional security functions.

While firewalls share some router-like features (such as packet forwarding and filtering), they provide stronger security controls than a traditional router. For example, most firewalls use the following logic to determine whether to allow or discard a packet:

* **Source/Destination IP Matching** – Like router ACLs, firewalls filter traffic based on source and destination IP addresses.
* **Static Port-Based Filtering** – Identifies applications by matching well-known TCP/UDP ports (e.g., blocking port 23 for Telnet or allowing port 80 for HTTP).
* **Dynamic Port Tracking** – Monitors application-layer flows to detect additional TCP/UDP ports used mid-session (e.g., FTP data connections) and filters accordingly.
* **Stateful Inspection** – Maintains state tables to track active connections, allowing only legitimate follow-up traffic (e.g., permitting return packets for an established outbound session while blocking unsolicited inbound traffic).
* **Basic URI Filtering (Limited in Traditional Firewalls)** – Some firewalls can inspect HTTP requests and match text in URIs (web addresses) to block access to specific websites.

Unlike next-generation firewalls (NGFWs), traditional firewalls do not perform deep packet inspection (DPI), user-based authentication, or advanced application-layer analysis. Instead, they focus on **network-layer security** (IPs, ports, and connection states), making them efficient for basic traffic control but less effective against sophisticated threats.

• Intrusion Detection Systems (IDS): Network-based systems that monitor network traffic for signs of unauthorized access or malicious activity.

• Encryption: Converting plaintext data into unreadable ciphertext to protect it from unauthorized access.

• Virtual Private Networks (VPNs): Creating a secure, encrypted connection between two or more networks over the Internet.

### Risk mitigation via (re)design

Segmentation, DMZ, Honeypots, Defense in Depth

### Networking protocols&#x20;

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

### Organizational policies&#x20;

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

**Security awareness training**

**Security program elements (formal security training)**

A security program is an enterprise’s set of security policies and procedures. For the CCNA, there are a few elements we need to be aware of.

User awareness programs are designed to make employees aware of potential security threats and risks. User awareness programs will help make employees aware of all of the cyber threats the company is facing.

For example, a company might send out false phishing emails to make employees click a link and sign in with their login credentials. Employees who are tricked by the false emails will be informed that it is part of a user awareness program, and they should be more careful about phishing emails.

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
