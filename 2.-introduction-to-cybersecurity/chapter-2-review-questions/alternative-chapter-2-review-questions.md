---
hidden: true
---

# Alternative Chapter 2 review questions

### Foundational cybersecurity concepts

**1. Define the three components of the CIA triad and provide a simple example of what protecting each one means for a company's customer database.**\
**Answer:**

* **Confidentiality:** Protecting information from unauthorized access. Example: Ensuring only authorized employees can view customer personal information using passwords and encryption.
* **Integrity:** Ensuring data is accurate and unaltered. Example: Preventing a hacker from maliciously changing customer order details or account balances.
* **Availability:** Ensuring information is accessible when needed. Example: Keeping the database online so customers can place orders and access their accounts without interruption.

**2. Explain the relationship between a vulnerability, a threat, and a risk in the context of information security.**\
**Answer:**\
A **vulnerability** is a weakness in a system (e.g., unpatched software). A **threat** is a potential danger that could exploit a vulnerability (e.g., a hacker looking to attack). **Risk** is the potential for loss or damage when a threat successfully exploits a vulnerability. It is often calculated as Threat × Vulnerability × Impact.

**3. What are the three standard responses to a risk identified during a risk assessment? Briefly describe each.**\
**Answer:**\
The three standard responses are:

* **Accept:** The cost of implementing countermeasures is deemed higher than the potential cost of the loss, so the risk is consciously accepted.
* **Mitigate:** Implementing safeguards and controls (like firewalls or policies) to reduce either the vulnerability or the impact of the threat.
* **Transfer:** Shifting the financial burden of the risk to another party, such as by purchasing cybersecurity insurance.

**4. The text states that a SYN flood attack is a technique that compromises availability. How does this attack work?**\
**Answer:**\
A SYN flood attack targets the TCP three-way handshake. An attacker sends a flood of SYN packets (connection requests), often with spoofed source IP addresses. The target server allocates resources for each request and sends back a SYN-ACK, but the attacker never sends the final ACK to complete the connection. This exhausts the server's resources, making it unable to respond to legitimate connection requests and causing a denial of service.

**5. Differentiate between the purposes of the RADIUS and TACACS+ protocols within the AAA framework.**\
**Answer:**\
Both RADIUS and TACACS+ are AAA protocols, but they have key differences:

* **RADIUS** is an open standard that combines authentication and authorization. It uses UDP and is often used for network access control (like Wi-Fi logins).
* **TACACS+** (developed by Cisco) separates authentication, authorization, and accounting into discrete processes. It uses TCP and provides more detailed control and accounting, making it popular for administering network devices like routers and switches.

### The cybersecurity threat landscape

**1. List two types of cybersecurity threats faced by individuals, as outlined in the section.**\
**Answer:** Identity theft/personal information theft and political interference/malicious online influence activity (e.g., through botnets).

**2. What are the four top information security risks that were a priority for higher education IT in 2016?**\
**Answer:** 1) Phishing and Social Engineering, 2) End-User Awareness, Training, and Education, 3) Limited Resources for the Information Security Program, and 4) Addressing Regulatory Requirements.

**3. According to Kool et al. (2017), what are the three phases in the "cybernetic loop" that characterizes the new wave of digitization?**\
**Answer:** The three phases are: 1) Collection (measuring processes in the physical world), 2) Analysis (of the resulting data), and 3) Application (real-time intervention based on that analysis).

**4. How does the "digital convergence of communications channels" expand the cybersecurity threat landscape?**\
**Answer:** It expands the threat landscape by interconnecting previously isolated systems (like telecom, broadcast, and IT) onto IP-based networks and cloud platforms. This creates new vulnerabilities, as attackers can exploit weaknesses in one sector (e.g., telecom) to attack another (e.g., a business's VoIP system or a government broadcast system).

**5. Name one technological driver and one sociopolitical driver that are changing the cybersecurity threat landscape.**\
**Answer:**

* **Technological Driver:** Artificial Intelligence/Machine Learning (AI/ML) OR Internet of Things (IoT) OR Social Digitization OR Digital Convergence OR A growing spyware industry.
* **Sociopolitical Driver:** U.S.-China rivalry for technological dominance OR Expansion of the military-industrial complex (collusion between governments, media, and tech companies).

### Common cyber attacks

**1. Explain the key difference between a reflection attack and an amplification attack.**\
**Answer:** Both are types of DoS attacks where an attacker spoofs the target's IP address to send traffic to it. A reflection attack sends traffic to a reflector (e.g., a DNS server) that then sends a reply to the target. An amplification attack is a specific, more powerful type of reflection attack where the attacker sends a small request that triggers a very large reply from the reflector to the target, thereby "amplifying" the volume of attack traffic.

**2. Describe what happens in an ARP spoofing (ARP poisoning) attack and name one mitigation technique.**\
**Answer:** In an ARP spoofing attack, an attacker sends fake gratuitous ARP replies to associate their own MAC address with the IP address of a legitimate device (like the default gateway). This tricks other hosts on the network into sending traffic intended for that legitimate IP to the attacker instead, allowing them to eavesdrop or modify the traffic. A primary mitigation technique is **Dynamic ARP Inspection (DAI)**.

**3. What are the two main characteristics that distinguish a worm from a virus?**\
**Answer:** 1) A worm is a standalone program and does not require a host file or program to infect. 2) A worm can self-replicate and spread across a network automatically without any user interaction.

**4. What is the purpose of a brute force password attack, and what is one key characteristic of a strong password that makes it resistant to such an attack?**\
**Answer:** The purpose of a brute force attack is to discover a password by systematically trying every possible combination of letters, numbers, and symbols. A strong password is resistant to this because it is **long (e.g., more than 8 characters)**, which exponentially increases the number of possible combinations and the time required to guess it.

**5. A user receives a phone call from someone claiming to be from the IT department who needs their password to perform a reset. What type of attack is this?**\
**Answer:** This is a **vishing** (voice phishing) attack, which is a form of social engineering.

### Cybersecurity risk mitigation methods

**1. Briefly describe the primary purpose of a Demilitarized Zone (DMZ) in network architecture.**\
**Answer:** A DMZ is a secure, isolated network segment positioned between the public internet and the internal private network. Its purpose is to host public-facing services (like web or email servers) so that external users can access them without being able to penetrate into the internal network, thereby limiting the potential damage of a breach.

**2. What is one key security benefit of using Network Address Translation (NAT)?**\
**Answer:** NAT enhances security by hiding the internal IP addresses of devices on a private network from the public internet. It obscures the internal network structure, making it harder for attackers to identify and target specific devices.

**3. Name two technical methods used to enforce network segmentation.**\
**Answer:** 1) Virtual Local Area Networks (VLANs) for Layer 2 segmentation. 2) Subnetting (with firewalls/ACLs between subnets) for Layer 3 segmentation.

**4. What is the critical difference between a user awareness program and a user training program in cybersecurity?**\
**Answer:** A user awareness program is designed to make employees conscious of threats (e.g., through simulated phishing emails), while a user training program is a more formal, dedicated session that educates users on policies and procedures (e.g., how to create strong passwords).

**5. List three components that should be included in a comprehensive Information Security Policy.**\
**Answer:** (Any three of the following) Data Classification and Handling policy, Access Control Policy, Incident Response Plan, Acceptable Use Policy (AUP), Vendor and Third-Party Risk Management policy.

### Network security risk mitigation best practices

