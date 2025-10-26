---
description: >-
  This section explores types of penetration testing, differentiates black box
  from white box penetration testing, and explores possible risks of penetration
  testing
---

# Types of penetration testing

## Learning objectives

* Describe main types of penetration testing
* Compare black box and white box penetration testing methods
* Identify the possible risks of penetration testing

This section explores six types of penetration testing (network penetration testing, wireless network penetration testing, website/web application penetration testing, physical penetration testing, social engineering, and cloud penetration testing), compares between black box and white box penetration testing, and sheds light on possible risks of penetration testing to the client organization.

## Topics covered in this section

* **Types of penetration testing**
* **Black box penetration testing and white box penetration testing**
* **Risks of penetration testing**

### Types of penetration testing

Penetration testing is scoped to target specific segments of an organization's attack surface. A comprehensive security program employs a variety of tests, each designed to identify vulnerabilities in different technologies and environments. Network penetration testing and exploitation techniques typically include bypassing firewalls, router testing, IPS/IDS evasion, DNS footprinting, open port scanning and testing, SSH attacks, proxy servers, network vulnerabilities, and application penetration testing (Cipher, n.d.). The following outlines six common types of penetration tests, detailing their technical focus and objectives.

**Network Penetration Testing** 

This test targets an organization's network infrastructure, assessing both perimeter and internal defenses. The methodology involves reconnaissance, service enumeration, vulnerability scanning, and exploitation of identified weaknesses in network devices (routers, switches), servers, and network services. Testers aim to bypass security controls like firewalls and Intrusion Prevention Systems (IPS), often using techniques like protocol manipulation and credential brute-forcing. The goal is to map attack paths, demonstrate lateral movement potential, and identify misconfigurations that could lead to a full network compromise.

**Wireless Network Penetration Testing**  

This assessment focuses on the security of an organization's radio frequency (RF) communications. It involves enumerating all wireless SSIDs, testing the strength of encryption protocols (e.g., WPA2-Enterprise, WPA3), and attempting to exploit weaknesses in authentication mechanisms like 802.1X. The scope extends beyond corporate Wi-Fi to include guest networks, Bluetooth Low Energy (BLE) devices, and Zigbee systems, identifying if they can be used as a vector to gain a foothold on the wired network.

**Website/Web Application Penetration Testing**  

This is a code-level assessment of web applications and the services they depend on. It involves manually probing for the OWASP Top Ten vulnerabilities, including injection flaws (SQLi, OS command injection), broken access controls, and security misconfigurations. Testers analyze the application's logic, input validation, session management, and backend API interactions to find vulnerabilities that automated scanners might miss, providing a realistic view of the application's resilience to targeted attack.

**Physical Penetration Testing**  

This assessment evaluates the effectiveness of physical security controls as a barrier to digital assets. Testers use lock picking, tailgating, badge cloning, and other pretexting techniques to bypass physical barriers and gain access to secure areas. The objective is often to connect a rogue device to the internal network, access unattended workstations, or exfiltrate physical hardware, demonstrating the direct impact of a physical breach on information security.

**Social Engineering Penetration Testing**  

This test quantitatively assesses the human layer of security by simulating real-world attack techniques. Technical execution includes crafting and deploying targeted phishing campaigns with malicious payloads or credential harvesters, conducting vishing (voice phishing) calls to extract sensitive information, and testing physical pretexting. The results measure the organization's susceptibility to manipulation and the effectiveness of its security awareness training in a controlled, measurable way.

**Cloud Penetration Testing**  

This specialized assessment targets cloud-specific infrastructure and services (IaaS, PaaS, SaaS). The focus is on identifying misconfigurations in services like S3 buckets, IAM roles and policies, serverless functions, and cloud management consoles. Testing must be conducted within the scope of the cloud provider's shared responsibility model and specific compliance requirements (e.g., AWS Customer Penetration Testing Policy). The goal is to prevent data exposure and resource hijacking resulting from improper cloud configuration.

### Black box penetration testing and white box penetration testing

White box and black box penetration testing are two fundamental approaches to security assessments, differing in the level of knowledge and access given to the testers. Broadly, white box penetration testing and black box penetration testing simulate an insider's and an outsider's attack types, respectively. Based on the type of auditing required, there are two main penetration testing types. In black box testing, the penetration tester has no prior knowledge of a company’s network, more closely resembling remote attacks. In white box testing, the penetration tester typically has complete access to information about the application or system he is attacking, that is, complete knowledge of the network. White box testing represents a worst-case scenario where the attacker has a complete knowledge of the network.

White box penetration testing, also referred to as "clear box" or "full knowledge" testing, is a security assessment where the tester is granted full access to the target system's internal information. This includes source code, architecture diagrams, network configurations, and even credentials. With this level of transparency, the primary advantage is the ability to conduct a more thorough examination, uncovering logic flaws, complex misconfigurations, and hidden vulnerabilities that other methods might miss. Because testers do not need to spend time on reconnaissance, the process is also significantly faster. However, this approach is less realistic, as real-world attackers typically do not start with such extensive internal knowledge. Consequently, it is ideally suited for secure code reviews, testing internal applications before release, and meeting specific compliance audit requirements like those for PCI DSS.

In contrast, black box penetration testing operates on a "zero knowledge" premise, where the tester begins with no prior understanding of the system's internal workings, simulating the perspective of an external attacker. This method is highly valued for its realism, as it directly mimics the threats an organization faces from the outside. The process tests the effectiveness of external-facing defenses such as firewalls, web applications, and APIs, and is particularly effective at uncovering issues like information leakage, weak authentication mechanisms, and exposed services. The main drawback is that it can be time-consuming, as a significant portion of the engagement is dedicated to reconnaissance and fingerprinting. Furthermore, it may miss deeper internal flaws, such as business logic errors, that are not accessible from an unprivileged viewpoint. Common use cases include external network penetration tests, red team engagements, and bug bounty programs, where ethical hackers often operate with limited information.

Bridging the gap between these two methodologies is grey box penetration testing, a hybrid approach where the tester is provided with partial knowledge of the system. This often includes low-privilege user account credentials or limited documentation. By providing this contextual information, grey box testing strikes a balance between the speed and depth of white box testing and the realism of the black box approach. It allows testers to bypass the initial reconnaissance phase and focus their efforts more efficiently, while still simulating an attack vector that could come from a compromised user account or an insider threat. This balanced nature makes it a common and practical choice for internal penetration tests and for organizations seeking a comprehensive yet efficient security assessment that aligns well with various compliance frameworks.

**Comparison Table**

| Feature       | White Box                                     | Black Box                                  | grey Box                        |
| ------------- | --------------------------------------------- | ------------------------------------------ | ------------------------------- |
| **Knowledge** | Full                                          | None                                       | Partial                         |
| **Speed**     | Fast                                          | Slow                                       | Moderate                        |
| **Realism**   | Low                                           | High                                       | Medium                          |
| **Best For**  | Code review, pre-release audits, blue teaming | External security assessments, red teaming | A balanced approach, compliance |

#### Testing from an outsider vs insider perspective: A historical emphasis

There are several kinds of testing—each of which can be performed from an outsider or insider perspective (Palmer, 2001, pp. 777-778):

* Remote network. This test simulates the intruder launching an attack across the Internet. The primary defenses that must be defeated here are border firewalls, filtering routers, and Web servers.
* Remote dial-up network. This test simulates the intruder launching an attack against the client’s modem pools. The primary defenses that must be defeated here are user authentication schemes. These kinds of tests should be coordinated with the local telephone company. 
* Local network. This test simulates an employee or other authorized person who has a legal connection to the organization’s network. The primary defenses that must be defeated here are intranet firewalls, internal Web servers, server security measures, and e-mail systems.
* Stolen laptop computer. In this test, the laptop computer of a key employee, such as an upper-level manager or strategist, is taken by the client without warning and given to the ethical hackers.
* Social engineering. This test evaluates the target organization’s staff as to whether it would leak information to someone. A typical example of this would be an intruder calling the organization’s computer help line and asking for the external telephone numbers of the modem pool. Defending against this kind of attack is the hardest, because people and personalities are involved. Most people are basically helpful, so it seems harmless to tell someone who appears to be lost where the computer room is located, or to let someone into the building who “forgot” his or her badge. The only defense against this is to raise security awareness.
* Physical entry. This test acts out a physical penetration of the organization's building.

#### Testing from an outsider vs insider perspective: A modern emphasis

The classification of penetration tests by entry point as noted by Palmer (2001) remains a useful way to scope assessments. However, the specific attack vectors have evolved with technology. Modern tests can be categorized from both outsider (no initial access) and insider (some level of initial access) perspectives:

- External network testing: This simulates an attacker from the internet targeting an organization's public-facing presence. The scope has expanded from just border firewalls and web servers to include cloud workloads, APIs, and misconfigured public cloud storage (e.g., S3 buckets). The goal is to breach the external perimeter and gain an initial foothold.
- Internal network testing: This simulates an attack from inside the network, such as from a compromised employee device or a malicious insider. In a modern context, this tests the principles of Zero-Trust architecture. The objective is to defeat internal segmentation, lateral movement controls, and privilege escalation mechanisms to access critical data and systems.
- Physical and social engineering: These tests evaluate the human and physical security layers.
    - Social engineering remains a highly effective vector, now conducted through phishing emails, vishing (voice phishing), and SMS phishing (smishing) to steal credentials or deploy malware.
    - Physical entry tests the security of offices, data centers, and other facilities, attempting to gain unauthorized access to connect devices to the internal network or steal equipment.
- Modern "stolen asset" scenarios: This category has evolved beyond a single laptop. It now includes testing the security of mobile devices (BYOD), tablets, and the data accessible from them, often through cloud synchronization (e.g., OneDrive, Google Drive). The test focuses on disk encryption, biometric bypasses, cached credentials, and the ability to remotely wipe the device.
- Wireless and IoT testing: A modern addition, this assesses the security of Wi-Fi networks (corporate and guest), Bluetooth implementations, and Internet of Things (IoT) devices that could serve as a pivot point into the core network.

The following table summarizes the evolution from the 2001 concepts to their modern equivalents, highlighting the key shifts in emphasis. A modern framework should incorporate the complex, cloud-centric, and API-driven nature of today's digital environments. 

**Evolution of Penetration Testing Vectors: From 2001 to Modern Day**

|Palmer (2001) Concept|Modern Equivalent / Updated Emphasis|Rationale for the Shift|
|---|---|---|
|**Remote Network**|**External Network Testing**|The focus has expanded from simple "border firewalls" and web servers to include **cloud workloads, APIs, serverless functions, and misconfigured public cloud storage.** The perimeter is no longer a single, defined boundary.|
|**Remote Dial-Up Network**|**(Largely Deprecated)**|Modem pools are an obsolete attack vector for most organizations. The resources are better allocated to testing more prevalent external threats.|
|**Local Network**|**Internal Network Testing & Zero-Trust Validation**|The core concept remains, but the context has shifted. The test now evaluates how well an organization implements **Zero-Trust principles** (e.g., micro-segmentation, lateral movement controls) after an initial breach.|
|**Stolen Laptop Computer**|**Endpoint & Mobile Device Compromise**|The scenario is broader than a single physical theft. It now emphasizes **mobile device management (MDM) security, disk encryption, cloud-synced data theft, and credential caching** on a wide range of corporate and BYOD devices.|
|**Social Engineering**|**Social Engineering & Phishing Campaigns**|The human element is constant, but the primary methods have moved from phone calls (**vishing**) to large-scale, automated **phishing, smishing (SMS), and sophisticated spear-phishing** campaigns.|
|**Physical Entry**|**Physical Entry & Security Bypass**|This remains highly relevant, especially for red team engagements. The goals are unchanged: to access secure areas, plant devices, or connect to the internal network.|
|_(Not explicitly covered)_|**Wireless & IoT Testing**|A critical modern addition. This involves assessing the security of **Wi-Fi networks (corporate/guest), Bluetooth, and IoT devices** that create a large, often insecure, attack surface.|
|_(Not explicitly covered)_|**API Security Testing**|APIs are the core of modern web and mobile applications. They represent a massive and critical attack surface that did not have the same prominence in 2001 and now requires dedicated testing.|

### Risks of penetration testing

Penetration testing involves “launching real attacks on real systems and data using tools and techniques commonly used by hackers” (NIST SP 800-115, p. 5-2). While invaluable for security, performing real attacks on live systems carries inherent risks that must be carefully weighed against the intended benefits.

Performing real attacks on real systems carries a risk that must be weighed carefully against the intended benefits. It must be justified on a cost-benefit basis by a security analyst with broad and interdisciplinary knowledge about the social threat landscape, human behavior, sociopolitical conflicts, in addition to the technical knowledge. 

**These risks can be broadly categorized into operational and data-related impacts.** The primary operational risks include "alarmed staff and unintentional system crashes, degraded network or system performance, denial of service, and log-file size explosions" (Palmer, 2001, p. 776). **Furthermore,** penetration testing can directly compromise data integrity or availability through accidental damage, or breach confidentiality simply because the tester sees sensitive information during the assessment.
Penetration testing can compromise data integrity or availability (accidental damage) or confidentiality (the penetration tester sees confidential information just by virtue of performing the test).

**Given these potential side effects, the approach to testing must be carefully negotiated.** The most thorough evaluation is done under a “no-holds-barred” approach, where the ethical hacker can try any conceivable technique to gain access. **However, this level of aggression is often tempered by operational constraints.** Clients may balk at this approach because target systems are “in production,” and interference could damage the organization’s interests (Palmer, 2001, pp. 775-776). **Consequently,** the risk of serious side effects directly informs which specific tests are approved and how they are executed on a live system.

**Beyond technical disruptions, there are also strategic security risks to consider.** Once the contractual agreement is in place and testing begins, a criminal hacker monitoring the network transmissions of the ethical hackers could learn the same information. If a weakness is identified, a malicious actor could attempt to exploit it simultaneously, with the ethical hackers' activities potentially masking the attack. **To mitigate this,**  
ethical hackers maintain logs and may use a variety of source addresses. In extreme cases, additional intrusion monitoring can be deployed to ensure all activity originates from the testers' machines (Palmer, 2001, p. 777).

**Ultimately, due to these potential side effects, penetration testing is often a scheduled activity** that focuses on specific aspects of the infrastructure rather than being an ongoing process. The tester's access is typically limited to defined systems and a specific duration to control the risk exposure. A security analyst must justify the exercise on a cost-benefit basis, requiring broad interdisciplinary knowledge to navigate these risks effectively.

--
The best evaluation is done under a “no-holds-barred” approach. This means that the ethical hacker can try anything he or she can think of to attempt to gain access to or disrupt the target system. While this is the most realistic and useful, some clients balk at this level of testing. Clients have several reasons for this, the most common of which is that the target systems are “in production” and interference with their operation could be damaging to the organization’s interests. (Palmer, 2001, pp. 775-776)

The risk of serious side effects from performing penetration testing will inform the specific tests to be made and how on a live system. 

Once the contractual agreement is in place, the testing may begin as defined in the agreement. It should be noted that the testing itself poses some risk to the client, since a criminal hacker monitoring the transmissions of the ethical hackers could learn the same information. If the ethical hackers identify a weakness in the client’s security, the criminal hacker could potentially attempt to exploit that vulnerability. This is especially vexing since the activities of the ethical hackers might mask those of the criminal hackers. The best approach to this dilemma is to maintain several addresses around the Internet from which the ethical hacker’s transmissions will emanate, and to switch origin addresses often. Complete logs of the tests performed by the ethical hackers are always maintained, both for the final report and in the event that something unusual occurs. In extreme cases, additional intrusion monitoring software can be deployed at the target to ensure that all the tests are coming from the ethical hacker’s machines. (Palmer, 2001, p. 777)

The technical risks of penetration testing on computer systems to an organization include damaging the system infrastructure or data assets, or exposing confidential information, downtime, and exploits may remain in the system. Given the potential side effects of penetration testing, the work of penetration testers is often conducted on a defined schedule and focuses on specific aspects of a network or computer infrastructure rather than being an ongoing overall security. The penetration tester may have only limited access to the system that is subject to testing and only for the duration of the testing.

### Key takeaways

* Types of penetration testing include network, wireless, web application, physical, social engineering, and cloud.
* Black box penetration testing and white box penetration testing methods broadly simulate an insider's and outsider's attack types.
* Organizations must weigh potential benefits vs possible risks when deciding the details of the penetration test.

### References

Cipher. (n.d.). The types of pentests you must know about. Retrieved January 21, 2020, from https://cipher.com/blog/the-types-of-pentests-you-must-know-about/

Palmer, C. C. (2001). Ethical hacking. _IBM Systems Journal, 40_(3), 769-780.
