---
description: This section explores common cyber attacks and malware types
---

# Common cyber attacks

Learning objectives

• Point 1\
• Point 2 \
• Point 3\
• Point 4 \
• Point 5

This section looks at common cyber attacks (DoS, spoofing, reflection/amplification, MITM, reconnaissance, social engineering, and password attacks) and malware types (viruses, worms, ransomware, spyware).

## Topics covered in this section

* **Common cyber attacks**
  * **Reconnaissance**
  * **Social engineering**
  * **Password attacks**
  * **Denial of service (DoS)**
  * **Reflection and amplification**
  * **Man in the middle (MITM)**
  * **Spoofing attacks**
* **Malware types**
  * **Viruses and worms**
  * **Ransomeware**
  * **Spyware**

### Common cyber attacks

Attack types are threats which can potentially exploit vulnerabilities to compromise the CIA of an enterprise’s information assets and network system. We explore how attackers can threaten the CIA of enterprise systems and information by looking at the following common types of attacks: Reconnaissance, social engineering, password attacks, denial of service (DoS), reflection and amplification, MITM, and spoofing attacks. There are many more potential attacks than these, but these are some of the main attack categories.

#### Reconnaissance

Reconnaissance “attacks” are used to gather information about a target. The information gathered in the initial stage at least is often publicly available information.

For example, you can perform an NSLOOKUP to learn the IP address of a site. From there, you can probe for open ports which are potential vulnerabilities. You could also perform a WHOIS query to learn email addresses, phone numbers, physical addresses, etc. at this website: https://lookup.icann.org/en

The information gathered in this stage can be used to launch a targeted social engineering attack.

#### Social engineering

Social engineering attacks do not directly exploit a company’s IT systems, instead they exploit the employees. No matter how many security features you configure on your routers, switches, firewalls, servers, PCs, etc., people are always a vulnerability that can be exploited.

Social engineering attacks involve psychological manipulation to make the target reveal confidential information or perform some action the attacker wants the target to do. As with the previous attack types, there are various kinds of social engineering attacks. Here are a few common ones.

\*Phishing involves fraudulent emails that appear to come from a legitimate business, such as your bank or your credit card company. These emails contain links to a fraudulent website that seems legitimate. The website may look identical to the real login page of your bank’s website, for example. Users are told to login to the fake website, therefore providing their login credentials to the attacker.

Spear phishing is a type of phishing that is more targeted. This can take the form of personalized emails sent to employees of a specific company.

Whaling is another kind of phishing targeted at high-profile individuals, for example a company president.

Vishing, voice phishing, is phishing performed over the phone. The attacker could pretend to be from the target’s bank or from the IT department in the company. For example, an attacker may impersonate an IT department employee who says they need to know the password to reset it.

Mishing, SMS phishing, which is phishing performed using SMS text messages to the target’s cell phone.

\*Watering hole attacks compromise sites that the target victim frequently visits. If a malicious link is placed on a website the target trusts, they might not hesitate to click it. So, this kind of attack is taking advantage of the user’s trust in the website they frequently visit.

\*Tailgating attacks involve entering restricted, secure areas by simply walking in behind an authorized person as they enter. Any company that has restricted areas will have rules against this, but often the target will hold the door open for the attacker to be polite, assuming the attacker is also authorized to enter.

#### Password attacks

Most systems use a username and password combination to authenticate users. The username itself is often simple and easy to guess, for example the user’s email address. So, often, the strength and secrecy of the password is relied on to provide the necessary security.

However, attackers can learn a user’s password through multiple methods.

First, they could guess the password. A dictionary attack can also be used, in which a program runs through a dictionary, which is a list of common words and passwords, to guess the target’s password. The program tries each word, hoping to find the correct password.

A brute force attack involves trying every possible combination of letters, numbers, and special characters to find the target’s password. This requires a very powerful computer, and if the password is sufficiently strong, the chances of it working are very low, because it takes so much time.

A strong password should contain at least 8 characters, preferably more than 8. The more characters, the harder it is to brute force attack the password.

A strong password should have a mix of uppercase and lowercase letters and a mix of letters and numbers.

It should also have one or more special characters such as question marks, exclamation points, etc.

Finally it should be changed regularly.

Most enterprises will enforce rules like these on their employees, but it’s also recommended that you follow rules like these when making your own personal passwords.

#### Denial of service (DoS)

There are many types of DoS attacks, such as TCP SYN flood, UDP flood, HTTP flood, Ping of death, and DHCP starvation attack. DoS and DDoS attacks threaten the availability of information systems. A prime mitigation method for DoS attacks is network segmentation.

**TCP SYN flood**

• The TCP SYN flood is a common type of DoS attack (often directed against ISPs) which exploits the TCP three-way handshake process used by TCP connections. The attacker likely spoofs their IP address, meaning the attacker uses a fake IP address, making this a spoofing attack. By spoofing the source IP address in the SYN, the malicious client causes the server to send the SYN-ACK to a falsified IP address – which will not send an ACK because it knows that it never sent a SYN. Or the malicious client can simply not send the expected ACK.

For mitigation of TCP SYN flood attacks, you would need techniques that focus on managing the connection setup process itself. A layered approach combining these methods is most effective in mitigating TCP SYN flood attacks. Here are some common mitigation methods:

1. Rate limiting: This limits the number of incoming SYN requests to a manageable rate, preventing the attacker from overwhelming your system.
2. SYN cookies: This is a technique where the server generates a temporary challenge instead of allocating resources for a full connection handshake in case of a suspected SYN flood.
3. Firewalls and Intrusion Prevention Systems (IPS): These can be configured to identify and block suspicious SYN flood traffic patterns.

• UDP flood: UDP floods simply bombard the target with UDP packets, consuming bandwidth and making it difficult for legitimate traffic to get through.

• HTTP flood: This attack targets web servers by sending a huge number of HTTP requests, overloading the server's capacity to process them.

• Ping of death: This attack sends a malformed packet that's larger than the intended size, causing the target system to crash or reboot.

**DHCP exhaustion attack**

• DHCP exhaustion attack, also known as a DHCP starvation attack, is similar to the TCP SYN flood attack. An attacker uses spoofed MAC addresses to flood a DHCP server with DHCP Discover messages. Attackers send DHCP Discover messages with fake source MAC addresses at a very quick pace. The target server’s DHCP pool becomes full, resulting in a denial-of-service to other devices which are no longer able to get an IP address.

Mitigation: DHCP snooping, Switch Port Security.

Two types of attacks DHCP snooping can help defeat (spoofing attacks)

[https://docs.google.com/document/d/e/2PACX-1vSl\_p7eJbMA3IupZVa4GhGdLukXcU1b\_uIfTA1LndgIoCQEP7OTULScySTh8LWmIBNe-8F-5xo1GPET/pub](https://docs.google.com/document/d/e/2PACX-1vSl_p7eJbMA3IupZVa4GhGdLukXcU1b_uIfTA1LndgIoCQEP7OTULScySTh8LWmIBNe-8F-5xo1GPET/pub)

#### Reflection and amplification

In a reflection attack, the attacker sends traffic to a reflector such as a DNS server and spoofs the source address of the sent packets using the target’s IP address. Then the reflector sends the reply to the target’s IP address. If the amount of traffic is large enough this can result in a DoS to the target.&#x20;

#### Man in the middle (MITM)&#x20;

DHCP poisoning: In this attack a malicious device impersonates a legitimate DHCP server and offers IP addresses to clients. Once a client accepts the attacker's offer, their communication gets routed through the attacker's device, allowing them to potentially eavesdrop on traffic, steal data, redirect the user to malicious websites, or tamper with (damage) or alter the captured traffic. Mitigation: DHCP snooping.

A spurious DHCP server and a malicious MITM < DHCP snooping configuration and verification

[https://itnetworkingskills.wordpress.com/2023/05/14/dhcp-snooping-configuration-verification/](https://itnetworkingskills.wordpress.com/2023/05/14/dhcp-snooping-configuration-verification/)

Two types of attacks DHCP snooping can help defeat (spoofing attacks)

[https://docs.google.com/document/d/e/2PACX-1vSl\_p7eJbMA3IupZVa4GhGdLukXcU1b\_uIfTA1LndgIoCQEP7OTULScySTh8LWmIBNe-8F-5xo1GPET/pub](https://docs.google.com/document/d/e/2PACX-1vSl_p7eJbMA3IupZVa4GhGdLukXcU1b_uIfTA1LndgIoCQEP7OTULScySTh8LWmIBNe-8F-5xo1GPET/pub)

ARP spoofing, also known as ARP poisoning: A MITM attack that allows attackers to intercept communication between network devices. The attacker spoofs the MAC address of the target device as their own (using **gratuitous ARP**) to direct traffic to himself. Alternatively, you can say the attacker spoofs the source IP address of the target device as their own (impersonates a legitimate IP address such as a router’s IP). Mitigation: DAI.

Man in the middle attacks < CCNA security fundamentals

[https://itnetworkingskills.wordpress.com/2023/05/06/ccna-security-fundamentals/](https://itnetworkingskills.wordpress.com/2023/05/06/ccna-security-fundamentals/)

DAI configuration and verification

[https://itnetworkingskills.wordpress.com/2023/05/16/dynamic-arp-inspection-configuration-and-verification/](https://itnetworkingskills.wordpress.com/2023/05/16/dynamic-arp-inspection-configuration-and-verification/)

#### Spoofing attacks

Denial-of-Service Attacks\
Reflection and Amplification Attacks\
Man-in-the-Middle Attacks

\*IP spoofing

IP Spoofing: Attackers can manipulate IP addresses to deceive network routers and gain unauthorized access to networks.

TCP SYN flood (IP spoofing attack)

Reflection and amplification attacks

DHCP poisoning/MITM

ARP spoofing, also known as ARP poisoning

\*MAC spoofing

DHCP exhaustion attack (MAC address spoofing). Mitigation: DHCP snooping, Switch Port Security.

Other:&#x20;

TCP/IP Hijacking: Attackers can intercept ongoing TCP connections and take control of the session, potentially leading to unauthorized data access or manipulation.

Session Hijacking: Attackers can take over an existing session, posing as legitimate users and potentially gaining unauthorized access to sensitive data.

### Malware types

Malware, malicious software, refers to a variety of harmful programs that can infect a computer. There are many types of malware. Here are a few types.

\*Viruses are malware that infects other software, called a host program. The virus spreads as the software is shared by users or downloaded from malicious websites. Once the virus has infected a device it can corrupt or modify files on the target computer.

\*Worms are different from viruses in that they don’t require a host program. They are standalone malware and are also able to spread on their own, without user interaction. The spread of worms from device to device can congest the network, but in addition to that if the worm has a payload, other malicious code within the worm, it can cause additional harm to target devices.

\*A Trojan horse is harmful software disguised as legitimate software. Trojan horses spread through user interaction such as opening email attachments or downloading a file from the Internet.

These types of malware are defined by how the malware infects a system and how it spreads, not the attacks they carry out after infecting the system.

The above malware types can exploit various vulnerabilities to threaten any of the CIA triad aspects of the target device.

### Key takeaways

• Point 1\
• Point 2\
• Point 3 \
• Point 4 &#x20;

### References

Odom, W. (2020). CCNA 200-301 Official Cert Guide, Volume 2. Cisco Press.

Odom, W. (2020). Chapter 4. Security Architectures, CCNA 200-301 Official Cert Guide (pp. 68-85), Volume 2. Cisco Press.
