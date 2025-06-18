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
  * **Denial of service (DoS) attacks**
  * **Reflection and amplification attacks**
  * **Man in the middle (MITM) attacks**
  * **Spoofing attacks**
* **Malware types**
  * **Viruses and worms**
  * **Ransomeware**
  * **Spyware**

### Common cyber attacks

#### Reconnaissance

#### Social engineering

#### Password attacks

#### Denial of service (DoS) attacks

DoS and DDoS attacks threaten the availability of a system.

There are many types of DoS attacks, such as TCP SYN flood, UDP flood, HTTP flood, Ping of death, and DHCP starvation attack. **Mitigation**: Network segmentation.

TCP SYN flood (IP spoofing attack).

DHCP exhaustion attack (MAC address spoofing). **Mitigation**: DHCP snooping, Switch Port Security.

• The TCP SYN flood is a common type of DoS attack (often directed against ISPs) which exploits the TCP three-way handshake process used by TCP connections. The attacker likely spoofs their IP address, meaning the attacker uses a fake IP address, making this a spoofing attack. By spoofing the source IP address in the SYN, the malicious client causes the server to send the SYN-ACK to a falsified IP address – which will not send an ACK because it knows that it never sent a SYN. Or the malicious client can simply not send the expected ACK.

For mitigation of TCP SYN flood attacks, you'd need techniques that focus on managing the connection setup process itself. A layered approach combining these methods is most effective in mitigating TCP SYN flood attacks. Here are some common mitigation methods:

1. Rate limiting: This limits the number of incoming SYN requests to a manageable rate, preventing the attacker from overwhelming your system.
2. SYN cookies: This is a technique where the server generates a temporary challenge instead of allocating resources for a full connection handshake in case of a suspected SYN flood.
3. Firewalls and Intrusion Prevention Systems (IPS): These can be configured to identify and block suspicious SYN flood traffic patterns.

• UDP flood: UDP floods simply bombard the target with UDP packets, consuming bandwidth and making it difficult for legitimate traffic to get through.

• HTTP flood: This attack targets web servers by sending a huge number of HTTP requests, overloading the server's capacity to process them.

• Ping of death: This attack sends a malformed packet that's larger than the intended size, causing the target system to crash or reboot.

• DHCP exhaustion attack, also known as a DHCP starvation attack, is similar to the TCP SYN flood attack. An attacker uses spoofed MAC addresses to flood a DHCP server with DHCP Discover messages. Attackers send DHCP Discover messages with fake source MAC addresses at a very quick pace. The target server’s DHCP pool becomes full, resulting in a denial-of-service to other devices which are no longer able to get an IP address.

#### Reflection and amplification attacks

In a reflection attack, the attacker sends traffic to a reflector such as a DNS server and spoofs the source address of the sent packets using the target’s IP address. Then the reflector sends the reply to the target’s IP address. If the amount of traffic is large enough this can result in a DoS to the target.&#x20;

#### Man in the middle (MITM) attacks

DHCP poisoning: In this attack a malicious device impersonates a legitimate DHCP server and offers IP addresses to clients. Once a client accepts the attacker's offer, their communication gets routed through the attacker's device, allowing them to potentially eavesdrop on traffic, steal data, redirect the user to malicious websites, or tamper with (damage) or alter the captured traffic. Mitigation: DHCP snooping.

A spurious DHCP server and a malicious MITM < DHCP snooping configuration and verification

[https://itnetworkingskills.wordpress.com/2023/05/14/dhcp-snooping-configuration-verification/](https://itnetworkingskills.wordpress.com/2023/05/14/dhcp-snooping-configuration-verification/)

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

Other:

TCP/IP Hijacking: Attackers can intercept ongoing TCP connections and take control of the session, potentially leading to unauthorized data access or manipulation.

Session Hijacking: Attackers can take over an existing session, posing as legitimate users and potentially gaining unauthorized access to sensitive data.

### Malware types

Malware, malicious software, refers to a variety of harmful programs that can infect a computer. There are many types of malware. Here are a few types.

### Key takeaways

• Point 1\
• Point 2\
• Point 3 \
• Point 4 &#x20;

### References

Odom, W. (2020). CCNA 200-301 Official Cert Guide, Volume 2. Cisco Press.

Odom, W. (2020). Chapter 4. Security Architectures, CCNA 200-301 Official Cert Guide (pp. 68-85), Volume 2. Cisco Press.

Two types of attacks DHCP snooping can help defeat (spoofing attacks)

[https://docs.google.com/document/d/e/2PACX-1vSl\_p7eJbMA3IupZVa4GhGdLukXcU1b\_uIfTA1LndgIoCQEP7OTULScySTh8LWmIBNe-8F-5xo1GPET/pub](https://docs.google.com/document/d/e/2PACX-1vSl_p7eJbMA3IupZVa4GhGdLukXcU1b_uIfTA1LndgIoCQEP7OTULScySTh8LWmIBNe-8F-5xo1GPET/pub)
