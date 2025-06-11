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

Common cyber attacks (DoS, spoofing, reflection/amplification, MITM, reconnaissance, social engineering, and password attacks) and malware types (viruses, worms, ransomware, spyware).

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

There are many types of DoS attacks, such as TCP SYN flood, UDP flood, HTTP flood, Ping of death, and DHCP starvation attack. Mitigation: Network segmentation.

TCP SYN flood (IP spoofing attack).

DHCP exhaustion attack (MAC address spoofing). Mitigation: DHCP snooping, Switch Port Security.

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

**\*IP spoofing**

IP Spoofing: Attackers can manipulate IP addresses to deceive network routers and gain unauthorized access to networks.

TCP SYN flood (IP spoofing attack)

Reflection and amplification attacks

DHCP poisoning/MITM

ARP spoofing, also known as ARP poisoning

**\*MAC spoofing**

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
