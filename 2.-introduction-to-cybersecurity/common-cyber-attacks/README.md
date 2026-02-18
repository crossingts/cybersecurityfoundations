---
description: This section explores common cyber attacks and malware types
---

# Common cyber attacks

## Learning objectives

* Become familiar with common cyber attacks
* Become familiar with common malware types

This section looks at common cyber attacks (reconnaissance, social engineering, password attacks, DoS, reflection and amplification, MITM, and spoofing) and malware types (viruses, worms, and ransomware).

This section explores common methods and mechanisms used by adversaries to compromise the CIA (Confidentiality, Integrity, and Availability) of information systems. It begins by examining the attacker's kill chain, starting with reconnaissance, the vital information gathering phase that enables more precise and targeted strikes. From there, the discussion moves to social engineering, which bypasses technical defenses by targeting the human element, and then to direct technical assaults like password attacks and various forms of denial of service (DoS). The section will detail how attackers can amplify the power of DoS through reflection and amplification techniques, and how they can position themselves to intercept or alter communications using man-in-the-middle (MITM) attacks. A recurring theme across many of these threats is the use of spoofing, where an attacker falsifies data—such as an IP or MAC address—to conceal their identity or impersonate a trusted entity. Finally, the section shifts from active network attacks to the malicious software itself, providing an overview of common malware types, including how viruses and worms propagate, and the destructive impact of ransomware.

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

### Common cyber attacks

This discussion explores how attackers can compromise the CIA (Confidentiality, Integrity, and Availability) of an enterprise's information assets through a range of cyber attack methods: reconnaissance, social engineering, password attacks, denial of service (DoS), reflection and amplification, MITM (Man-in-the-Middle), and spoofing attacks.

#### Reconnaissance

Reconnaissance, often the first phase of the cyber kill chain, is the process of an attacker gathering as much information as possible about a target to identify potential vulnerabilities and plan an attack strategy. This initial stage is not an attack in the traditional sense, as it rarely involves direct interaction with the target’s production systems, but it is a critical enabler for all subsequent hacking activity. The information gathered can be broadly categorized into two types: passive and active reconnaissance. Passive reconnaissance involves collecting data without directly engaging with the target, often leveraging publicly available sources, a practice known as OSINT (Open-Source Intelligence). For instance, an attacker might perform a WHOIS query through services like ICANN Lookup to uncover administrative contacts, name servers, and registered IP addresses associated with a domain. Tools like `nslookup` or `dig` can be used to map out a target’s mail exchangers (MX records) and other key infrastructure, while search engines and even social media can yield valuable insights into an organization's technology stack, partnerships, and employee details, all of which can fuel a highly targeted social engineering campaign.

Active reconnaissance, in contrast, involves direct engagement with the target's systems to probe for weaknesses, a process that is far more likely to trigger detection systems like Intrusion Detection/Prevention Systems (IDS/IPS). A primary technique in this phase is port scanning, often performed with tools like Nmap, to discover live hosts and enumerate open ports and services. An attacker is not just looking for open ports, but for the specific service versions running on them (e.g., Apache 2.4.49 vs. nginx 1.18.0), as this fingerprinting allows them to query a database of known vulnerabilities (CVEs) for an easy exploit. Furthermore, techniques like banner grabbing can reveal detailed software information, and OS fingerprinting can determine the underlying operating system of a target host. The cumulative knowledge from active reconnaissance—from identifying a vulnerable service on a seldom-monitored port to confirming a target's operating system—provides the attacker with a precise blueprint for crafting the next, more destructive phases of their operation.

#### Social engineering

Social engineering attacks do not directly exploit a company’s IT systems, instead they exploit people's propensity to trust others. No matter how many security features you configure on your routers, switches, firewalls, servers, PCs, etc., people are always a vulnerability that can be exploited.

Social engineering attacks involve psychological manipulation to make the target reveal confidential information or perform some action the attacker wants the target to do. As with other attack types, there are various kinds of social engineering attacks. Here are a few common ones.

**Phishing**

Phishing involves fraudulent emails that appear to come from a legitimate business, such as your bank or your credit card company. These emails contain links to a fraudulent website that seems legitimate. The website may look identical to the real login page of your bank’s website, for example. Users are told to login to the fake website, therefore providing their login credentials to the attacker.

**Spear phishing** is a type of phishing that is more targeted. This can take the form of personalized emails sent to employees of a specific company. **Whaling** is another kind of phishing targeted at high-profile individuals, for example a company president. **Vishing**, voice phishing, is phishing performed over the phone. The attacker could pretend to be from the target’s bank or from the IT department in the company. For example, an attacker may impersonate an IT department employee who says they need to know the password to reset it. **Mishing**, SMS phishing, is phishing performed using SMS text messages to the target’s cell phone.

**Watering Hole**

Watering hole attacks compromise sites that the target frequently visits. If a malicious link is placed on a website the target trusts, they might not hesitate to click it. So, this kind of attack is taking advantage of the user’s trust in the website they frequently visit.

**Tailgating**

Tailgating attacks involve entering restricted, secure areas by simply walking in behind an authorized person as they enter. Any company that has restricted areas will have rules against this, but often the target will hold the door open for the attacker to be polite, assuming the attacker is also authorized to enter.

#### Password attacks

Most systems use a username and password combination to authenticate users. The username itself is often simple and easy to guess, for example the user’s email address. So, often the strength and secrecy of the password is relied on to provide the necessary security.

However, attackers can learn a user’s password through multiple methods. They could guess the password. A dictionary attack can be used, in which a program runs through a dictionary, which is a list of common words and passwords, to guess the target’s password. The program tries each word, hoping to find the correct password. A brute force attack involves trying every possible combination of letters, numbers, and special characters to find the target’s password. This requires a very powerful computer, and if the password is sufficiently strong, the chances of it working are very low, because it takes so much time.

A strong password should contain at least 8 characters, preferably more than 8. The more characters, the harder it is to brute force attack the password. A strong password should have a mix of uppercase and lowercase letters and a mix of letters and numbers. It should also have one or more special characters such as question marks, exclamation points, etc. Finally it should be changed regularly.

Most enterprises will enforce rules like these on their employees, but it’s also recommended that you follow rules like these when making your own personal passwords.

#### Denial of service (DoS)

There are many types of DoS attacks, such as TCP SYN flooding, DHCP exhaustion attack, UDP flooding, HTTP flooding, and Ping of death. DoS and DDoS attacks threaten the availability of information. Mitigating DoS and DDoS attacks requires a defense-in-depth strategy combining host-based protections, network-level filters, dedicated appliances, and often cloud-based scrubbing services.

**TCP SYN Flooding**

The TCP SYN flood is a common type of DoS attack (often directed against ISPs) which exploits the TCP three-way handshake process used by TCP connections. The three-way handshake is SYN, SYN-ACK, and ACK. The attacker sends a large number of SYN packets to a target server. The target server sends a SYN-ACK message in response to each SYN it receives. But the attacker never replies with the final ACK of the handshake.

<figure><img src="../../.gitbook/assets/image (17).png" alt="TCP SYN flood"><figcaption><p>The TCP SYN flood attack</p></figcaption></figure>

The attacker likely spoofs their source IP address, making this a spoofing attack. By spoofing the source IP address in the SYN message, the malicious client causes the server to send the SYN-ACK to a falsified IP address – which will not send an ACK because it knows that it never sent a SYN. Or the malicious client can simply not send the expected ACK.

The target waits for the final ACK of each handshake, and the incomplete connections fill up the target’s TCP connection table. The incomplete connections will timeout and be removed from the table after a certain period of time, but the attacker continues sending SYN messages and the target keeps sending SYN-ACK messages. 

```mermaid
sequenceDiagram
    participant Attacker
    participant Target Server
    participant Legitimate Client

    Note over Attacker, Target Server: Phase 1: Attack Setup
    Attacker->>Target Server: SYN Packet (spoofed source IP)
    Target Server->>Nowhere: SYN-ACK Packet (to non-existent IP)
    Note right of Target Server: Half-open connection created<br/>Waits for final ACK

    Note over Attacker, Target Server: Phase 2: Flood Attack
    loop Continuous SYN Flood
        Attacker->>Target Server: Multiple SYN Packets<br/>(different spoofed IPs)
        Target Server->>Nowhere: SYN-ACK Responses<br/>(to non-existent hosts)
        Note right of Target Server: Connection queue fills up<br/>Memory resources exhausted
    end

    Note over Attacker, Target Server: Phase 3: Service Denial
    Legitimate Client->>Target Server: Legitimate SYN Request
    Target Server-->>Legitimate Client: No response or timeout
    Note right of Target Server: Server cannot accept<br/>new legitimate connections

    Note over Target Server: Server State: Overwhelmed<br/>- Connection queue full<br/>- Memory exhausted<br/>- CPU overloaded<br/>- Legitimate traffic blocked
```

Eventually, the target’s TCP connection table fills up - it is no longer able to make legitimate TCP connections because it has reached the maximum number of TCP connections it can maintain. The exhaustion of the server’s resources prevents legitimate users from accessing it. Denial-of-service has been achieved.

A much more powerful version of this attack type is the distributed denial-of-service (DDoS) attack. In a DDoS attack, the attacker infects many target computers with malware and uses the computers to initiate a DoS attack such as a TCP SYN flood attack. The group of infected computers is called a botnet. The PCs infected with malware together start flooding the target with SYN messages, so the target server is no longer able to respond to legitimate TCP connection requests.

Mitigating TCP SYN flooding attacks requires a layered approach. Modern systems rely heavily on SYN cookies—enabled by default in major operating systems—as the critical first line of defense, complemented by rate limiting, firewall policies, and scalable offloading techniques. Here is an outline of the key technical mitigation methods used at each layer:

1. **Operating System Hardening**

    - **SYN Cookies:** Stateless encoding of connection information in the sequence number; no backlog entry until the final ACK is received (Linux: `net.ipv4.tcp_syncookies=1`; Windows: default from Vista/2008).
    - **Increase SYN Backlog:** Expands the queue for half-open connections (`tcp_max_syn_backlog`).
    - **Reduce Retries/Timeouts:** Shortens SYN-ACK retries (`tcp_synack_retries=1`) and wait times (Cisco: `ip tcp synwait-time`).

2. **Network-Layer Filtering & Rate Limiting**
    
    - **Rate Limiting:** Controls the volume of incoming SYNs per source or aggregate using policing (Cisco MQC, CoPP) or ACLs.
    - **Firewall/IPS Policies:** Identifies abnormal SYN patterns and drops malicious traffic.
    - **Ingress Filtering (uRPF):** Blocks spoofed source IPs at the edge (`ip verify unicast source reachable-via rx`).

3. **Proxy-Based Mitigations (Cisco & Firewall)**
    
    - **TCP Intercept:** Router proxies the handshake, validating clients before connecting to the server.
    - **SYN Proxy:** Firewall or load balancer completes the handshake on behalf of the server, forwarding only validated connections.

4. **Scalable & Offloaded Defenses**
    
    - **Dedicated Anti-DDoS Appliances:** Hardware/software (Arbor, Radware) that detect and drop flood traffic behaviorally.
    - **Cloud Scrubbing Services:** Traffic diversion to providers (Cloudflare, AWS Shield, Akamai) for absorption and filtering before reaching the origin.

**DHCP Exhaustion Attack**

Like the TCP SYN flood attack, DHCP exhaustion, also called DHCP starvation, is a resource exhaustion attack. However, instead of consuming connection table entries, it targets a different finite resource: the DHCP server's pool of available IP addresses.

An attacker floods a DHCP server with DHCP Discover messages using spoofed MAC addresses. For each spoofed DHCP Discover message, the server responds with a DHCP Offer, temporarily reserving an IP address from its pool. The server places these addresses in a 'offered' state, awaiting DHCP Request messages that never arrive from the non-existent clients. Over time, the entire address scope becomes reserved for these bogus leases. The depletion of the server's DHCP pool results in a DoS to other devices which are no longer able to get an IP address. 

```mermaid
sequenceDiagram
    participant Legitimate Client
    participant Attacker
    participant DHCP Server
    participant Network Switch

    Note over DHCP Server: Initial State: Healthy DHCP Pool
    Note right of DHCP Server: Available IPs: 250/250

    Legitimate Client->>Network Switch: Legitimate DHCP Discover (Real MAC)
    Network Switch->>DHCP Server: Forward Discover
    DHCP Server->>Legitimate Client: DHCP Offer (IP: 192.168.1.10)
    Legitimate Client->>DHCP Server: DHCP Request
    DHCP Server->>Legitimate Client: DHCP Ack
    Note right of DHCP Server: IP 192.168.1.10 leased<br/>Available IPs: 249/250

    Note over Attacker, DHCP Server: Phase 1: Attack Launch
    loop Flood of Bogus Requests
        Attacker->>Network Switch: DHCP Discover (Spoofed MAC)
        Network Switch->>DHCP Server: Forward Discover
        DHCP Server->>Nowhere: DHCP Offer (to non-existent client)
        Note right of DHCP Server: IP reserved in pool<br/>Available IPs: 248... 200... 100...
    end

    Note over DHCP Server: Phase 2: Pool Exhaustion
    Note right of DHCP Server: ❌ Pool Status: FULL (0/250)<br/>All IPs are reserved for<br/>non-existent clients.

    Note over Legitimate Client, DHCP Server: Phase 3: Service Denial
    Legitimate Client->>Network Switch: Legitimate DHCP Discover (Real MAC)
    Network Switch->>DHCP Server: Forward Discover
    DHCP Server-->>Legitimate Client: ❌ No IP Address Available (or Silence)
    Note left of Legitimate Client: Client cannot get an IP.<br/>No network access. Denied Service.
```

The goal of a DHCP starvation attack is to overwhelm the DHCP server with a flood of bogus DHCP requests, exhausting the pool of available IP addresses. This prevents legitimate clients from obtaining an IP address and essentially denies them access to the network.

Defending against DHCP starvation requires a combination of switch-level security features and network design practices:

1. DHCP Snooping: This security feature acts as a firewall between untrusted clients and trusted DHCP servers. The switch is configured to differentiate between trusted ports (connected to legitimate DHCP servers) and untrusted ports (connected to clients). DHCP snooping helps mitigate DoS attacks by limiting the rate of DHCP messages and filtering out suspicious traffic (DHCP messages received on an untrusted port, as normally sent by a DHCP client, may be filtered if they appear to be part of an attack). On untrusted ports, the switch:

    - **Rate-limits DHCP traffic:** Prevents an attacker from flooding the network with Discover messages by limiting the number of DHCP packets accepted per second from a single port.
    - **Validates DHCP messages:** Drops DHCP server messages (OFFER, ACK) received on untrusted ports, preventing rogue server responses.
    - **Builds a DHCP snooping binding table:** Tracks legitimate IP-to-MAC bindings, which other security features (like Dynamic ARP Inspection) can use.

For a detailed walkthrough of DHCP snooping configuration and verification on Cisco switches: [DHCP snooping configuration and verification](https://itnetworkingskills.wordpress.com/2023/05/14/dhcp-snooping-configuration-verification/)

2. Port Security: This feature limits the number of MAC addresses allowed on a single switch port. By setting a maximum of one to three MAC addresses per access port, the switch can shut down or block a port that suddenly generates traffic from dozens of spoofed MAC addresses—a clear indicator of a DHCP starvation attempt.

3. VLAN Segmentation: Placing DHCP clients in separate broadcast domains limits the scope of an exhaustion attack to a single VLAN, preventing it from affecting the entire network.

While DHCP exhaustion aims to deny service by consuming addresses, a related attack, the rogue DHCP server (DHCP poisoning—examined in the MITM section), uses similar techniques to position the attacker for man-in-the-middle operations:

- Spoofed MAC addresses: Both attacks involve using spoofed source MAC addresses.
- Attack chaining: Attackers often use DHCP exhaustion first to force clients to accept offers from a rogue DHCP server they introduce later. When the legitimate server's pool is empty, clients will accept any offer—including from the attacker's malicious server.

Both attack types (DHCP exhaustion and DHCP poisoning) are mitigated by the same control—DHCP snooping—which validates DHCP server legitimacy and rate-limits traffic. 

**UDP Flooding**

In a direct UDP flooding attack, the attacker directly targets a victim’s server or host by flooding it with a high volume of UDP packets. Since UDP is connectionless, the target must process each incoming packet, consuming bandwidth, CPU, and memory. Attackers often spoof the source IP address to hide their identity and make mitigation harder. The goal is to exhaust the victim’s resources, causing slowdowns or a complete denial of service (DoS). Mitigation strategies include rate limiting UDP traffic, deploying firewalls to filter malicious packets, and using intrusion detection/prevention systems (IDS/IPS) to identify and block suspicious activity. Cloud-based DDoS protection services can also help absorb and disperse the attack traffic before it reaches the target.

In a UDP Reflection/Amplification attack, the attacker does not target the victim directly. Instead, they send small, spoofed UDP requests (e.g., DNS or NTP queries) to publicly accessible servers, forging the victim’s IP as the source. These servers then respond with much larger replies, reflecting and amplifying the attack traffic toward the victim. The attacker leverages misconfigured servers as unwitting "proxies" to multiply the attack’s impact, potentially achieving 10x–100x amplification with minimal effort. Mitigation strategies include disabling open DNS/NTP resolvers, implementing source IP validation, and using cloud-based scrubbing.

**HTTP Flooding**

HTTP flooding is a layer 7 (application layer) DoS attack in which a botnet sends a high volume of seemingly legitimate HTTP requests—typically GETs for web pages or POSTs for form submissions—to overwhelm a web server's resources. Because these requests mimic normal user behavior, distinguishing attack traffic from legitimate visitors becomes challenging for traditional network-layer defenses. Attackers often employ variations such as slow-rate attacks (sending requests gradually to evade threshold-based detection) or pulse-wave attacks (bursts of traffic followed by pauses). Mitigation typically requires web application firewalls (WAFs) capable of analyzing request patterns, rate limiting based on user behavior, CAPTCHA challenges, and cloud-based scrubbing services that absorb and filter malicious HTTP traffic before it reaches the origin server.

**Ping of Death**

Ping of death is a legacy Layer 3 DoS attack that exploits improper handling of oversized ICMP packets. Under normal operation, IPv4 packets are limited to 65,535 bytes. By sending a malformed ping packet that exceeds this size—typically fragmented and reassembled on the target—an attacker can trigger buffer overflows in vulnerable systems, causing crashes, reboots, or kernel panics. While this attack is largely historical due to patches implemented in modern operating systems (which now drop such malformed packets by default), it remains relevant for legacy systems, unpatched IoT devices, and as a foundational example of how protocol violations can lead to denial of service. Mitigation involves simply ensuring systems are updated and applying ingress filtering to block suspicious ICMP traffic at the network perimeter.

#### Reflection and amplification

Reflection and amplification attacks are sophisticated variants of volumetric denial-of-service attacks that leverage the behavior of legitimate network services to turn them against a target. Rather than flooding a victim directly, the attacker spoofs the victim's IP address and sends requests to intermediary servers—called reflectors—which then unwittingly deliver the attack traffic. This indirection not only obscures the attacker's identity but also harnesses the processing power and bandwidth of unsuspecting third-party infrastructure.

In a reflection attack, the attacker sends packets to a reflector (such as a DNS, NTP, or SNMP server) with the source IP address forged to match the intended victim. The reflector, believing the request is legitimate, sends its response to the victim's IP address. When enough reflectors are enlisted—or a single reflector receives enough queries—the aggregate response traffic can overwhelm the victim's network connection, resulting in denial of service. The key mechanism here is the spoofed source address; without it, the responses would return to the attacker rather than the target.

A reflection attack becomes an amplification attack when the response traffic is significantly larger than the requests that triggered it. Attackers specifically seek out services where a small query generates a voluminous reply, achieving what is known as the amplification factor. For example, a DNS query of approximately 60 bytes can be crafted to return a DNS response many times larger, particularly when using the ANY metatype or DNSSEC records. Similarly, the now-patched NTP monlist command would return a list of the last 600 clients that interacted with the NTP server, amplifying traffic by a factor of 200 or more. By combining reflection with amplification, attackers can generate devastating DDoS attacks—sometimes exceeding hundreds of gigabits per second—from relatively modest attacker-controlled infrastructure. Mitigation requires disabling unnecessary services on publicly accessible servers, implementing source IP validation to prevent spoofing, and using cloud-based DDoS scrubbing services to absorb and filter amplified traffic before it reaches the target.

#### Man-in-the-Middle (MITM) 

Man-in-the-middle attacks represent a class of exploits where an adversary secretly intercepts and potentially alters communications between two parties who believe they are directly communicating with each other. Unlike DoS attacks, which target availability, MITM attacks primarily threaten the confidentiality and integrity of information—allowing attackers to eavesdrop on sensitive data, steal credentials, inject malicious content, or redirect users to fraudulent websites. Follows is a discussion of two common MITM techniques: DHCP poisoning, where a rogue server assigns itself as the default gateway, and ARP spoofing, where falsified address resolution messages redirect traffic through the attacker's system.

**DHCP Poisoning**

In a DHCP poisoning attack a malicious device impersonates a legitimate DHCP server and offers IP addresses to clients. The spurious DHCP server leases a useful IP address to the target device, in the correct subnet, with the correct mask, but assigns its own IP address as the default gateway. Once a client accepts the attacker's offer, their communication gets routed through the attacker's device, allowing them to potentially eavesdrop on traffic, steal data, redirect the user to malicious websites, or damage or alter captured traffic. Mitigation: DHCP snooping.

```mermaid
sequenceDiagram
    participant Legitimate Client
    participant Attacker
    participant Legit DHCP Server
    participant Legit Gateway

    Note over Legitimate Client: Client needs an IP address

    Legitimate Client->>Attacker: DHCP Discover (Broadcast)
    Legitimate Client->>Legit DHCP Server: DHCP Discover (Broadcast)

    Note over Attacker, Legit DHCP Server: The Attacker races to respond first

    Attacker->>Legitimate Client: DHCP Offer (Malicious)
    Note left of Attacker: Offers: IP: 192.168.1.100<br/>Gateway: Attacker_IP<br/>DNS: Attacker_IP
    Legit DHCP Server->>Legitimate Client: DHCP Offer (Legitimate)
    Note right of Legit DHCP Server: Offers: IP: 192.168.1.10<br/>Gateway: Legit_Gateway_IP

    Note over Legitimate Client: Client typically accepts<br/>the first offer it receives

    Legitimate Client->>Attacker: DHCP Request (For malicious offer)
    Legitimate Client->>Legit DHCP Server: DHCP Request (For malicious offer - Broadcast)

    Attacker->>Legitimate Client: DHCP Ack
    Note left of Attacker: ✅ Attack Successful<br/>Client now uses attacker as gateway.

    Legit DHCP Server-->>Legitimate Client: (Silently discards request)

    Note over Legitimate Client, Attacker: Phase 2: Man-in-the-Middle Achieved

    Legitimate Client->>Attacker: All traffic to Internet
    Note left of Legitimate Client: Sends data via<br/>attacker's gateway
    Attacker->>Legit Gateway: Forward Traffic (Intercept & Inspect)
    Legit Gateway->>Attacker: Return Traffic
    Attacker->>Legitimate Client: Forward Traffic (Intercept & Inspect)

    Note over Attacker: Attacker can now:<br/>- Eavesdrop on all traffic<br/>- Steal data (passwords, etc.)<br/>- Redirect to malicious sites<br/>- Alter or damage packets
```

DHCP snooping is a security feature that helps prevent MITM attacks by identifying and discarding unauthorized DHCP messages, thereby stopping the attacker from establishing themselves as a fake server. DHCP snooping helps to prevent unauthorized DHCP servers from providing IP addresses to devices on a network. It does this by classifying ports on a switch as either trusted or untrusted. Untrusted ports are only allowed to forward DHCP Discover messages.

A DHCP server can send DHCP offers and acknowledgements only to ports that are trusted. If a DHCP server tries to send a DHCP offer or acknowledgement to an untrusted port, the switch will drop the packet. This helps to prevent unauthorized DHCP servers from providing IP addresses to devices on the network.

A further illustration of the DHCP poisoning attack (also covering DHCP snooping configuration and verification): [A spurious DHCP server and a malicious MITM](https://itnetworkingskills.wordpress.com/2023/05/14/dhcp-snooping-configuration-verification/)

**ARP spoofing**

ARP spoofing, also known as ARP poisoning, is a MITM attack that allows attackers to intercept communication between network devices. In this kind of attack the attacker places himself between the source and destination to eavesdrop on communications or to modify traffic before it reaches the destination. Mitigation: Dynamic ARP Inspection (DAI).

The attacker sends fake ARP replies (gratuitous ARP) to associate their own MAC address with someone else’s IP address (e.g., the gateway’s IP). The attacker spoofs the source IP address of the target device as their own (impersonates a legitimate IP address). This tricks other devices into sending traffic intended for the victim’s IP to the attacker’s MAC instead.

In an ARP spoofing attack, a host sends an ARP request asking for the MAC address of another device. PC1 is asking for the MAC address of host 10.0.0.1, which is SRV1. Because ARP request messages are broadcast, the switch floods the frame, so both SRV1 and the attacker receive it. SRV1 sends an ARP reply to PC1. The attacker waits briefly and then sends another ARP reply (called **gratuitous ARP**) after the legitimate reply. If the attacker’s ARP reply arrives last, it will overwrite the legitimate ARP entry in PC1’s ARP table. 

Now in PC1’s ARP table, the entry for 10.0.0.1 will have the attacker’s MAC address, not the MAC address of the real 10.0.0.1, SRV1. So when PC1 tries to send traffic to SRV1, traffic will be forwarded to the attacker instead. Then, the attacker can inspect the messages, read their contents and then forward them to SRV1. Or the attacker can modify the messages before forwarding them to SRV1.

```mermaid
sequenceDiagram
    participant PC1
    participant Attacker
    participant Switch
    participant SRV1

    Note over PC1: Needs to send data to SRV1 (10.0.0.1)
    Note over PC1: Checks its ARP table...<br/>? -> 10.0.0.1

    PC1->>Switch: ARP Request (Broadcast)<br/>"Who has 10.0.0.1? Tell PC1"
    Note right of PC1: ARP Table: 10.0.0.1 -> ?

    Switch->>SRV1: Flood Request
    Switch->>Attacker: Flood Request

    Note over SRV1, Attacker: Both devices receive the request.

    SRV1->>Switch: LEGITIMATE ARP Reply (Unicast)<br/>"10.0.0.1 is at MAC-SRV1"
    Switch->>PC1: Forward Reply

    Note over PC1: ARP Table Updated (Temporarily Correct)<br/>10.0.0.1 -> MAC-SRV1

    Attacker->>Switch: MALICIOUS Gratuitous ARP Reply (Unicast/Broadcast)<br/>"10.0.0.1 is at MAC-ATTACKER"<br/>(Spoofs SRV1's IP)
    Switch->>PC1: Forward Malicious Reply

    Note over PC1: ⚠️ ARP Table POISONED<br/>Legitimate entry is OVERWRITTEN<br/>10.0.0.1 -> MAC-ATTACKER

    Note over PC1, Attacker: Phase 2: Man-in-the-Middle Achieved

    PC1->>Switch: Data for SRV1 (10.0.0.1)
    Note left of PC1: Dest MAC: MAC-ATTACKER
    Switch->>Attacker: Forward Data

    Note over Attacker: Attacker INTERCEPTS traffic.<br/>Can now:<br/>- Eavesdrop (Sniff)
    Attacker->>SRV1: Forward Data (Option A: Passively Relay)
    Note over Attacker: - Alter (Modify packets)<br/>- Damage (Drop packets)
    Attacker->>SRV1: Modified Data (Option B: Actively Tamper)

    SRV1->>Attacker: Reply Data (Dest: PC1)
    Attacker->>PC1: Forward Reply (Intercept & Inspect)
```

DAI (Dynamic ARP Inspection) validates ARP packets by checking them against a trusted DHCP snooping binding table or a manually configured ARP ACL. DAI ensures that the IP-to-MAC mappings in ARP replies are correct, stopping attackers from spoofing another host's IP address (a key technique in ARP poisoning attacks).

Since DAI verifies that an ARP reply matches a legitimate IP-MAC binding, it prevents a malicious host from falsely claiming a MAC address that does not belong to it (thus indirectly helping to prevent MAC spoofing).

A further illustration of the ARP spoofing attack: [Man in the middle attacks](https://itnetworkingskills.wordpress.com/2023/05/06/ccna-security-fundamentals/)

A further illustration of the ARP spoofing attack and mitigation via dynamic ARP inspection: [DAI configuration and verification](https://itnetworkingskills.wordpress.com/2023/05/16/dynamic-arp-inspection-configuration-and-verification/)

#### Spoofing attacks

To spoof an address is to use a fake source address, for example a fake IP or MAC address. There are various types of spoofing attacks: 

* Denial-of-Service (DoS)
* Reflection and Amplification 
* Man-in-the-Middle 

Each of the following spoofing attack types involves either IP spoofing or MAC spoofing as a mechanism of action.

**Spoofing Attacks Summary Table**

| Spoofing Attack Type                       | Primary Spoofing Method | Mitigation                                           | Explanation                                                                                                                                                               |
| ------------------------------------------ | ----------------------- | ---------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| TCP SYN Flood (DoS)                        | **IP Spoofing**         | Rate limiting, SYN cookies, Firewalls and IPS        | The attacker uses a spoofed source IP to hide their identity and overwhelm the target with connection requests, making the attack difficult to trace.                     |
| DHCP Exhaustion Attack (DoS)               | **MAC Spoofing**        | DHCP Snooping, Port Security                         | The attacker spoofs many different MAC addresses to request all available IP addresses from a DHCP server, exhausting the pool and denying service to legitimate clients. |
| Reflection and Amplification Attacks (DoS) | **IP Spoofing**         | Anti-spoofing ACLs, BCP38 (network egress filtering) | The attacker spoofs the victim's IP address as the source. This causes reflection servers to send large responses to the victim, amplifying the attack traffic.           |
| DHCP Poisoning (MITM)                      | **IP Spoofing**         | DHCP Snooping                                        | The attacker spoofs a legitimate DHCP server to provide clients malicious DHCP responses to redirect traffic for a MITM attack.                                           |
| ARP Spoofing (MITM)                        | **IP Spoofing**         | Dynamic ARP Inspection (DAI)                         | The attacker sends gratuitous ARP replies to link their MAC address to the IP address of a legitimate host, intercepting traffic.                                         |

Man-in-the-Middle attacks like ARP Spoofing and DHCP Poisoning are a prime example of how MAC spoofing and IP spoofing can be used in conjunction.

### Malware types

Malware (malicious software) refers to a variety of harmful programs designed to infiltrate, damage, or disable computers and computer systems without the user's informed consent. There are many types of malware, categorized by how they infect a system and how they spread, not by the attacks they carry out after infecting the system.

**Virus**\
A virus is a type of malware that attaches itself to a legitimate program or file, known as a host. It requires human action to spread, such as a user sharing an infected file or launching a corrupted program. Once activated, a virus can replicate itself and spread to other files and systems. Its payload can range from being merely annoying to highly destructive.

* Example: The ILOVEYOU Virus (2000) - One of the most damaging viruses ever, it arrived as a seemingly innocent love confession email attachment (`LOVE-LETTER-FOR-YOU.TXT.vbs`). Once opened, it overwrote critical user files (like JPEGs and documents) and replicated by sending itself to everyone in the victim's Microsoft Outlook address book, causing an estimated $10-15 billion in damages globally.

**Worm**\
Worms are different from viruses in that they are standalone software and do not require a host program or human interaction to propagate. They exploit vulnerabilities in network services or operating systems to spread automatically across networks at an incredible speed.

* Example: The WannaCry Worm (2017) - Although often called ransomware, WannaCry's rapid global spread was due to its worm component. It exploited a known Windows vulnerability (EternalBlue) to move laterally across networks without user interaction. Once on a system, it encrypted the user's files (its ransomware payload), demanding payment. It crippled critical infrastructure worldwide, including the UK's National Health Service (NHS), causing massive disruptions to healthcare services.

**Trojan Horse**\
A Trojan horse is harmful software disguised as legitimate or desirable software, tricking users into installing it themselves (e.g., a free game, a cracked application, or a fake software update). Unlike viruses and worms, Trojans do not self-replicate. Their purpose is to create a backdoor on the system, giving attackers unauthorized remote access.

* Example: Zeus Trojan (2007) - A notorious Trojan designed to steal banking credentials through keystroke logging and form grabbing. It was primarily spread through drive-by downloads and phishing emails. Once installed, it secretly transferred millions of dollars from victims' accounts. Its code was later adapted into other malware, making it one of the most influential and damaging Trojans in history.

**Ransomware**\
Ransomware is a particularly destructive form of malware that encrypts the victim's files, rendering them inaccessible. The attackers then demand a ransom payment (usually in cryptocurrency) in exchange for the decryption key.

* Example: Colonial Pipeline Attack (2021) - The DarkSide ransomware gang infected the systems of Colonial Pipeline, a major US fuel pipeline operator. The attack forced the company to shut down its entire pipeline system for days, causing widespread fuel shortages and price spikes across the US East Coast. The company paid a ransom of nearly $4.4 million, highlighting the real-world physical and economic damage cyberattacks can cause.

### Key takeaways

* Common cyber attacks include reconnaissance, social engineering, password attacks, denial-of-service (DoS), reflection and amplification, man-in-the-middle (MITM), and spoofing attacks.
* Common malware types include viruses, worms, Trojan horses, and ransomware.
* Social engineering exploits human psychology rather than technical vulnerabilities, with common types including phishing, vishing, tailgating, and watering hole attacks.
* Password attacks like dictionary and brute force attacks target weak authentication. Strong passwords should be at least 8 characters long, complex (mixing uppercase letters, lowercase letters, numbers, and special symbols), unique for every account, and changed regularly.
* DoS/DDoS attacks threaten availability by overwhelming a target's resources. Mitigation often involves rate limiting, traffic filtering, and network segmentation.
* Spoofing attacks (using fake IP or MAC addresses) are a core technique enabling many other attacks, including MITM (like ARP spoofing and DHCP poisoning) and DoS (like SYN floods).
* Specific security controls like DHCP snooping, Dynamic ARP Inspection (DAI), and SYN cookies are essential for defending against common network-based attacks.

### References

ICANN. (n.d.). ICANN Lookup. Retrieved from https://lookup.icann.org/en

Odom, W. (2020). CCNA 200-301 Official Cert Guide, Volume 2. Cisco Press.
