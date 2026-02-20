---
description: >-
  This section discusses major cybersecurity risk mitigation methods, including
  technologies, network design, networking protocols, organizational polices,
  security testing, and security training
---

# Cybersecurity risk mitigation methods

## Learning objectives

* List and describe major cybersecurity risk mitigation methods
* Understand the specific functions and practical applications of key cybersecurity risk mitigation technologies
* Understand how a segmented network architecture using VLANs and subnets can contain security breaches and limit lateral movement
* Identify the key components of an organizational information security policy, including data classification, access control, and incident response
* Understand the role of information security testing in validating security controls and meeting compliance requirements
* Understand the importance of continuous security training in mitigating cybersecurity risk

This section studies major cybersecurity risk mitigation methods. This section explores specific functions and practical applications of common cybersecurity risk mitigation technologies such as next-generation firewalls and intrusion prevention systems. Furthermore, it looks at how network architecture—through segmentation and secure design—forms a critical layer of defense. The discussion also covers the critical role of organizational policies, the necessity for proactive security testing, and the importance of continuous employee training in creating a resilient security posture.

## Topics covered in this section

* **Risk mitigation technologies**
* **Network design**
* **Networking protocols**
* **Organizational policies**
* **Security testing**
* **Security training**

### Risk mitigation technologies

Common cybersecurity risk mitigation technologies include Firewalls, IDS/IPS, Web Proxies, Virtual Private Networks (VPNs), Encryption, Web Filters, Anti-Virus, SIEM, EDR/XDR, Identity and Access Management (IAM), and Network Access Control (NAC).

#### Firewalls

Firewalls are network security systems that control incoming and outgoing network traffic based on predetermined security rules. Firewalls sit in the path of packets so they can filter the packets, redirect them for collection and later analysis, or let them continue toward their destination. In their most basic form, firewalls do the same kinds of work that routers do with ACLs (Access Control Lists). ACLs are configured on network devices such as routers to only allow specific traffic to pass through based on source and destination IP addresses, ports, and protocols. However, firewalls can perform packet filtering with more granularity and additional security functions.

While firewalls can share some router-like features (such as packet forwarding and filtering), they provide stronger security controls than a traditional router. For example, most firewalls use the following logic to determine whether to allow or discard a packet:

* **Source/Destination IP Matching** – Like router ACLs, firewalls filter traffic based on source and destination IP addresses.
* **Static Port-Based Filtering** – Identifies applications by matching well-known TCP/UDP ports (e.g., blocking port 23 for Telnet or allowing port 80 for HTTP).
* **Dynamic Port Tracking** – Monitors application-layer flows to detect additional TCP/UDP ports used mid-session (e.g., FTP data connections) and filters accordingly.
* **Stateful Inspection** – Maintains state tables to track active connections, allowing only legitimate follow-up traffic (e.g., permitting return packets for an established outbound session while blocking unsolicited inbound traffic).

Unlike next-generation firewalls (NGFWs), traditional firewalls do not perform deep packet inspection (DPI), user-based authentication, or advanced application-layer analysis. Instead, they focus on network-layer security (IPs, ports, and connection states), making them efficient for basic traffic control but less effective against sophisticated threats.

**Industry focus: Cisco Next-Generation Firewalls**

Next-generation firewall (NGFW): A firewall device with advanced features, including the ability to run many related security features in the same firewall device (IPS, malware detection, VPN termination), along with deep packet inspection with Application Visibility and Control (AVC) and the ability to perform URL filtering versus data collected about the reliability and risk associated with every domain name.

The following list summarizes a few key features of an NGFW (Odom, 2020):

**Traditional Firewall Foundation**: Cisco NGFWs perform all standard firewall functions, including stateful packet filtering, network address translation (NAT/PAT), and VPN termination—serving as the baseline upon which advanced security features are added.

**Application Visibility and Control (AVC)**: Unlike traditional firewalls that identify applications solely by port numbers, Cisco NGFWs inspect application-layer data to identify the actual application in use. This prevents attacks that evade detection by using non-standard ports or protocol tunneling, enabling policies based on application identity rather than just port numbers.

**Advanced Malware Protection (AMP)**: Cisco NGFW platforms run AMP directly on the firewall appliance rather than simply passing traffic to separate devices. This integration enables network-based antimalware functions to block file transfers carrying malicious code in real-time while also saving copies of files for retrospective analysis using Cisco Threat Grid—identifying new threats that may have initially evaded detection.

**URL Filtering with Cisco Talos Intelligence**: Cisco NGFWs examine URLs within web requests and categorize them using reputation data from the Cisco Talos security intelligence group. Talos continuously monitors Internet domains, assigning each a reputation score based on factors such as age, traffic patterns, and known associations with malicious activity. The firewall can then filter, block, or rate-limit traffic based on these scores and organizational policies.

**Integrated Next-Generation IPS**: Cisco NGFW products can run Cisco next-generation IPS (NGIPS) functionality as an integrated service rather than as a separate appliance. This tight integration allows the firewall and IPS to share context and coordinate responses, improving detection accuracy and enabling more sophisticated threat mitigation strategies.

#### IDS/IPS

Intrusion Detection Systems (IDS) monitor network traffic for signs of unauthorized access or malicious activity. A traditional intrusion prevention system (IPS) can sit in the path packets take through the network, and it can filter packets, but it makes its decisions with different logic. The IPS first downloads a database of exploit signatures. Each signature defines different header field values found in sequences of packets used by different exploits. Then the IPS can examine packets, compare them to the known exploit signatures, and notice when packets may be part of a known exploit. Once identified, the IPS can log the event, discard packets, or even redirect the packets to another security application for further examination.

A traditional IPS differs from firewalls in that instead of an engineer at the company defining rules for that company based on applications (by port number) and zones, the IPS applies the logic based on signatures supplied mostly by the IPS vendor. Those signatures look for these kinds of attacks: DoS, DDoS, Worms, Viruses. Organizations can also create custom signatures—an important capability for zero-day and application-specific threats.

**Industry focus: Cisco Next-Generation IPS**

Next-generation IPS (NGIPS): An IPS device with advanced features, including the capability to go beyond a comparison to known attack signatures to also look at contextual data, including the vulnerabilities in the current network, the capability to monitor for new zero-day threats, with frequent updates of signatures from the Cisco Talos security research group.

The following list mentions a few of the Cisco NGIPS features (Odom, 2020, p. 103):

■ Traditional IPS: An NGIPS performs traditional IPS features, like using exploit signatures to compare packet flows, creating a log of events, and possibly discarding and/or redirecting packets.

■ Application Visibility and Control (AVC): As with NGFWs, an NGIPS has the ability to look deep into the application layer data to identify the application.

■ Contextual Awareness: NGFW platforms gather data from hosts—OS, software version/level, patches applied, applications running, open ports, applications currently sending data, and so on. Those facts inform the NGIPS as to the often more limited vulnerabilities in a portion of the network so that the NGIPS can focus on actual vulnerabilities while greatly reducing the number of logged events.

■ Reputation-Based Filtering: The Cisco Talos security intelligence group researches security threats daily, building the data used by the Cisco security portfolio. Part of that data identifies known bad actors, based on IP address, domain, name, or even specific URL, with a reputation score for each. A Cisco NGIPS can perform reputation-based filtering, taking the scores into account.

■ Event Impact Level: Security personnel need to assess the logged events, so an NGIPS provides an assessment based on impact levels, with characterizations as to the impact if an event is indeed some kind of attack.

#### Web Proxies

**Understanding Proxies: Forward vs. Reverse**

Proxies act as intermediaries between clients and servers, but their roles differ significantly. A **forward proxy** sits in front of clients (e.g., users on a corporate network) and forwards their requests to the internet while masking their IP addresses—common in VPNs or censorship bypassing. In contrast, a **reverse proxy** sits in front of servers, receiving client requests and routing them to the appropriate backend (e.g., Apache, Node.js). This setup improves security by hiding server infrastructure and enhances performance through load balancing, SSL termination, and caching. For example, Nginx is often used as a reverse proxy to distribute traffic across multiple Apache servers while handling HTTPS encryption.

**Choosing the Right Proxy for Your Needs**

The choice between forward and reverse proxies depends on the use case. Forward proxies are ideal for user privacy and bypassing restrictions, while reverse proxies excel in optimizing server performance and security. For instance, a company might use a forward proxy to monitor employee internet traffic, while a high-traffic website would deploy a reverse proxy like Nginx to balance loads between servers. Both types can coexist—Cloudflare, for example, acts as a reverse proxy for websites while also offering forward proxy-like features (e.g., WARP VPN). Understanding these distinctions helps in designing scalable, secure, and efficient network infrastructures.

**When to Use Each?**

| **Scenario**                    | **Solution**          | **Example Tools**                                                                               |
| ------------------------------- | --------------------- | ----------------------------------------------------------------------------------------------- |
| **Control outbound web access** | Forward proxy         | Zscaler (commercial), Squid (open source/free), Palo Alto Prisma Access (commercial)            |
| **Control inbound web access**  | Reverse proxy/gateway | Cloudflare Access (commercial), Azure AD App Proxy (commercial), NGINX (open source/commercial) |
| **Comprehensive control**       | Both (Zero Trust)     | Combine Zscaler (outbound) + Cloudflare (inbound)                                               |

**Outbound vs. Inbound Web Access**

* **Outbound web access**
  * **Goal:** Control/monitor internal users/devices accessing the internet.
  * **Forward Proxy Role:**
    * Enforces policies (e.g., block malicious sites, filter content).
    * Authenticates users (e.g., prevents malware from exfiltrating data anonymously).
    * Logs traffic for audits (e.g., detect compromised workstations).
    * **Compliance:** Regulations like PCI DSS require monitoring outbound traffic for data leaks.
  * _Example:_ A company uses **Zscaler** or **Squid Proxy** to block employees from visiting phishing sites.
* **Inbound web access**
  * **Goal:** Protect internal resources from external access (e.g., web apps, APIs).
  * **Reverse Proxy/Gateway Role:**
    * Authenticates external users (e.g., VPN, WAF).
    * Filters malicious traffic (e.g., DDoS, SQL injection).
  * _Example:_ A bank routes all inbound traffic through **Cloudflare Access** or an **Azure Application Proxy** to enforce MFA.

**Key Functions of a Reverse Proxy**

Unlike a **forward proxy** (which hides clients from servers, e.g., VPNs), a **reverse proxy** hides servers from clients, improving security, performance, and scalability.

1. **Load Balancing**
   * Distributes incoming traffic across multiple backend servers to prevent overload.
   * Example: Nginx can route requests to 3 different web servers running the same site.
2. **SSL/TLS Termination**
   * Handles HTTPS encryption/decryption, offloading the work from backend servers.
   * Example: Nginx manages SSL certificates, while Apache serves plain HTTP internally.
3. **Caching**
   * Stores static content (images, CSS, JS) to reduce load on backend servers.
   * Example: Nginx caches a blog’s homepage for faster delivery.
4. **Security & Anonymity**
   * Hides backend servers (e.g., Apache, Node.js) from direct exposure to the internet.
   * Can block malicious traffic (DDoS, SQLi) before it reaches the app.
5. **URL Rewriting & Routing**
   * Redirects requests based on paths (e.g., `/blog` → a WordPress server, `/api` → a Node.js app).

**How Reverse Proxies Optimize Web Servers**

Reverse proxies like Nginx or Traefik are crucial for modern web architectures. They efficiently manage traffic by directing requests based on paths (e.g., `/api` to a backend service, `/static` to cached files) and offloading heavy tasks like SSL decryption. This allows backend servers (such as Apache) to focus on processing dynamic content without exposure to direct internet traffic. Additionally, reverse proxies provide security benefits—blocking malicious requests, mitigating DDoS attacks, and acting as a shield for vulnerable applications. A typical setup might involve Nginx serving static content at high speed while proxying PHP requests to Apache for processing.

All organizational web traffic—outbound (workstation to internet) and inbound (external access to internal apps)—should route through authenticated gateways for control and monitoring. For outbound traffic, a forward proxy ensures only authorized users/programs initiate connections. For inbound traffic, a reverse proxy or API gateway enforces access policies. This centralized approach simplifies security without significant user impact.

#### Virtual Private Networks (VPNs)

**Internet VPNs: Secure Connectivity Over a Public Network**

Businesses require secure connectivity between geographically separate sites and for remote employees. Private WAN services such as leased lines and MPLS provide security through dedicated physical infrastructure (leased lines) or traffic separation via tags (MPLS). However, when using the Internet as a WAN to connect sites together, there is no built-in security by default.

VPNs solve this problem by creating a secure "tunnel" over the shared public Internet, ensuring confidentiality, integrity, and authentication for the traffic that passes through them. Internet VPNs are broadly categorized into two types, each designed for a specific use case and employing different technologies: **Site-to-Site VPNs** and **Remote-Access VPNs**.

#### **1. Site-to-Site VPNs (using IPsec)**

A site-to-site VPN establishes a secure, permanent connection between two networks (e.g., a main office and a branch office) over the Internet. It connects entire networks to each other.

* **Primary Technology:** IPsec (Internet Protocol Security)
* **Function:** A VPN tunnel is created between two gateway devices (such as routers or firewalls) at the edge of each network. All traffic between the sites is routed through these gateways, which handle the encryption and decryption. This provides security for _all devices_ within each site without requiring software on every individual computer.

**How IPsec VPNs Work: A Basic Overview**\
The security process involves the following steps for each packet:

1. **Encryption:** The gateway router at Office A takes the original IP packet destined for Office B and encrypts its payload.
2. **Encapsulation:** The router encapsulates the encrypted packet by adding an IPsec header (for security parameters) and a _new_ IP header. This new header uses the public IP addresses of the two gateway routers as its source and destination.
3. **Transit:** This new, secure packet is routed across the public Internet. To any intermediary device, the packet appears as a standard IP packet moving between the two routers, hiding the original source, destination, and content.
4. **Decryption:** The gateway router at Office B receives the packet, verifies its authenticity, strips off the new IP header and IPsec header, decrypts the payload, and forwards the original packet to the intended host inside its local network.

**Limitations of Standard IPsec and Enhancements**

* **Problem 1: No Native Support for Multicast/Broadcast**\
  IPsec only supports unicast traffic. This prevents the transmission of multicast or broadcast traffic, which is essential for routing protocols like OSPF or EIGRP to dynamically exchange routing information across the tunnel.
* **Solution: GRE over IPsec**\
  To overcome this, **GRE (Generic Routing Encapsulation)** is used in conjunction with IPsec. GRE can encapsulate a wide variety of traffic—including multicast, broadcast, and non-IP protocols—into a standard unicast IP packet. However, GRE does not provide encryption.\
  **GRE over IPsec** combines the best of both: GRE first encapsulates the original packet (including any multicast routing updates), and then IPsec encrypts the entire GRE packet. This provides the flexibility of GRE with the robust security of IPsec.
* **Problem 2: Scalability in Full-Mesh Networks**\
  Manually configuring a full mesh of IPsec tunnels between every site in a large network (where every site connects directly to every other site) becomes complex and labor-intensive.
* **Solution: Dynamic Multipoint VPN (DMVPN)**\
  Scalability solutions like **Cisco's DMVPN** dynamically create tunnels on-demand between sites only when needed, significantly reducing configuration overhead and simplifying the management of large-scale site-to-site VPN deployments.

#### **2. Remote-Access VPNs (using TLS/SSL)**

Whereas site-to-site VPNs connect entire networks, remote-access VPNs are designed to provide secure, on-demand access for individual end-user devices (like laptops, smartphones, and tablets) to a central company network over the Internet.

* **Primary Technology:** TLS (Transport Layer Security).
* **Function:** This technology, which also secures HTTPS websites, creates a secure tunnel between VPN client software on an end device and a VPN gateway (a dedicated server or a firewall) at the company's data center.

**How Remote-Access VPNs Work**

1. **Client Software:** Users have a VPN client application (e.g., Cisco AnyConnect, OpenVPN) installed on their device.
2. **Connection Initiation:** The user launches the client, which establishes an authenticated and encrypted TLS session with the company's VPN gateway.
3. **Secure Access:** Once the tunnel is established, the user's device behaves as if it is directly connected to the company's internal network, allowing it to securely access email, internal file shares, and business applications.

#### **Key Comparison: Site-to-Site vs. Remote-Access VPNs**

| Feature                | Site-to-Site VPN                                                 | Remote-Access VPN                                                |
| ---------------------- | ---------------------------------------------------------------- | ---------------------------------------------------------------- |
| **Purpose**            | Permanently connect two or more networks.                        | Provide on-demand access for individual devices.                 |
| **Endpoint**           | Gateway-to-Gateway (e.g., Router to Router).                     | Client-to-Gateway (e.g., Laptop to Firewall).                    |
| **Scope**              | Protects traffic for **all devices** within the connected sites. | Protects traffic for **only the one device** running the client. |
| **Primary Technology** | IPsec (often with GRE).                                          | TLS (Transport Layer Security).                                  |
| **Use Case**           | Connecting a branch office to a headquarters.                    | An employee working from home or a hotel.                        |

In summary, both VPN types are essential tools for modern business, leveraging the Internet's ubiquity and low cost while providing the security once exclusive to private networks. The choice between them depends entirely on whether the goal is to connect entire networks or to connect individual users.

**Popular VPN Examples:**

* **Open-Source VPNs:**
  * **OpenVPN** – A highly configurable, secure, and widely used open-source VPN solution.
  * **WireGuard** – A lightweight, high-performance VPN known for its simplicity and strong encryption.
* **Commercial Enterprise VPNs:**
  * **Cisco AnyConnect** – A widely adopted enterprise VPN offering robust security and scalability.
  * **NordLayer (by NordVPN)** – A business-focused VPN with advanced access control and encryption.

#### Encryption

Encryption transforms readable data (plaintext) into a scrambled, unreadable format (ciphertext) using algorithms and cryptographic keys to protect it from unauthorized access. Encryption is a fundamental security measure designed to protect data confidentiality for data at rest (on storage devices), in transit (across networks), and in use (during processing). Strong encryption standards can be implemented to secure sensitive information, enforce data protection policies, and ensure privacy for communications and stored files across individual, corporate, and government use.

#### Web Filters 

Web Filters prevent users’ browsers from loading certain pages from particular websites. There are different web filters designed for individual, family, institutional, and enterprise use. Web domain whitelisting can be implemented using a web filter that can make web access policies and perform web site monitoring.

#### Anti-Virus

Anti-Virus software is a security program designed to prevent, detect, and remove malicious software (malware), including viruses, worms, Trojan horses, spyware, and ransomware. It uses a combination of signature-based detection (matching known malware code) and heuristic analysis (identifying suspicious behavior) to protect systems. Anti-Virus solutions can be implemented on individual devices, networks, and email gateways to establish security policies, perform real-time system monitoring, and quarantine threats for both personal and enterprise use.

**Note** - SIEM, EDR/XDR, IAM, and NAC are covered in the section [Network security risk mitigation best practices](../network-security-risk-mitigation-best-practices/) (Chapter 2). SIEM and EDR/XDR are further discussed in the section [Defensive cybersecurity technologies](../../6.-practical-foundations-in-ethical-hacking/defensive-cybersecurity-technologies/) (Chapter 6).

### Network design

A well designed network supports efficient Internet usage and device communication as well as redundancy, optimization, and security. Network design considerations/practices in support of network security include Network Segmentation, Honeypots, Network Automation, and Effective Network Architecture. Designing networks with these considerations in mind reduces attack surfaces and improves overall resilience against cyber threats.

#### Network Segmentation

Effective cybersecurity risk mitigation begins with a well-designed network architecture that prioritizes security at every layer. By strategically segmenting networks, organizations can limit the spread of malware and unauthorized access, ensuring that breaches in one area do not compromise the entire system. Network segmentation involves segregating a network into logical or functional zones. For example, you might have a zone for sales, a zone for technical support, and a zone for research, with each zone having different technical needs. You can separate zones using routers or switches or using virtual local area networks (VLANs).

Segmentation limits the potential damage of a compromise to whatever is in the compromised zone. Segmentation divides one target into many, which forces attackers to interact with each segment as a separate network. This creates a great deal of additional work for the attacker, since the attacker must compromise each segment individually. Further, this approach dramatically increases the attacker’s exposure to being discovered. 

Segmentation also helps enforce data protection by applying different security rules to each zone based on sensitivity. In extreme cases, critical systems can be air-gapped (disconnected entirely) to prevent attacks, such as with backup servers.

Virtualization is another way to segment a network. It is much easier to segment virtual systems than it is to segment physical systems. For example, you can easily configure a virtual machine on your workstation so that the virtual machine is completely isolated from the workstation — it does not share a clipboard, common folders or drives, and literally operates as an isolated system.

**Virtual Local Area Networks (VLANs)**

When segmenting networks for security, both **subnets** and **VLANs** can be used, but they serve different purposes and operate at different layers of the network. Here’s when to use each:

#### 1. VLANs (Virtual LANs) – Layer 2 Segmentation

VLANs are used to segment portions of a network at layer two and differentiate devices. VLANs are configured on a switch by adding a tag to a frame. The 802.1q (dot1q) tag designates the VLAN that the traffic originates from.

* **Use VLANs when:**
  * You need to **isolate broadcast domains** at Layer 2 (switch level).
  * You want to **logically separate devices** (e.g., departments, IoT, guests) without requiring physical switches.
  * You need **traffic isolation** (devices in different VLANs cannot communicate without a router/firewall).
  * You want to **reduce attack surfaces** (e.g., preventing ARP spoofing, Layer 2 attacks between groups).
  * You’re working in a **single physical network** but need multiple logical networks (e.g., one switch handling multiple secure zones).
* **Example Use Cases:**
  * Separating **HR, Finance, and Engineering** departments.
  * Isolating **IoT devices** from the main corporate network.
  * Creating a **guest Wi-Fi network** that can’t access internal resources.

#### 2. Subnets – Layer 3 Segmentation

* **Use Subnets when:**
  * You need **IP-based segmentation** (routed networks).
  * You want to **apply firewall rules between networks** (e.g., blocking traffic from Sales to IT).
  * You need **better traffic management** (e.g., QoS, routing policies).
  * Your network is **large and requires hierarchical addressing** (e.g., different offices, cloud networks).
  * You’re using **cloud environments** (AWS/Azure subnets for security groups & NACLs).
* **Example Use Cases:**
  * Separating **branch offices** with different IP ranges.
  * Creating **DMZ subnets** for public-facing servers.
  * Enforcing **micro-segmentation** in data centers (e.g., PCI-compliant networks).

#### When to Use Both VLANs + Subnets Together

* For **stronger security**, combine both:
  * **VLANs** for Layer 2 isolation (prevents direct device-to-device attacks).
  * **Subnets** for Layer 3 segmentation (enables firewall filtering between groups).
* Example:
  * VLAN 10 → Subnet `192.168.1.0/24` (Corporate)
  * VLAN 20 → Subnet `192.168.2.0/24` (Guests)
  * VLAN 30 → Subnet `10.0.30.0/24` (IoT)
  * **Firewall rules** block IoT from accessing Corporate.

#### Key Differences for Security

| Feature                | VLANs (Layer 2)                                       | Subnets (Layer 3)                 |
| ---------------------- | ----------------------------------------------------- | --------------------------------- |
| **Segmentation Level** | MAC-based (switch ports)                              | IP-based (routing)                |
| **Traffic Control**    | Limited (broadcast domains)                           | Granular (firewall rules)         |
| **Attack Surface**     | Protects against Layer 2 attacks (e.g., ARP spoofing) | Protects against IP-based attacks |
| **Scalability**        | Good for single-site networks                         | Better for large, routed networks |
| **Cloud Usage**        | Rare (mostly on-prem)                                 | Common (AWS/Azure subnets)        |

#### Best Practices for Security

✔ **Use VLANs** for **internal segmentation** (switch-level isolation).\
✔ **Use Subnets** for **inter-VLAN routing & firewall policies**.\
✔ **Combine both** for **defense-in-depth** (e.g., VLANs + Subnets + ACLs).\
✔ **Avoid VLAN hopping** by securing trunk ports and using private VLANs where needed.\
✔ **Prefer Subnets in cloud** (cloud networks rely on IP-based segmentation).

#### Practical Approach

* **For physical networks:** Start with VLANs, then assign subnets for routing.
* **For cloud/virtual networks:** Use subnets with security groups/NACLs.
* **For maximum security:** Use both with strict firewall rules between them.

#### Security zones using VLANs

VLANs can be used to define security zones to regulate traffic flow within and between network segments. 

* **Traffic Management and Access Control**:\
  While security zones primarily focus on internal traffic, it’s crucial to plan for how external devices or traffic will integrate into the network. For example:
  * Most external traffic (e.g., HTTP, mail) remains confined to the demilitarized zone (DMZ).
  * Remote users requiring internal access can be granted permissions based on MAC/IP addresses, enforced via network security controls.
  * Access rules are dictated by organizational policies, compliance requirements, and security protocols, which we’ll explore next.
* **Implementation and Enforcement**:\
  Security zones and access controls dictate traffic routing, but authorization decisions rely on:
  * Company security policies.
  * Compliance standards.
  * Technical controls (e.g., firewalls, NAC).

The next step is applying these principles to practical VLAN deployment and policy enforcement. Follows is a summary table of commonly standardized security zones. 

#### Security Zones

| Zone           | Explanation                                                         | Examples                                  |
| -------------- | ------------------------------------------------------------------- | ----------------------------------------- |
| **External**   | Devices and entities outside the organization’s network or control. | Devices connecting to a web server        |
| **DMZ**        | Isolates untrusted networks/devices from internal resources.        | BYOD, remote users/guests, public servers |
| **Trusted**    | Internal networks/devices without sensitive data.                   | Workstations, B2B                         |
| **Restricted** | High-risk servers or databases.                                     | Domain controllers, client information    |
| **Management** | Dedicated to network/device management (often grouped with Audit).  | Virtualization management, backup servers |
| **Audit**      | Dedicated to security monitoring (often grouped with Management).   | SIEM, telemetry                           |

DMZ is a noncritical yet secure segment of the network at the periphery of a private network, positioned between the public internet and the internal network. It is typically separated from the public network by an outer firewall and may also be divided from the private network by an additional firewall. Organizations often deploy a DMZ to host public-facing servers—such as web or email servers—that need to be accessible to untrusted users. By placing these servers in the DMZ, the organization can restrict access to the internal network, reducing exposure to potential threats. While authorized internal users can still reach the DMZ servers, external users are confined to the DMZ and cannot penetrate deeper into the network.

* **Network Security Policies and Controls**

Now that we’ve discussed segmentation and secure architecture design (security zones), enforcement becomes critical. Key considerations include:

* **Routing Between VLANs**: If VLANs are meant to be isolated, how is access restricted or granted?
* **Policy-Based Control**: Network traffic policies dictate routing behavior before standard protocols take effect.
* **Standards & Vendor Practices**:
  * IEEE provides standardized policies like **QoS (802.11e)** for traffic prioritization.
  * Many other routing and traffic policies, though not IEEE-standardized, are widely adopted by vendors for consistency.

**Traffic Filtering**

A fundamental method for enforcing access is through **ACLs (Access Control Lists)**:

* **ACLs** serve as rule sets for filtering traffic across different implementations.
* Each ACL contains **ACEs (Access Control Entries)**, which define rules based on criteria like:
  * Source/destination IP addresses.
  * Port numbers.
  * Protocol types.
* **Use Cases**:
  * **Cisco**: Applies ACLs for traffic filtering, queuing, and dynamic access control.
  * **VyOS**: Uses ACLs or prefix lists in its basic filtering policy.

Traffic filtering ensures security, validation, and segmentation by allowing or blocking traffic based on predefined rules.

**Practice**

Explore practical ACL implementation in traffic filtering and access control policies: [How to configure standard ACLs on Cisco routers](https://itnetworkingskills.wordpress.com/2023/04/11/how-configure-standard-acls-cisco-routers/)

**Prioritize network traffic using QoS**

Set up QoS (Quality of Service) policies on routers, switches, and firewalls to shape and prioritize traffic. QoS settings are vital in managing network traffic, ensuring priority is given to critical applications. Load balancing and bandwidth management further help in evenly distributing network traffic, preventing any single resource from becoming a bottleneck.

**Network Segmentation vs Micro-Segmentation**

While traditional network segmentation can use VLANs and subnets as its primary tool, micro-segmentation often bypasses or works on top of these constructs. 

* **Network Segmentation**: Dividing the network into smaller, isolated zones (e.g., VLANs, subnets) to contain breaches.
* **Micro-Segmentation**: Applying granular **security policies** to individual workloads or applications for enhanced protection. 

A micro-segmentation policy could be applied to two VMs that are on the _same VLAN and subnet_, preventing them from talking to each other unless explicitly allowed. A traditional network firewall at the VLAN boundary would be blind to this East-West traffic.

**The "Zero Trust" Principle:** Micro-segmentation is a core implementation of the Zero Trust model ("never trust, always verify"). It assumes a breach has already occurred inside a segment and prevents lateral movement by an attacker. Traditional segmentation often operates on a "trust but verify" model within a segment.

**East-West vs. North-South Traffic:**

* **Network Segmentation** is traditionally very good at controlling **North-South** traffic (traffic moving in and out of the network segment/zone).
* **Micro-Segmentation** is specifically designed to control **East-West** traffic (traffic between servers _within_ the same segment/zone), which is where most malicious lateral movement occurs after a breach.

Micro-segmentation takes the principle of "divide and contain" and applies it with far greater precision, using software-defined policies instead of relying on network hardware boundaries. You can have network segmentation _without_ micro-segmentation (e.g., just using VLANs), but effective micro-segmentation implements and enhances the goals of network segmentation.

#### Detailed Comparison

| Feature                   | Network Segmentation                                                                  | Micro-Segmentation                                                                                                                  |
| ------------------------- | ------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| **Primary Scope**         | **Broad, network-centric.** Focuses on dividing the network itself.                   | **Granular, workload-centric.** Focuses on isolating individual workloads, applications, or processes.                              |
| **Unit of Segmentation**  | Subnets, VLANs, Zones (e.g., "DMZ," "Finance VLAN," "User Subnet").                   | Individual servers, virtual machines (VMs), containers, or even applications _within_ a server.                                     |
| **Enforcement Point**     | Physical or virtual network infrastructure: **Routers, Firewalls, Switches.**         | **Software-based.** The hypervisor vSwitch, host-based firewalls, or a dedicated software agent on the workload itself.             |
| **Underlying Technology** | VLANs, ACLs (Access Control Lists), Subnetting, Physical Firewalls.                   | **Software-Defined Networking (SDN)**, Cloud Security Groups, Host-Based Firewalls (e.g., iptables, Windows Firewall).              |
| **Policy Based On**       | Primarily **IP Addresses, TCP/UDP Ports, and VLAN tags.**                             | **Identity and Context.** Labels (e.g., "Web-Tier," "App-Tier"), workload names, security tags, and application identity.           |
| **Agility & Flexibility** | Less agile. Changes often require reconfiguring physical hardware or network devices. | Highly agile. Policies can be applied and changed instantly through software, ideal for dynamic cloud and virtualized environments. |

In a modern security architecture, you would often use both:

* **Network Segmentation** to create large, logical zones (e.g., Production, Development, DMZ).
* **Micro-Segmentation** inside each of those zones to control traffic between the individual workloads.

#### Honeypots

A honeypot is a security mechanism designed to detect, deflect, or study unauthorized access attempts in a network. It acts as a decoy system, appearing to be a legitimate target (e.g., a server, database, or IoT device) but is actually isolated and monitored to gather information about attackers. For example, you might set up a server that appears to be a financial database but actually has only fake records. 

Honeypots can exhaust attackers by making them interact with phoney systems. Further, since honeypots are not real systems, legitimate users do not ever access them and therefore you can turn on extremely detailed monitoring and logging there. When an attacker does access a honeypot, you can gather a lot of evidence to aid in your investigation. When properly deployed, honeypots enhance threat detection and incident response capabilities.

A honeynet can be deployed as a complementary defense mechanism. A honeynet is a fake network segment that appears to be a very enticing target. Some organizations set up fake wireless access points for just this purpose.

#### Types of Honeypots

| Type Category             | Specific Type          | Description                                                                                              | Key Examples (Open Source / Commercial)              |
| ------------------------- | ---------------------- | -------------------------------------------------------------------------------------------------------- | ---------------------------------------------------- |
| **By Interaction Level**  | **Low-Interaction**    | Simulates only limited services (e.g., fake SSH/HTTP ports). Low risk and easy to deploy.                | **Honeyd, Kippo** (Both are **Open Source**)         |
|                           | **High-Interaction**   | Fully functional systems that allow deep attacker interaction. Capture detailed methods but are riskier. | **Honeynets, Cowrie** (Both are **Open Source**)     |
| **By Purpose**            | **Research**           | Used by cybersecurity researchers to study attack techniques and malware.                                | **Dionaea** (**Open Source** - for malware analysis) |
|                           | **Production**         | Deployed in corporate networks to detect and deflect intrusions.                                         | **Canary Tokens** (**Open Source**)                  |
| **Specialized Honeypots** | **Spam Honeypots**     | Designed to trap email harvesters and spammers.                                                          | **Spamhole** (Implied to be **Open Source**)         |
|                           | **Database Honeypots** | Fake databases used to detect SQL injection (SQLi) attacks.                                              | **HoneyDB** (**Open Source**)                        |
|                           | **IoT Honeypots**      | Mimic vulnerable Internet of Things (IoT) devices to attract attacks.                                    | **IoTPOT** (**Open Source**)                         |

**How Honeypots Enhance Security**

* **Attack Detection:** Identify malicious activity without false positives.
* **Threat Intelligence:** Gather data on attacker behavior (TTPs).
* **Distraction:** Keep attackers away from real systems.
* **Incident Response:** Help analyze breaches and improve defenses.

#### Network Automation

Software-defined networking (SDN) is a relatively recent trend that can be useful both in placing\
security devices and in segmenting the network. SDN is a powerful and efficient technology for implementing and managing micro-segmentation in a modern enterprise network. Essentially, in SDN the entire network is virtualized, which enables relatively easy segmentation of the network. It also allows administrators to place virtualized security devices wherever they want.

**How SDN can be Used for Micro-Segmentation**

* **Centralized Control and Policy Management:** The core principle of SDN is separating the control plane (the brain that decides how traffic flows) from the data plane (the devices that forward traffic). An SDN controller has a centralized, holistic view of the entire network. This allows administrators to define security policies (e.g., "Web server can talk to Database server on port 3306, but nothing else") in one place and push them out to all relevant devices instantly and consistently.
* **Network Virtualization and Abstraction:** SDN virtualizes the underlying physical hardware. This means micro-segmentation is achieved through software-defined policies (often called "groups" or "tags") rather than complex physical firewall rules and Access Control Lists (ACLs) on every switch and router. You segment based on **what a device is** (e.g., "IoT Sensor," "HR Server") rather than **where it is** plugged in (e.g., "Switch 5, Port 12").
* **Dynamic and Granular Enforcement:** Policies in an SDN are dynamic. When a device moves or a new virtual machine spins up, the SDN controller automatically identifies it, applies the appropriate security policy based on its identity, and places it in the correct segment. This enables extremely granular segmentation, down to the level of a single workload or device.

Adopting SDN permits dynamic security policy adjustments in response to emerging threats. For example, Cisco DNA Center is a software-based network management and automation platform that helps organizations simplify, automate, and secure their networks. DNA Center is an SDN controller in SD-Access architecture, but it can also be used as a general network management tool even in networks that do not use SD-Access. DNA Center has two main roles. First, it is the SDN controller used in SD-Access. Second, it can be a network manager in a traditional network that is not using SD-Access. In this case, it acts as a central point to monitor, analyze, and configure the network.

Cisco's SD-Access uses something called a **Virtual Network (VN)** for macro-segmentation (e.g., separating Guest, Corporate, and IoT traffic) and **Scalable Group Tags (SGTs)** for micro-segmentation within a VN. An SGT policy can enforce rules between any two entities, regardless of their IP address or physical location.

**Key Ways Network Automation Enhances Cybersecurity Posture**

Network automation uses software to perform network tasks with minimal human intervention. This fundamentally enhances security in the following key ways:

1. **Consistency and Elimination of Human Error:** Manual configuration is error-prone. A mistyped ACL can create a major security hole. Automation ensures that security policies are deployed exactly as defined, every time, across thousands of devices, eliminating configuration drift.
2. **Rapid Threat Response and Mitigation:**
   * When a threat is detected (e.g., an infected host), automated scripts can instantly isolate the compromised device by reconfiguring switch ports, updating ACLs, or pushing a new SGT policy across the entire network in seconds, far faster than any human team could.
3. **Continuous Compliance and Auditing:**
   * Automation tools can continuously scan network devices, compare their configurations against a gold-standard security template (a "desired state"), and automatically remediate any deviations. This ensures the network is always in a compliant state and generates audit-ready reports effortlessly.
4. **Comprehensive Visibility and Real-Time Monitoring:**
   * Automated systems provide a single source of truth for the entire network state. They can collect and correlate data from all devices, applications, and security tools, giving security teams a real-time view of traffic flows, anomalies, and potential threats.
5. **Secure Zero-Trust and Micro-Segmentation Deployment:**
   * As detailed above, automating the deployment and lifecycle management of micro-segmentation policies is the only practical way to implement a Zero-Trust architecture ("never trust, always verify") at scale across a large, dynamic network.
6. **Enhanced Vulnerability Management:**
   * Automation can schedule and execute security patches and updates for network devices (routers, switches, firewalls) during maintenance windows with minimal downtime, rapidly closing known vulnerabilities before they can be exploited.

In summary, **network automation transforms cybersecurity from a manual, reactive effort into a consistent, proactive, and rapid-response strategy.** It is essential for managing the complexity and scale of modern networks and enforcing robust security policies like those enabled by SDN and micro-segmentation.

#### Effective Network Architecture

When designing a network segregation strategy, device placement is critical. The simplest device to position is the firewall: it should be deployed at every network zone junction, ensuring each segment is protected. Fortunately, this is easier than it sounds—modern switches and routers include built-in firewall capabilities that only need activation and proper configuration. Another essential perimeter device is an anti-DDoS solution, which mitigates attacks before they impact the entire network. Behind the primary public-facing firewall, a web filter proxy should also be implemented.

For other devices, placement depends on the network’s structure. Load balancers, for example, should reside in the same segment as the servers they manage—whether in a DMZ for web servers or a private segment for database clusters. 

Network aggregation switches lack a fixed placement rule but are commonly used to consolidate bandwidth streams—for instance, optimizing throughput to and from a server cluster.

Finally, any Internet-connected network must have a local router with NAT and DHCP, both for security and to prevent IP exhaustion. The router should be the sole device connected to the modem, with all other devices routing through it.

### Networking protocols

Organizations must replace vulnerable protocols that transmit data in plaintext to prevent the exposure of credentials and configuration data in transit. For instance, FTP, Telnet, and HTTP should be substituted with their secure counterparts like FTPS/SFTP, SSH, and HTTPS. Similarly, SNMPv1/v2c, which uses cleartext community strings, must be replaced with SNMPv3. While protocols like NTP and SMTP can be secured using cryptographic extensions, they are not inherently safe by default and require explicit configuration. The fundamental principle is to assume attackers can eavesdrop on all network traffic and proactively eliminate cleartext protocols wherever possible.

**Network Address Translation (NAT)** helps organizations overcome the limited availability of IPv4 addresses by allowing multiple devices on a private network to share a single public IP address. NAT works by converting private (internal) IP addresses—used within an organization—into publicly routable addresses for communication over the internet or other IP networks.

Furthermore, NAT hides internal IP addresses from the public Internet by translating them to a public IP address. NAT enhances network security by acting as an additional layer of defense alongside firewalls. Hosts within the protected private network can initiate outbound connections to external systems, but external devices cannot directly access internal hosts without passing through a NAT gateway. This obscures the internal network structure, making it harder for attackers to identify and target specific devices. Additionally, by reducing the number of exposed public IP addresses, NAT further complicates reconnaissance efforts by malicious actors.

Secure DNS services like Cloudflare’s offer enhanced privacy and security by encrypting DNS queries, which can protect against DNS eavesdropping and spoofing attacks, often providing faster response times and improved reliability compared to standard DNS services.

**Network security protocols**

Network security protocols are essentially the security guards of the data traveling across a network. These protocols act as a set of rules that ensure the data gets from point A to B safely, without unauthorized access or alteration. There are different types of security protocols, each focusing on a specific aspect of data protection. Here's a brief breakdown:

• Encryption protocols: These scramble data using algorithms, making it unreadable to anyone without the decryption key. Examples include SSL/TLS, which secures communication on websites.

• Authentication protocols: These verify the identity of users or devices trying to access a network resource. For example, RADIUS (Remote Authentication Dial-In User Service) is a client-server protocol often used for managing network access.

• Integrity protocols: These make sure data has not been tampered with during transmission. They act like checksums, ensuring the data received is exactly what was sent. For example, HMAC (Hash-Based Message Authentication Code) is a specific mechanism used by other protocols such as TLS and IPsec to guarantee integrity. 

• Tunneling protocols: These encapsulate and encrypt data packets to create a secure "tunnel" across an untrusted network. For example, IPsec (Internet Protocol Security) operates at the network layer (Layer 3) of the OSI model, securing all communication between two points (e.g., two offices, a remote worker and a central server). 

• Wireless network security protocols such as WPA and WPA2 are considered more secure than WEP. For example, WPA2 uses AES for encryption and 802.1X for authentication. 

### Organizational policies

Information security organizational policies can include Usage Policy, Information Security Policy, and Privacy Policy. Such policies can be articulated separately or as provisions within a master policy (e.g., Security Policy) or as part of a broader security governance program or framework, such as a GRC program, detailing an enterprise’s set of security policies and procedures to achieve them. An organization’s information security policy has to be clear—and regularly updated. Employee’s knowledge of and adherence to information security policy are critical to robust data security. 

#### Key components of an information security policy

Here is a basic information security policy framework, aligned with industry best practices and international standards like ISO/IEC 27001, covering key components of an information security policy.

**1. Governance & Framework**

* **Policy Purpose & Scope:** Clearly defines the objectives of the policy and to whom/what it applies (employees, contractors, systems, data).
* **Roles and Responsibilities:** Explicitly outlines the security duties of everyone from the Board of Directors and CEO to IT staff and end-users.
* **Information Security Risk Governance:** The process for identifying, assessing, and treating risks. This includes compliance with regulations (GDPR, HIPAA, CCPA) and adherence to frameworks (ISO 27001, NIST CSF, SOC 2).

**2. Asset Management & Data Protection**

* **Asset Management Policy:** Rules for managing IT assets throughout their lifecycle (from procurement to disposal).
* **Data Classification and Handling:** A critical policy that defines categories of data (e.g., Public, Internal, Confidential, Restricted) and specifies how each class must be stored, transmitted, and destroyed. _(This was a key missing element in the original list.)_
* **Cryptography (Encryption) Policy:** Guidelines for the use of encryption to protect data at rest (on servers/drives) and in transit (over networks).

**3. Human Resources Security**

* **Employee Onboarding/Offboarding:** Security procedures for when employees join, change roles, or leave the organization.
* **Security Awareness Training:** Mandates regular training to ensure all personnel understand their security responsibilities and can recognize threats like phishing.
* **Acceptable Use Policy (AUP):** Defines acceptable and unacceptable use of company IT resources (email, internet, software, etc.). This is your "User responsibility/usage policies."
* **Ethical Code of Conduct / Confidentiality Agreements:** Establishes expected behavior and legal obligations to protect company information.

**4. Operational & Technical Security**

* **Access Control Policy:** Principles for granting and revoking user access to systems and data (e.g., principle of least privilege, role-based access).
* **Network Security Policy:** Governs the design, configuration, and monitoring of networks, including firewalls, segmentation, and wireless access.
* **System Hardening & Maintenance:** Policies for secure configuration of hardware and software (servers, workstations, network devices) and patch management.
* **Secure Software Development Lifecycle (SDLC):** Integrates security into the process of developing, testing, and deploying software and applications.
* **Backup, Disaster Recovery & Business Continuity:** Procedures for data backup, and plans to restore operations after a security incident or disaster.

**5. Incident Management & Compliance**

* **Incident Response Plan:** A formal plan for detecting, responding to, and recovering from security incidents (data breaches, ransomware, etc.). _(Another critical missing element.)_
* **Physical and Environmental Security:** Controls to protect physical assets like data centers, server rooms, and workstations from unauthorized access and environmental hazards.
* **Vendor and Third-Party Risk Management:** Policies to assess and monitor the security practices of partners, suppliers, and cloud service providers that have access to your data. _(Extremely important in modern supply-chain attacks.)_
* **Audit and Compliance Monitoring:** Procedures for regularly reviewing and auditing compliance with the security policy itself.

### Security testing

Information security testing is an essential part of both risk assessments and compliance audits.

A risk assessment is the process of **identifying, estimating, and prioritizing risks** to organizational operations, assets, and individuals. Information security testing is used to identify and assess the risks to an organization's information assets. This information is then used to develop and implement security controls to mitigate those risks. Security testing (like vulnerability scans and penetration tests) provides the **empirical evidence** needed to:

* **Identify Vulnerabilities:** Find actual weaknesses in systems, networks, and applications.
* **Validate Threats:** Confirm whether theoretical threats can actually be exploited.
* **Estimate Likelihood:** Get real data on how easy or difficult it is for an attacker to breach a system.
* **Predict Impact:** Simulate an attack to understand what data could be accessed and what the business impact would be.

Without testing, a risk assessment is often just an educated guess. Testing turns it into a data-driven evaluation.

A compliance audit is the process of **verifying that an organization adheres to a specific set of external rules or internal policies** (e.g., PCI DSS, HIPAA, SOC 2, ISO 27001). Information security testing is used in compliance audits to verify that an organization's information security controls are effective and are in compliance with applicable regulations. Many of these standards and regulations explicitly require regular security testing as a condition for compliance. For example:

* **PCI DSS:** Requires internal and external vulnerability scans (Req. 11.2) and penetration testing (Req. 11.3).
* **ISO 27001:** Control A.12.6.1 requires information about technical vulnerabilities to be managed and addressed in a timely manner, which is operationalized through vulnerability scanning.
* **SOC 2:** The Security principle often requires penetration testing and vulnerability scans as evidence of operational effectiveness for relevant criteria.

In an audit, testing provides the evidence that an auditor will examine to verify that security controls are not just in place on paper, but are actually working effectively.

There are a variety of information security testing methods that can be used, including:

* Vulnerability scanning: This method scans an organization's systems and networks for known vulnerabilities. 
* Penetration testing: This method simulates an attack on an organization's systems and networks to identify and exploit vulnerabilities. 
* Social engineering testing: This method tests the effectiveness of an organization's security controls against social engineering attacks. 
* Physical security testing: This method tests the security of an organization's physical assets, such as its buildings and data centers. 

The specific information security testing methods that are used will vary depending on the organization's specific risk assessment and compliance requirements.

Some of the benefits of information security testing include:

* It helps to identify and assess risks to an organization's information assets. 
* It helps to verify that an organization's information security controls are effective and are in compliance with applicable regulations. 
* It helps to identify and fix security vulnerabilities before they are exploited by attackers. 
* It helps to improve an organization's overall security posture.

### Security training

As technology evolves, so do the tactics of attackers, making continuous learning and adaptation paramount in maintaining robust cybersecurity defenses. In order to have good data security, it is important to maintain security awareness among employees. Good security awareness among IT personnel and other employees will allow an enterprise’s technical controls to work effectively. Employees should receive continuous security education.

User awareness programs are designed to make employees aware of potential security threats and risks. User awareness programs will help make employees aware of all of the cyber threats the company is facing. For example, a company might send out false phishing emails to make employees click a link and sign in with their login credentials. Employees who are tricked by the false emails will be informed that it is part of a user awareness program, and they should be more careful about phishing emails.

User training programs are more formal than user awareness programs. For example, dedicated training sessions which educate users on the corporate security policies, how to create strong passwords, and how to avoid potential threats. These should happen when employees enter the company, and also at regular intervals during the year.

### Key takeaways

* Key industry cybersecurity risk mitigation methods span technologies, system/network design, and organizational and network policies.
* A Layered Defense is Critical: Effective cybersecurity requires a combination of technologies (firewalls, VPNs, antivirus), secure network design (segmentation, DMZs), organizational policies, and continuous security training. No single solution is sufficient.
* Understand Core Security Technologies: Key technologies like NGFWs, NGIPS, and VPNs (both Site-to-Site and Remote-Access) serve distinct but complementary roles in protecting network perimeters and securing data in transit.
* Design for Security: Network architecture itself is a primary defense mechanism. Practices like segmentation (and its modern evolution, micro-segmentation) and deploying honeypots limit an attacker's ability to move laterally and cause widespread damage.
* Policies and People are Fundamental: Technical controls are supported by strong organizational policies (e.g., Information Security Policy, AUP) that define rules and procedures. These are ineffective without continuous security training and awareness programs to ensure employee adherence.
* Validate Your Defenses: Proactive security testing (vulnerability scanning, penetration testing) is essential for identifying weaknesses, informing risk assessments, and providing evidence for compliance audits. It turns theoretical security into proven, operational security.
* Embrace Automation and Modern Principles: Network automation ensures consistent, rapid, and error-free enforcement of security policies. Modern concepts like Zero Trust and micro-segmentation, often enabled by SDN, provide granular security that adapts to dynamic IT environments.

### References

Engebretson, P. (2011). _The Basics of Hacking and Penetration Testing: Ethical Hacking and Penetration Testing Made Easy_. Syngress.

Odom, W. (2020). CCNA 200-301 Official Cert Guide, Volume 2. Cisco Press.
