---
description: >-
  This section discusses network security risk mitigation methods, including
  technologies, network design, networking protocols, organizational polices,
  compliance frameworks, and risk assessment
---

# Risk mitigation methods

## Learning objectives

* List and describe key cybersecurity risk mitigation methods
* Develop an appreciation for the conceptual overlap between risk mitigation approaches
* Develop an appreciation for the need for a layered approach to cybersecurity
* Identify the need for a system's view of cybersecurity management&#x20;

This section reviews the main risk mitigation methods used to reduce the risk of a security breach or minimize the impact of an attack if it occurs. Risk mitigation methods explored span technologies, network design, networking protocols, organizational policies, compliance frameworks, risk assessment/security testing, professional conduct, and security training.

## Topics covered in this section

* **Risk mitigation technologies**
* **Risk mitigation via (re)design**
* **Networking protocols**
* **Organizational policies**
* **Risk assessment/security testing**
* **Security training**

### Risk mitigation technologies

Common risk mitigation technologies include: Firewalls, IDS/IPS, Next-Generation IPS, Next-Generation Firewalls, Web Proxies, VPN, Encryption, Web filters, SIEM, EDR/XDR, Network Access Control (NAC), Anti-Virus.

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

The most fundamental approaches to detecting cyber intrusions are to monitor server logs for signs of unauthorized access, to monitor firewall or router logs for abnormal events, and to monitor network performance for spikes in traffic. (EDUCAUSE, 2020)

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

Unlike a **forward proxy** (which hides clients from servers, e.g., VPNs), a **reverse proxy** hides servers from clients, improving security, performance, and scalability.

**Key Functions of a Reverse Proxy**

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

**Choosing the Right Proxy for Your Needs**

The choice between forward and reverse proxies depends on the use case. Forward proxies are ideal for user privacy and bypassing restrictions, while reverse proxies excel in optimizing server performance and security. For instance, a company might use a forward proxy to monitor employee internet traffic, while a high-traffic website would deploy a reverse proxy like Nginx to balance loads between servers. Both types can coexist—Cloudflare, for example, acts as a reverse proxy for websites while also offering forward proxy-like features (e.g., WARP VPN). Understanding these distinctions helps in designing scalable, secure, and efficient network infrastructures.

#### **When to Use Each?**

| **Scenario**                    | **Solution**                   | **Example Tools**                                   |
| ------------------------------- | ------------------------------ | --------------------------------------------------- |
| **Control outbound web access** | Forward proxy (authenticating) | Zscaler, Squid, Palo Alto Prisma Access             |
| **Control inbound web access**  | Reverse proxy/gateway          | Cloudflare Access, Azure AD App Proxy, NGINX + Auth |
| **Comprehensive control**       | Both (Zero Trust)              | Combine Zscaler (outbound) + Cloudflare (inbound)   |

**Outbound vs. Inbound Web Access**

* **Outbound web access**
  * **Goal:** Control/monitor internal users/devices accessing the internet.
  * **Proxy Role:**
    * Enforces policies (e.g., block malicious sites, filter content).
    * Authenticates users (e.g., prevents malware from exfiltrating data anonymously).
    * Logs traffic for audits (e.g., detect compromised workstations).
    * **Compliance:** Regulations like PCI DSS require monitoring outbound traffic for data leaks.
  * _Example:_ A company uses **Zscaler** or **Squid Proxy** to block employees from visiting phishing sites.
* **Inbound web access**
  * **Goal:** Protect internal resources from external access (e.g., web apps, APIs).
  * **Proxy/Gateway Role:**
    * Authenticates external users (e.g., VPN, WAF).
    * Filters malicious traffic (e.g., DDoS, SQL injection).
  * _Example:_ A bank routes all inbound traffic through **Cloudflare Access** or an **Azure Application Proxy** to enforce MFA.

All organizational web traffic—outbound (workstation to internet) and inbound (external access to internal apps)—should route through authenticated gateways for control and monitoring. For outbound traffic, a forward proxy ensures only authorized users/programs initiate connections. For inbound traffic, a reverse proxy or API gateway enforces access policies. This centralized approach simplifies security without significant user impact.

• **Virtual Private Networks (VPNs)**: Create a secure, encrypted connection between two or more networks over the Internet. A VPN is a secure, private network connection established over a public network. It enables remote devices to connect to a local network as if they were physically present. VPNs are commonly used to link LANs across the internet securely.

Setting up a VPN requires specialized hardware or VPN software installed on servers and workstations. VPNs rely on tunneling protocols like **Layer 2 Tunneling Protocol (L2TP)**, **IPSec**, or **Point-to-Point Tunneling Protocol (PPTP)**. To enhance security, VPNs often encrypt data, though this can reduce speed compared to standard network connections.

**Popular VPN Examples:**

* **Open-Source VPNs:**
  * **OpenVPN** – A highly configurable, secure, and widely used open-source VPN solution.
  * **WireGuard** – A lightweight, high-performance VPN known for its simplicity and strong encryption.
* **Commercial Enterprise VPNs:**
  * **Cisco AnyConnect** – A widely adopted enterprise VPN offering robust security and scalability.
  * **NordLayer (by NordVPN)** – A business-focused VPN with advanced access control and encryption.

• **Encryption**: Convert plaintext data into unreadable ciphertext to protect it from unauthorized access.

**• Web filters** prevent users’ browsers from loading certain pages from particular websites. There are different web filters designed for individual, family, institutional, and enterprise use. Web domain whitelisting can be implemented using a web filter that can make web access policies and perform web site monitoring.

### Risk mitigation via (re)design

Network Segmentation, DMZ, Honeypots, Defense in Depth, Network Automation, Effective Network Architecture

A well designed network supports efficient Internet usage and device communication as well as redundancy, optimization, and security.

#### Cybersecurity Risk Mitigation via Network (Re)Design

Effective cybersecurity risk mitigation begins with a well-designed network architecture that prioritizes security at every layer. By strategically segmenting networks, organizations can limit the spread of malware and unauthorized access, ensuring that breaches in one area do not compromise the entire system. A zero-trust model, which requires continuous authentication and authorization for all users and devices, further enhances security by eliminating implicit trust. Designing networks with these principles in mind reduces attack surfaces and improves overall resilience against cyber threats.

Key strategies for secure network (re)design include:

* **Network Segmentation**: Dividing the network into smaller, isolated zones (e.g., VLANs, subnets) to contain breaches.
* **Zero-Trust Architecture (ZTA)**: Enforcing strict **access controls** and verifying every request before granting access.
* **Micro-Segmentation**: Applying granular **security policies** to individual workloads or applications for enhanced protection.
* **Defense-in-Depth**: Layering security controls (firewalls, IDS/IPS, encryption) to provide multiple barriers against attacks.

#### Network Segmentation

Network segmentation involves segregating a network into logical or functional zones. For\
example, you might have a zone for sales, a zone for technical support, and a zone for research, with each zone having different technical needs. You can separate zones using routers or switches or using virtual local area networks (VLANs).

Segmentation limits the potential damage of a compromise to whatever is in the compromised zone. Segmentation divides one target into many, which forces attackers to interact with each segment as a separate network. This creates a great deal of additional work for the attacker, since the attacker must compromise each segment individually. Further, this approach dramatically increases the attacker’s exposure to being discovered.&#x20;

Segmentation also helps enforce data protection by applying different security rules to each zone based on sensitivity. In extreme cases, critical systems can be air-gapped (disconnected entirely) to prevent attacks, such as with backup servers.

Virtualization is another way to segment a network. It is much easier to segment virtual systems than it is to segment physical systems. For example, you can easily configure a virtual machine on your workstation so that the virtual machine is completely isolated from the workstation — it does not share a clipboard, common folders or drives, and literally operates as an isolated system.

#### VLANs&#x20;

VLANs (Virtual LAN) are used to **segment** portions of a network at layer two and differentiate devices.

VLANs are configured on a switch by adding a tag to a frame. The 802.1q or dot1q tag designates the VLAN that the traffic originates from.

When segmenting networks for security, both **subnets** and **VLANs** can be used, but they serve different purposes and operate at different layers of the network. Here’s when to use each:

#### **1. VLANs (Virtual LANs) – Layer 2 Segmentation**

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

#### **2. Subnets – Layer 3 Segmentation**

* **Use Subnets when:**
  * You need **IP-based segmentation** (routed networks).
  * You want to **apply firewall rules between networks** (e.g., blocking traffic from Sales to IT).
  * You need **better traffic management** (e.g., QoS, routing policies).
  * Your network is **large and requires hierarchical addressing** (e.g., different offices, cloud networks).
  * You’re using **cloud environments** (AWS/Azure subnets for security groups & NACLs).
* **Example Use Cases:**
  * Separating **branch offices** with different IP ranges.
  * Creating **DMZ subnets** for public-facing servers.
  * Enforcing **microsegmentation** in data centers (e.g., PCI-compliant networks).

#### **When to Use Both VLANs + Subnets Together**

* For **stronger security**, combine both:
  * **VLANs** for Layer 2 isolation (prevents direct device-to-device attacks).
  * **Subnets** for Layer 3 segmentation (enables firewall filtering between groups).
* Example:
  * VLAN 10 → Subnet `192.168.1.0/24` (Corporate)
  * VLAN 20 → Subnet `192.168.2.0/24` (Guests)
  * VLAN 30 → Subnet `10.0.30.0/24` (IoT)
  * **Firewall rules** block IoT from accessing Corporate.

#### **Key Differences for Security**

| Feature                | VLANs (Layer 2)                                       | Subnets (Layer 3)                 |
| ---------------------- | ----------------------------------------------------- | --------------------------------- |
| **Segmentation Level** | MAC-based (switch ports)                              | IP-based (routing)                |
| **Traffic Control**    | Limited (broadcast domains)                           | Granular (firewall rules)         |
| **Attack Surface**     | Protects against Layer 2 attacks (e.g., ARP spoofing) | Protects against IP-based attacks |
| **Scalability**        | Good for single-site networks                         | Better for large, routed networks |
| **Cloud Usage**        | Rare (mostly on-prem)                                 | Common (AWS/Azure subnets)        |

#### **Best Practices for Security**

✔ **Use VLANs** for **internal segmentation** (switch-level isolation).\
✔ **Use Subnets** for **inter-VLAN routing & firewall policies**.\
✔ **Combine both** for **defense-in-depth** (e.g., VLANs + Subnets + ACLs).\
✔ **Avoid VLAN hopping** by securing trunk ports and using private VLANs where needed.\
✔ **Prefer Subnets in cloud** (cloud networks rely on IP-based segmentation).

#### **Praactical Approach**

* **For physical networks:** Start with VLANs, then assign subnets for routing.
* **For cloud/virtual networks:** Use subnets with security groups/NACLs.
* **For maximum security:** Use both with strict firewall rules between them.

#### Security zones using VLANs

VLANs can be used to define security zones to regulate traffic flow within and between network segments.&#x20;

* **Traffic Management and Access Control**:\
  While security zones primarily focus on internal traffic, it’s crucial to plan for how external devices or traffic will integrate into the network. For example:
  * Most external traffic (e.g., HTTP, mail) remains confined to the DMZ.
  * Remote users requiring internal access can be granted permissions based on MAC/IP addresses, enforced via network security controls.
  * Access rules are dictated by organizational policies, compliance requirements, and security protocols, which we’ll explore next.
* **Implementation and Enforcement**:\
  Security zones and access controls dictate traffic routing, but authorization decisions rely on:
  * Company security policies.
  * Compliance standards.
  * Technical controls (e.g., firewalls, NAC).

The next step is applying these principles to practical VLAN deployment and policy enforcement. Follows is a summary table of commonly standardized security zones.&#x20;

#### Security Zones

| Zone           | Explanation                                                         | Examples                                  |
| -------------- | ------------------------------------------------------------------- | ----------------------------------------- |
| **External**   | Devices and entities outside the organization’s network or control. | Devices connecting to a web server        |
| **DMZ**        | Isolates untrusted networks/devices from internal resources.        | BYOD, remote users/guests, public servers |
| **Trusted**    | Internal networks/devices without sensitive data.                   | Workstations, B2B                         |
| **Restricted** | High-risk servers or databases.                                     | Domain controllers, client information    |
| **Management** | Dedicated to network/device management (often grouped with Audit).  | Virtualization management, backup servers |
| **Audit**      | Dedicated to security monitoring (often grouped with Management).   | SIEM, telemetry                           |

A demilitarized zone (DMZ) is a noncritical yet secure segment of the network at the periphery of a private network, positioned between the public internet and the internal network. It is typically separated from the public network by an outer firewall and may also be divided from the private network by an additional firewall. Organizations often deploy a DMZ to host public-facing servers—such as web or email servers—that need to be accessible to untrusted users. By placing these servers in the DMZ, the organization can restrict access to the internal network, reducing exposure to potential threats. While authorized internal users can still reach the DMZ servers, external users are confined to the DMZ and cannot penetrate deeper into the network.

* **Network Security Policies and Controls**

Now that we’ve discussed segmentation and secure architecture design (security zones), enforcement becomes critical. Key considerations include:

* **Routing Between VLANs**: If VLANs are meant to be isolated, how is access restricted or granted?
* **Policy-Based Control**: Network traffic policies dictate routing behavior before standard protocols take effect.
* **Standards & Vendor Practices**:
  * IEEE provides standardized policies like **QoS (802.11e)** for traffic prioritization.
  * Many other routing and traffic policies, though not IEEE-standardized, are widely adopted by vendors for consistency.

This section focuses on **traffic filtering** and introduces core network policy concepts.

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

**Formally, traffic filtering ensures security, validation, and segmentation by allowing or blocking traffic based on predefined rules.**

**Practice**

Explore **practical ACL implementation** in traffic filtering and access control policies:

**How to configure standard ACLs on Cisco routers**\
[**https://itnetworkingskills.wordpress.com/2023/04/11/how-configure-standard-acls-cisco-routers/**](https://itnetworkingskills.wordpress.com/2023/04/11/how-configure-standard-acls-cisco-routers/)

#### Prioritize network traffic using QoS

Set up QoS (Quality of Service) policies on routers, switches, and firewalls to shape and prioritize traffic.&#x20;

QoS settings are vital in managing network traffic, ensuring priority is given to critical applications. Load balancing and bandwidth management further help in evenly distributing network traffic, preventing any single resource from becoming a bottleneck.

#### Honeypots

A honeypot is a security mechanism designed to detect, deflect, or study unauthorized access attempts in a network. It acts as a decoy system, appearing to be a legitimate target (e.g., a server, database, or IoT device) but is actually isolated and monitored to gather information about attackers. For example, you might set up a server that appears to be a financial database but actually has only fake records.&#x20;

Honeypots can exhaust attackers by making them interact with phoney systems. Further, since honeypots are not real systems, legitimate users do not ever access them and therefore you can turn on extremely detailed monitoring and logging there. When an attacker does access a honeypot, you can gather a lot of evidence to aid in your investigation. When properly deployed, honeypots enhance threat detection and incident response capabilities.

A honeynet can be deployed as a complementary defense mechanism. A honeynet is a fake network segment that appears to be a very enticing target. Some organizations set up fake wireless access points for just this purpose.

### **Types of Honeypots**

1. **Based on Interaction Level:**
   * **Low-Interaction Honeypots**
     * Simulate only limited services (e.g., fake SSH or HTTP ports).
     * Low risk, easy to deploy (e.g., **Honeyd**, **Kippo**).
     * Used for basic threat detection.
   * **High-Interaction Honeypots**
     * Fully functional systems that allow deep attacker interaction.
     * Capture detailed attack methods but are riskier (e.g., **Honeynets**, **Cowrie**).
2. **Based on Purpose:**
   * **Research Honeypots**
     * Used by cybersecurity researchers to study attack techniques.
     * Example: **Dionaea** (malware analysis).
   * **Production Honeypots**
     * Deployed in corporate networks to detect intrusions.
     * Example: **Canary Tokens** (tripwires for attackers).
3. **Specialized Honeypots:**
   * **Spam Honeypots** – Trap email harvesters (e.g., **Spamhole**).
   * **Database Honeypots** – Fake databases to detect SQLi attacks (e.g., **HoneyDB**).
   * **IoT Honeypots** – Mimic vulnerable IoT devices (e.g., **IoTPOT**).

### **How Honeypots Enhance Security**

* **Attack Detection:** Identify malicious activity without false positives.
* **Threat Intelligence:** Gather data on attacker behavior (TTPs).
* **Distraction:** Keep attackers away from real systems.
* **Incident Response:** Help analyze breaches and improve defenses.

#### Network Automation

Software-defined networking (SDN) is a relatively recent trend that can be useful both in placing\
security devices and in segmenting the network. Essentially, in an SDN, the entire network is virtualized,\
which enables relatively easy segmentation of the network. It also allows administrators to place virtualized security devices wherever they want.

Adopting SDN permits dynamic security policy adjustments in response to emerging threats. For example, Cisco DNA Center is a software-based network management and automation platform that helps organizations simplify, automate, and secure their networks. DNA Center is an SDN controller in SD-Access architecture, but it can also be used as a general network management tool even in networks that do not use SD-Access. DNA Center has two main roles. First, it is the SDN controller used in SD-Access. Second, it can be a network manager in a traditional network that is not using SD-Access. In this case, it acts as a central point to monitor, analyze, and configure the network.

#### **Effective Network Architecture**

When designing your network segregation strategy, device placement is critical. The simplest device to position is the firewall: it should be deployed at every network zone junction, ensuring each segment is protected. Fortunately, this is easier than it sounds—modern switches and routers include built-in firewall capabilities that only need activation and proper configuration. Another essential perimeter device is an anti-DDoS solution, which mitigates attacks before they impact the entire network. Behind the primary public-facing firewall, a web filter proxy should also be implemented.

For other devices, placement depends on your network’s structure. Load balancers, for example, should reside in the same segment as the servers they manage—whether in a DMZ for web servers or a private segment for database clusters.&#x20;

Network aggregation switches lack a fixed placement rule but are commonly used to consolidate bandwidth streams—for instance, optimizing throughput to and from a server cluster.

Finally, any internet-connected network must have a local router with NAT and DHCP, both for security and to prevent IP exhaustion. The router should be the sole device connected to the modem, with all other devices routing through it.

### Networking protocols

IPsec/GRE over IPsec, Encryption protocols/IEEE 802.11, DTP/VTP

Vulnerable protocols that transmit data in plaintext should be substituted with secure protocols to prevent exposure of credentials and configuration data in transit. For example, FTP, SNMP v1/v2c community strings, and Telnet should be replaced with FTPS, SFTP, and SSH. In SNMPv1 the strings are sent in clear text. NTPv3 and SMTPv3 both provide encryption, authentication, and message integrity functions. Organizations should assume attackers can see their unencrypted traffic and eliminate cleartext protocols wherever possible.

**Network Address Translation (NAT)** helps organizations overcome the limited availability of IPv4 addresses by allowing multiple devices on a private network to share a single public IP address. NAT works by converting private (internal) IP addresses—used within an organization—into publicly routable addresses for communication over the internet or other IP networks.

Furthermore, NAT hides internal IP addresses from the public Internet by translating them to a public IP address. NAT enhances network security by acting as an additional layer of defense alongside firewalls. Hosts within the protected private network can initiate outbound connections to external systems, but external devices cannot directly access internal hosts without passing through a NAT gateway. This obscures the internal network structure, making it harder for attackers to identify and target specific devices. Additionally, by reducing the number of exposed public IP addresses, NAT further complicates reconnaissance efforts by malicious actors.

Secure DNS services like Cloudflare’s offer enhanced privacy and security by encrypting DNS queries, which can protect against DNS eavesdropping and spoofing attacks, often providing faster response times and improved reliability compared to standard DNS services.

Configure and enforce strong encryption standards using IPsec or SSL/TLS for network communications.

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

### Risk assessment/security testing

Information security testing is performed in risk assessments and **compliance audits**. In fact, it is an essential part of both processes.

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

Conduct security audits: Perform penetration testing and vulnerability scanning using tools like Wireshark, Nmap, Nessus, or OpenVAS.

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

* Key industry cybersecurity risk mitigation methods span technologies, system/network design, and organizational and network policies

### References

Odom, W. (2020). Chapter 5. Securing Network Devices, CCNA 200-301 Official Cert Guide (pp. 86-105), Volume 2. Cisco Press.
