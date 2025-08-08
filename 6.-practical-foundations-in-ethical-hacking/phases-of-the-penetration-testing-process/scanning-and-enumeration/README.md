# Scanning and enumeration

### Scanning for Targets

Scanning is "the process of discovering systems on the network and taking a look at what open ports and applications may be running" (Walker, 2012, p. 86).&#x20;

The steps for a scanning methodology according to EC-Council's CEH curriculum are (Walker, 2012, pp. 86-87):

1. Identify live systems (finding out which IP addresses are actually alive). Something as simple as a ping can provide this. This gives you a list of what’s actually alive on your network subnet.
2. Discover open ports. Once you know which IP addresses are active, find what ports they’re listening on.
3. Identify the OS and services. Banner grabbing and OS fingerprinting will tell you what operating system is on the machines and which services they are running.
4. Scan for vulnerabilities. Perform a more focused look at the vulnerabilities these machines haven’t been patched for yet.&#x20;

#### Identifying Active Machines

The simplest and easiest way to check for live systems on a network is to take advantage of ICMP (Internet Control Message Protocol), i.e., pinging target hosts. ICMP is built into every TCP/IP device. ICMP presents information back to the sender in one of several ICMP types. The most common of these are Type 8 (Echo Request) and Type 0 (Echo Reply). Table 4-1 lists some of the more relevant message type codes.

<figure><img src="../../../.gitbook/assets/image (2) (2).png" alt="ICMP message types"><figcaption><p>Source: Walker (2012, p. 88)</p></figcaption></figure>

An ICMP Type 8 packet received by a host tells the recipient, “Hey! I’m sending you a few packets. When you get them, reply back with the same number so I know you’re there.” The recipient will respond with an ICMP Type 0, stating, “Sure, I’m alive. Here are the data packets you just sent me as proof!” (Walker, 2012, p. 87)

The associated responses provide detailed information about the recipient host. Consider, for example, an Echo Request (Type 8) sent to a host returning a Type 3. Code 7 would tell us whether the host is down. Code 0 would tell us whether the network route is missing or corrupt in our local route tables. Code 13 would tell us whether a filtering device, such as a firewall, is preventing ICMP messages altogether.

Combining pings to each and every address within a subnet range is known as a ping sweep. A ping sweep is the easiest method to identify active machines on the network, though it may not necessarily be the only or best option. Sometimes it's convenient to combine the search for active machines with a port scan.

Another option for identifying machines (not necessarily live ones, but ones that were live at some time) is called a list scan, performed by running a reverse DNS lookup on all IPs in the subnet.

In addition to the ping command on its own, several tools can be used for a ping sweep. Examples include Angry IP Scanner, Pinger, WS\_Ping, SuperScan, and Friendly Pinger.

#### Port Scanning: Identifying Open Ports and Running Services

Port scanning is "the method by which systems on a network are queried to see which ports they are listening to" (Walker, 2012, p. 92). Since well-known port numbers are associated with specific upper-layer protocols, we can tell a lot about what services a system is running by performing port scanning. A system is said to be "listening for a port" when it has that port open (Walker, 2012, p. 92).

All port scanners work by manipulating Transport Layer (TCP/UDP) flags and analyzing responses to identify active hosts and scan their ports remotely.

#### TCP and UDP Communication

So what is a TCP flag and how does TCP and UDP communication work?

Two TCP/IP-enabled hosts can use two data transfer methods to communicate with each other: connectionless and connection-oriented.

In connectionless communication the sender does not care whether the recipient currently has the bandwidth to accept the message or whether the recipient gets the message at all. The sender relies on other upper-layer protocols to handle any problems. At the transport layer, connectionless communication is accomplished with UDP. Examples of application protocols that make use of UDP are TFTP, DNS, and DHCP.&#x20;

In connection-oriented communication, which uses TCP, a sender first reaches out to a recipient to make sure the recipient is available before attempting to exchange any data. TCP establishes a connection through the use of header flags and the three-way handshake. The method involves three messages being sent between any two hosts. Six flags can be set in the TCP header. Depending on what a segment is intended to do, some or all of these flags would be set.

The TCP header flags are (Walker, 2012, p. 96):

• URG (Urgent) When this flag is set, it indicates the data inside is being sent out of band.\
• ACK (Acknowledgment) This flag is set as an acknowledgment to SYN flags. This flag is set on all segments after the initial SYN flag.\
• PSH (Push) This flag forces delivery of data without concern for any buffering.\
• RST (Reset) This flag forces a termination of communications (in both directions).\
• SYN (Synchronize) This flag is set during initial communication establishment. It indicates negotiation of parameters and sequence numbers.\
• FIN (Finish) This flag signifies an ordered close to communications.

**Nmap** &#x20;

nmap can perform many different types of scans (from simply identifying active machines to port scanning and enumeration) and can also be configured to control the speed at which a scan operates—in general, the slower the scan, the less likely you are to be discovered. It comes in both a command-line version and a GUI version (now known as Zenmap), works on multiple OS platforms, and can even scan over TCP and UDP. (Walker, 2012, p. 98)

Nmap syntax is fairly straightforward:&#x20;

nmap \<scan options> \<target>

The target for nmap can be a single IP address, multiple individual IPs separated by spaces, or an entire subnet range (using CIDR notation). For example, to scan a single IP, the command might look like&#x20;

nmap 192.168.1.100

whereas scanning multiple IPs would look like&#x20;

nmap 192.168.1.100 192.168.1.101

and scanning an entire subnet would appear as&#x20;

nmap 192.168.1.0/24

Starting nmap without any of the options runs a “regular” scan and provides all sorts of information for you. But to get really sneaky and act like a true ethical hacker, you’ll need to learn the option switches—and there are a bunch of them. Table 4-3 nmap Switches lists some of the more relevant nmap switches. (Walker, 2012, p. 98)

<figure><img src="../../../.gitbook/assets/image (14).png" alt="Nmap switches"><figcaption><p>Source: Walker (2012, p. 99)</p></figcaption></figure>

Generally speaking, there are seven generic scan types for port scanning (Walker, 2012, pp. 99-100):

• TCP Connect Runs through a full connection (three-way handshake) on all ports. Easiest to detect, but possibly the most reliable. Open ports will respond with a SYN/ACK, closed ports with a RST/ACK.\
• SYN Known as a “half-open scan.” Only SYN packets are sent to ports (no completion of the three-way handshake ever takes place). Responses from ports are the same as they are for a TCP Connect scan.\
• FIN Almost the reverse of the SYN scan. FIN scans run the communications setup in reverse, sending a packet with the FIN flag set. Closed ports will respond with RST, whereas open ports won’t respond at all.\
• XMAS A Christmas scan is so named because the packet is sent with multiple flags (FIN, URG, and PSH) set. Port responses are the same as with a FIN scan.\
• ACK Used mainly for Unix/Linux-based systems. ACK scans make use of ICMP destination unreachable messages to determine what ports may be open on a firewall.\
• IDLE Uses a spoofed IP address to elicit port responses during a scan. Designed for stealth, this scan uses a SYN flag and monitors responses as with a SYN scan.\
• NULL Almost the opposite of the XMAS scan. The NULL scan sends packets with no flags set. Responses will vary, depending on the OS and version, but NULL scans are designed for Unix/Linux machines.

Table 4-4 Network Scan Types correlates a scan type and what response to expect from an open or closed port.&#x20;

A quick-and-easy tip to remember is that all scans return an RST on a closed port, with the exception of the ACK scan, which returns no response. nmap handles all these scans, using the switches identified earlier, and more. (Walker, 2012, p. 100)

<figure><img src="../../../.gitbook/assets/image (18).png" alt="Network Scan Types"><figcaption><p>Source: Walker (2012, p. 100)</p></figcaption></figure>

#### Vulnerability Scanning

Vulnerability scanning involves using automated tools to identify security weaknesses in a system, network, or application. These scanners must:

* Stay updated with the latest known vulnerabilities.
* Avoid causing harm to the systems being scanned.

**Types of Vulnerability Scanners**

1. **Enterprise-Level Scanners**
   * Scan entire networks, generate reports, and help enforce patch compliance.
   * Example: **Retina CS** (by BeyondTrust).
2. **Targeted Scanners**
   * Focus on specific environments (e.g., Windows).
   * Example: **Microsoft Baseline Security Analyzer (MBSA)** – Checks missing patches on Windows machines.
3. **General-Purpose Scanners**
   * Some are effective, while others may not be reliable.

**Industry Standard: Nessus (by Tenable)**

* **Features:**
  * High-speed asset discovery, configuration auditing, malware detection, compliance checks (PCI, HIPAA, etc.).
  * Supports **credentialed (deep) and non-credentialed (remote) scans**.
  * Over **450 compliance templates** available.
* **Pricing:**
  * **$2,190/year** for Nessus Professional (7-day free trial available).
  * Enterprise version: **Security Center**.
* **Additional Capabilities:**
  * Detects viruses, backdoors, botnet communications, and malicious web services.

**Other Notable Vulnerability Scanners**

1. **GFI LanGuard**
   * Combines vulnerability scanning with **patch management**.
   * Useful for compliance and security assessments.
2. **Qualys FreeScan**
   * Specializes in **web application scanning** (OWASP Top 10 risks, malware detection).
   * Often referenced in certification exams.
3. **OpenVAS (Open Vulnerability Assessment System)**
   * **Free and open-source alternative to Nessus**.
   * Comparable (or superior) in functionality.

#### **Illustrative Comparison**

| **Scanner**         | **Type**           | **Key Features**                          | **Cost**       |
| ------------------- | ------------------ | ----------------------------------------- | -------------- |
| **Nessus**          | Commercial         | Comprehensive scanning, compliance checks | $2,190/year    |
| **OpenVAS**         | Free & Open-Source | Nessus alternative, robust scanning       | Free           |
| **GFI LanGuard**    | Commercial         | Vulnerability + patch management          | Paid (varies)  |
| **Qualys FreeScan** | Freemium           | Web app scanning, OWASP focus             | Free (limited) |

### Enumeration

Enumeration refers to listing off the items found within a specific target. After identifying open ports, we now want to find things like open shares and any easy-to-grab user account information. We can use a variety of tools and techniques, many of which bleeds over from scanning.&#x20;

Enumeration should be performed on every system found on the target network, regardless of operating system. However, because Windows machines will likely make up the majority of the targets, it would helpful to spend a little time on them—to learn some of the basics of Windows’ design and security features.

#### Windows Security Basics

Everything in a Windows system runs within the context of an account. An account can be that of a user, running in something called user mode, or the system account, which runs in kernel mode. Actions and applications running in user mode are easy to detect and contain. Those running in kernel mode, though, can be hidden and run with absolute authority. Knowing this, a hacker must attempt to get code running in kernel mode as often as possible. (Walker, 2012, p. 108)

* **User Mode**:
  * Standard user accounts operate in **user mode**, where actions are restricted and monitored.
  * Malicious code running here is easier to detect and contain.
* **Kernel Mode (System Account)**:
  * The **SYSTEM account** operates in **kernel mode**, the highest privilege level.
  * Attackers aim to execute code here because it allows **stealth, persistence, and full system control**.

User rights are granted via an account’s membership within a group and determine which system tasks an account is allowed to perform. Permissions are used to determine which resources an account has access to. The method by which Windows keeps track of which account holds what rights and permissions comes down to SIDs and RIDs. (Walker, 2012, p. 109)

* **Rights**: Define **what system tasks** an account can perform (e.g., shutting down the system, changing the time).
  * Granted via **group membership** (e.g., Administrators, Power Users).
* **Permissions**: Define **access to resources** (files, folders, registry keys).
  * Example: A user may have **rights** to install software but **no permission** to modify system files.

**SIDs and RIDs (Security & Resource Identifiers)**

* **SID (Security Identifier)**:
  * Unique identifier for users, groups, and computers.
  * Format: **`S-1-5-21-[Domain]-[RID]`**
    * **S** = Security ID
    * **1** = Revision level
    * **5** = Authority (Windows)
    * **21-\[Domain]** = Domain/computer identifier
    * **\[RID]** = User/group identifier
* **RID (Resource Identifier)**:
  * The last part of the SID, indicating a specific account.
  * **Well-known RIDs**:
    * **500** → Administrator
    * **501** → Guest
    * **1000+** → Regular users (incremented sequentially, even if usernames are reused).

**Example**:

* `S-1-5-21-3874928736-367528774-1298337465-500` → **Local Administrator**
* `S-1-5-21-3984762567-8273651772-8976228637-1014` → **14th user created** (RID 1014)

**Password Storage (SAM Database)**

* **Local Passwords**: Stored in **`C:\Windows\System32\Config\SAM`** (encrypted).
* **Domain Passwords**: Handled by **Active Directory Domain Controllers**.
* **Security Implication**:
  * Attackers target the **SAM file** (e.g., via offline attacks like **Pass-the-Hash** or **SAM extraction**).
  * Domain attacks focus on **compromising the Domain Controller** (e.g., **Kerberoasting** or **DCSync**).

**Note**

* **Privilege Escalation**: Moving from **user mode → kernel mode** is a key attack vector.
* **SID/RID Manipulation**: Attackers may spoof or exploit well-known SIDs (e.g., RID 500 for Admin).
* **Credential Attacks**: Dumping the **SAM database** is a common post-exploitation step.

#### Enumeration Techniques

### **1. Banner Grabbing**

**Definition:** Banner grabbing retrieves service information (e.g., software version) from open ports by analyzing responses to connection requests.

#### **Methods:**

* **Telnet:**
  * Example: `telnet <IP> 80` (HTTP) or `telnet <IP> 25` (SMTP)
  * May reveal server software (e.g., `IIS/5.0`, `Microsoft Exchange`).
* **Netcat (nc):**
  * Example: `nc <IP> 80`
  * A versatile tool for reading/writing network data.
* **Port Scanners (Nmap, SuperScan):**
  * Many scanning tools include banner grabbing functionality.

#### **Notes:**

* **Active Banner Grabbing:** Sends crafted packets to analyze responses.
* **Passive Banner Grabbing:** Relies on sniffing traffic, error messages, or page extensions.

***

### **2. NetBIOS Enumeration**

**Definition:** Exploits the NetBIOS protocol to gather Windows network details (e.g., shares, users, roles).

#### **Tools & Techniques:**

* **`nbtstat` (Built-in Windows Tool):**
  * `nbtstat -n` → Local NetBIOS names.
  * `nbtstat -A <IP>` → Remote system’s NetBIOS table.
  *   Example output:

      text

      ```
      Name               Type         Status  
      ---------------------------------------  
      WORKSTATION      <00>  UNIQUE      Registered  
      WORKGROUP        <1E>  GROUP       Registered  
      ```

      * `<00>` = Workstation service.
      * `<20>` = File/print sharing.
      * `<1D>` = Master browser.
* **Other Tools:**
  * **SuperScan** (Port scanner + NetBIOS enumerator).
  * **Hyena** (GUI tool for shares, users, services).
  * **Winfingerprint, NSAuditor** (Additional enumeration tools).

#### **Notes:**

* NetBIOS **does not work with IPv6**.
* Focus on **NetBIOS codes (e.g., `<00>`, `<20>`)** and tools.

***

### **3. SNMP Enumeration**

**Definition:** Exploits **Simple Network Management Protocol (SNMP)** to extract device info via **Management Information Base (MIB)** queries.

#### **Key Concepts:**

* **Community Strings (Default Passwords):**
  * **Read-Only:** `public`
  * **Read-Write:** `private`
* **SNMP Versions:**
  * **SNMPv1/v2:** Cleartext community strings.
  * **SNMPv3:** Encrypted (more secure).
* **MIB (Management Information Base):**
  * Stores device data (OS, configs, usage stats).
  * Accessed via **OIDs (Object Identifiers)**.

#### **Tools:**

* **Engineer’s Toolset (SolarWinds)**
* **SNMPScanner**
* **OpUtils 5**
* **SNScan**

***

### **4. LDAP Enumeration**

**Definition:** Queries **Lightweight Directory Access Protocol (LDAP)** for directory info (users, org structure, system data).

#### **Key Points:**

* Runs on **TCP 389**.
* Used in **Active Directory (AD)** environments.
* Returns structured data via **Basic Encoding Rules (BER)**.

#### **Tools:**

* **Softerra LDAP Browser**
* **JXplorer**
* **Active Directory Explorer (Windows)**

***

### **Conclusion**

Enumeration provides critical details for ethical hackers, including:\
✅ **Banner Grabbing** → Service versions.\
✅ **NetBIOS** → Windows shares & roles.\
✅ **SNMP** → Device configurations.\
✅ **LDAP** → User/org data.

**Notes**

* Know **tools (nbtstat, netcat, SNMP scanners)**.
* Understand **default credentials (SNMP, NetBIOS)**.
* Differentiate **active vs. passive banner grabbing**.
