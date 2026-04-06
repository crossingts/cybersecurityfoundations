---
description: >-
  This section describes the phases of the penetration testing process, the
  goals of each phase, and key technologies used
---

# Phases of the penetration testing process

## Learning objectives

* Describe the phases of the penetration testing process
* Describe best practices for writing the penetration test report

This section describes the phases of the penetration testing process—planning, reconnaissance, scanning and enumeration, gaining access (exploitation) and privilege escalation, maintaining access, covering tracks, and reporting—including the goals of each phase and key technologies used. Further, this section describes best practices for writing the penetration test report.

## Topics covered in this section

* **Introduction**
* **Reconnaissance**
* **Scanning and enumeration**
* **Gaining access**
* **Maintaining access**
* **Covering tracks**
* **The penetration test report**

### Introduction

The penetration testing process can be broken down into several phases: planning or preparation, reconnaissance, scanning and enumeration, gaining access (exploitation) and privilege escalation, post-exploitation (maintaining access and covering tracks), and reporting (NIST SP 800-115, 2008; Walker, 2012, 2017).

<figure><img src="../../.gitbook/assets/Ethical-hacking-phases.jpg" alt="Ethical-hacking-phases"><figcaption><p>The seven phases of the ethical hacking process</p></figcaption></figure>

In the planning phase, rules are identified, management approval is finalized and documented, and testing goals are set. The planning phase sets the groundwork for a successful penetration test. No actual testing occurs in this phase. (NIST SP 800-115, 2008, p. 5-2)

In the words of Walker (2012), "There are three main phases to a pen test—preparation, assessment, and conclusion" (p. 8). The preparation phase defines the timeline and scope of the penetration test, "the types of attacks allowed, and the individuals assigned to perform the activity" (p. 8).

The assessment phase (sometimes also known as the security evaluation phase) is exactly what it sounds like—the actual assaults on the security controls are conducted during this time. Lastly, the conclusion (or post-assessment) phase defines the time when final reports are prepared for the customer, detailing the findings of the tests (including the types of tests performed) and many times even providing recommendations to improve security. (Walker, 2012, p. 8)

Penetration tests should be seen as targeted exercises. Test objectives and the specific machines or applications to be tested are all specified upfront in a contractual agreement between the client and the ethical hacker during the planning phase. Each test objective will have its own set of parameters and processes. The agreement provides a precise description, typically in the form of specific IP addresses, domain names, or cloud instance identifiers, of the systems to be evaluated. "Precision is critical, as a minor error could lead to testing the wrong system or, in the worst case, the systems of an unrelated organization" (Palmer, 2001, p. 775).

For Walker (2017), the the assessment phase or “act of hacking” is comprised of five main phases: 1) Reconnaissance, which involves the steps taken to gather evidence and information on the target; 2) scanning and enumeration, which takes the information gathered in reconnaissance and applies tools and techniques to gather more in-depth information on the targets; 3) gaining access, where “true attacks are leveled against the targets enumerated in the second phase”; 4) maintaining access, where hackers attempt to ensure they have a way back into the compromised system; and 5) covering tracks, where “attackers attempt to conceal their success and avoid detection by security professionals” (p. 36). In practice, assessment phases run concurrently and continuously throughout a penetration test (Walker, 2017).

For the purposes of this section, ethical hacking refers to the comprehensive process of 1) planning or preparing for a penetration test, 2) performing a penetration test (what Walker, 2012/2017 and EC-Council identify as the assessment phase of the penetration test and which is common to both malicious and ethical hackers), and 3) reporting on the findings of the penetration test. This comprehensive process is illustrated in the diagram "The seven phases of the ethical hacking process".

Typical penetration testing steps:

1. **Reconnaissance** – predominantly passive information gathering.
2. **Scanning** – active probing (mostly Nmap) for host discovery, port scanning, and service/OS detection.
3. **Enumeration** – extraction of information from discovered services (user accounts, shares, SNMP data, etc.). This may uncover weak configurations that could be exploited immediately (e.g., default credentials, anonymous access).
4. **Vulnerability Assessment** – using automated tools (OpenVAS, Nessus, etc.) to identify known vulnerabilities (CVEs), missing patches, and misconfigurations beyond what enumeration revealed. This step is systematic and produces a prioritized list of weaknesses.
5. **Exploitation** (gaining access and privilege escalation) – attempting to exploit the discovered weaknesses (whether from enumeration or vulnerability scanning) to gain access.
6. **Post‑Exploitation** – maintaining access and covering tracks.

### Reconnaissance

Penetration tests begin with an extensive information gathering phase to build a profile of the target user or system to determine entry points. Reconnaissance can be passive or active, but most reconnaissance activities are passive in nature. Passive reconnaissance involves gathering information from the public domain (OSINT) in places like Internet registries, Google, newspapers, and public records. At this stage "the target does not even know generally that they are the subject of surveillance". Active reconnaissance includes "anything that requires the hacker to interact with the organization", including social engineering activities (Walker, 2017, p. 45).

OSINT involves collating technical information on an organization’s public-facing systems. “Internet registries, coupled with services such as Shodan or VPN Hunter, can highlight and identify an organization’s Web servers, mail servers, remote access endpoints and many other Internet-facing devices.” During OSINT, the penetration tester identifies potential weaknesses and entry points across the organization’s security posture, including its network, applications, website, wireless networks, physical facilities, cloud-based systems, and employees.

Automated OSINT is used by hackers and penetration testers to gather and analyze intelligence about a specific target from social networks, including names, online handles, jobs, friends, likes/dislikes, interactions, locations, pictures, etc. Recon-ng and Maltego are examples of such automated OSINT tools, designed to streamline the collection, analysis, and organization of intelligence across multiple data sources.

Faircloth (2011) proposes an iterative five stage reconnaissance phase: Intelligence Gathering, Footprinting, Human Recon, Verification, and Vitality. Building on Faircloth (2011), follows is a table summarizing the stages of the reconnaissance phase. The first four stages—Intelligence Gathering, Footprinting, Human Recon, and Verification—rely exclusively on passive reconnaissance techniques, gathering information from public sources without directly interacting with the target’s systems. The Vitality stage introduces active reconnaissance, using direct probes to confirm reachability, and serves as the transition into the enumeration phase.

**Table: Stages of Reconnaissance (Adapted from Faircloth, 2011)**

| Stage                      | Objectives                                                                                                                                         | Output                                                                                                                                                                                                         | Tools                                                                                                                                               |
| :------------------------- | :------------------------------------------------------------------------------------------------------------------------------------------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :-------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Intelligence Gathering** | To learn as much about the target, its business, its organizational structure, and its business partners as possible.                              | The output of this phase is a list of company names, partner organization names, and DNS names which reflect the entire target organization including all of its brands, divisions, and local representations. | Search engines; Financial databases; Business reports; ICANN/WHOIS; RWHOIS; Domain name registries and registrars; Web archives; Data mining tools. |
| **Footprinting**           | To mine as many DNS host names as possible from the domains or company names collected and translate those into IP addresses or IP address ranges. | The output of this phase is a list of DNS host names, IP addresses, and IP address ranges.                                                                                                                     | DNS; ICANN/WHOIS; DIG; SMTP; Data mining tools; Censys.                                                                                             |
| **Human Recon**            | To analyze the human perspective of the target and gain as much intelligence as possible about the people associated with the organization.        | The output of this phase is a list of names, job titles, contact information, and other personal details about the people associated with the organization.                                                    | Search engines; Email lists and web site posts; Social networking services; Publicly available records.                                             |
| **Verification**           | To confirm the validity of information collected in the prior phases.                                                                              | This phase rarely produces new output, but can clean up existing output by removing invalid data. Some additional information can sometimes be gathered as a side-product of the verification.                 | DNS; WHOIS; DIG.                                                                                                                                    |
| **Vitality**               | To confirm the reachability of the IP addresses identified in prior phases. This is a phase which spreads between reconnaissance and enumeration.  | The output of this phase is a list of IP addresses from prior phases which have been confirmed as reachable.                                                                                                   | PING; Port scanners; Mapping tools.                                                                                                                 |

There is no clear cutoff point between passive and active intelligence gathering techniques. The definition of passive is not always consistent across the field. The confusion includes whether the information gathering can be performed without the knowledge of the organization under investigation (i.e., remains stealthy) and whether the process of testing can be traced back to the tester's location or IP address.

### Scanning and enumeration

Building on the information gathered during reconnaissance, security analysts now begin the discovery phase to gather in-depth technical details about the targets. Scanning and enumeration can be "something as simple as running a ping sweep or a network mapper to see what systems are on the network, or as complex as running a vulnerability scanner to determine which ports may be open on a particular system" (Walker, 2012, p. 9).

While recon may find that a network has 500 machines connected to a single subnet inside a building, scanning would uncover which ones are Windows machines and which ones are running FTP, web servers, or remote administration services. Enumeration would then extract usernames, share names, and configuration details from those services.

**Scanning vs Enumeration Key Goals and Open Source Tools**

| Scanning                                      | Enumeration                                                   |
| --------------------------------------------- | ------------------------------------------------------------- |
| **"What's alive and what ports are open?"**   | **"What can I extract from those services?"**                 |
| Broad, network-level discovery                | Targeted, service-specific probing                            |
| Identifies targets and potential entry points | Extracts data: usernames, shares, configurations              |
| **Tools:** `nmap`, `masscan`, `arp-scan`      | **Tools:** `enum4linux`, Metasploit aux modules, `ldapsearch` |

The core technical activities of the **scanning and enumeration phase** move from identifying potential targets to actively discovering and cataloging detailed information about them. 
This process typically follows a logical sequence:

- Host discovery – to identify live hosts on a network. 
- Port scanning – to discover open ports.
- Service and version detection – basic (manual) enumeration via banner grabbing.
- OS fingerprinting – to identify a host's operating system.
- Enumeration (beyond banner grabbing) – through Nmap’s enumeration scripts.
- Vulnerability scanning (optional) using vulnerability scanners – can be run after port scanning (fast) or after enumeration (stealthier but slower).
- Vulnerability identification – map findings from enumeration and vulnerability scanning (whether using dedicated vulnerability scanners like OpenVAS or Nmap’s NSE vulnerability scripts) to known CVEs, misconfigurations, and weaknesses.

**Nmap (Network Mapper)** 

Nmap is a key technology used in the discovery phase (scanning and enumeration) of the penetration testing process. Nmap sends custom ICMP, TCP, and UDP packets to probe a target. One purpose of these probes is host discovery – identifying live hosts on a network (hence its original name, network mapper). Other probes perform port scanning and service/version detection. The target’s responses form unique patterns (sometimes called fingerprints), which Nmap uses to identify running software, protocols, and the operating system. Because its primary function is to scan networks and enumerate open ports and services, Nmap is popularly referred to as a network scanner.

Nmap is a versatile tool. It can be used as a:

- **Network mapper** – highlights its ability to discover hosts on a network and map out the topology, IP ranges, and relationships between devices. 
- **Network scanner** – describes its most common use: probing specific targets to identify open ports, running services, operating systems, and potential vulnerabilities.

Typical uses of Nmap:

- Auditing the security of a device or firewall by identifying the network connections which can be made to it or through it.
- Network inventory, network mapping, maintenance, and asset management.
- Response analysis and response time measurement by generating traffic to hosts on a network.
- Finding and exploiting vulnerabilities in a network.
- Nmap can provide further information on targets, including configuration weaknesses, reverse DNS names, device types, and MAC addresses.

Nmap is a key technology used in the discovery phase (scanning and enumeration) of the penetration testing process. This phase entails host discovery, port scanning, service and version detection, OS fingerprinting, and enumeration of discovered hosts and services.

These features are extensible by scripts that provide more advanced service detection, vulnerability detection, and even exploitation.

Basic Nmap syntax:

```
nmap <scan options> <target>
```

The following command runs a basic host discovery and a fast port scan using Nmap.

```
nmap -F <target>
```

Here’s what each part does:

- **`nmap`** – the command-line tool used for discovering live hosts and identifying open ports/services.
- **`-F`** – stands for fast mode. Nmap scans only the top 100 most frequently used ports (e.g., 22/SSH, 80/HTTP, 443/HTTPS, 3389/RDP, etc.), rather than scanning all 65,535 ports. This makes the scan much quicker, which is useful for a preliminary reconnaissance.
- **`<target>`** – the target you specify. This can be an IP address (e.g., `192.168.1.10`), a hostname (e.g., `example.com`), or a network range (e.g., `192.168.1.0/24`).

When you run `nmap -F <target>`, Nmap will send:

- An **ICMP echo request** (ping)
- A **TCP SYN to port 443** (HTTPS)
- A **TCP ACK to port 80** (HTTP)
- An **ICMP timestamp request** (if the user has appropriate privileges)

First, the four probes (host discovery) to find live hosts. Then, if a host is alive, Nmap performs a TCP SYN scan (`-sS`) by default – or TCP connect scan (-sT) if run without privileges – on those 100 ports to identify open ports.

If any of these get a response, Nmap considers the host “up” and proceeds to the fast port scan to determine which ports are open. 

Every Nmap scan (including `-F`, `-sS`, `-sT`, etc.) first runs host discovery using those four probes, unless you override it with `-Pn` (skip host discovery). 

Host discovery is a default behavior unless you add other flags, like `-Pn` to skip host discovery or `-sn` (no port scan) to do only host discovery.

The command outputs a list of open ports (limited to top 100) on live hosts and often the service names associated with them (based on port number guesses).


**Scanning:**

**Classic scanning activities that can be performed with Nmap:**

 - Network scanning (`-sn`) to find live hosts.
 - Port scanning (`-sS`, `-sT`, etc.) to identify open ports.
 - Service/version detection (`-sV`) (basic enumeration via banner grabbing) 
 - OS fingerprinting (`-O`).  

#### Host discovery – to identify live hosts on a network

Nmap is used to discover live hosts on a network and then probes those hosts to identify which ports are open (listening), closed, or filtered. 

The host discovery phase uses a combination of **ICMP and TCP** packets to determine whether a target is alive.

Nmap sends the four probes ICMP echo, SYN to 443, ACK to 80, timestamp request to identify live hosts.

```bash
nmap -sn <target>
```



**`nmap -sn 192.168.1.0/24`** – Performs a ping sweep (**no port scan**) to discover which hosts are alive (network mapping) on the subnet `192.168.1.0/24`. 

Syntax Explanation

| Part             | Meaning                                                                                                                                                                                                                   |
| ---------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `nmap`           | The command-line network scanning tool.                                                                                                                                                                                   |
| `-sn`            | **Ping scan (no port scan)**. Sends ICMP echo requests, TCP SYN to port 443, TCP ACK to port 80, and ICMP timestamp requests to determine **which hosts are online**. Does **not** probe any ports beyond this discovery. |
| `192.168.1.0/24` | Target network in CIDR notation. `/24` means a subnet mask of `255.255.255.0`, so addresses from `192.168.1.1` to `192.168.1.254` are scanned.                                                                            |

Nmap sends an ICMP echo request to a target host to check connectivity. If an ICMP echo reply is received, this confirms the host is live. Nmap sends a TCP SYN to port 443 on the target host. If it receives a SYN‑ACK, it can be assumed that the port is open. However, `-sn` **does not** care whether port 443 is open – it only uses the response (SYN‑ACK or RST) to infer that the host is alive. Even a RST (if port is closed) still confirms the host exists.

By default, `nmap -sn` sends **four** probes (on modern versions):

1. ICMP echo request
2. TCP SYN to port 443
3. TCP ACK to port 80
4. ICMP timestamp request

Why does Nmap send a TCP ACK (not TCP SYN) to port 80? Many firewalls and host-based filters **block incoming SYN packets** (the start of a new connection) but allow **already‑established** traffic. A packet with only the ACK flag set appears to belong to an existing TCP connection. Some firewalls will pass an ACK packet even if they would drop a SYN packet to the same port.

Why port 80 specifically? Port 80 (HTTP) is almost always open on web servers, and many networks allow outbound HTTP traffic. It's a common “trusted” port where ACK packets often pass through stateful firewalls that track outbound connections. Nmap uses this probe to detect hosts behind firewalls that block ICMP and SYN scans. So Nmap sends an **ACK** deliberately – not a SYN – because an ACK can slip past firewall rules that would drop a SYN.


#### Port scanning – determine whether ports are open, closed, or filtered

Example: `nmap -p- 192.168.1.10` scans to determine what ports are open, closed, or filtered. It does **not** retrieve the **banner** or version string. 


**Port scanning** 

Port scanning refers to probing each port (sending prognostic packets to each port) to see whether it is open, closed, or filtered.
Open ports represent potential communication channels to running services.

if a host is alive, Nmap performs a TCP SYN scan (`-sS` by default) to identify open ports or a full TCP scan (-sT) if no root privileges
-sS: TCP SYN stealth scan (default with root)
-sT: TCP connect scan (default without root)

Example: 
**nmap -p22 192.168.1.1** scans to determine whether port 22 is open, closed, or filtered. 
It does **not** retrieve the **banner** or version string. 

At this stage, running services are **inferred** by port number (e.g., port 80 suggests HTTP), but not confirmed.



#### Service and version detection

Perform detailed port and service scans on a single machine.

Example 1:
nmap -sV -p22 192.168.1.1

Example 2: 
nmap -sV -p- 192.168.1.10

#### Service and version detection Example 1:

nmap -sV -p22 192.168.1.1

Service and version detection = basic enumeration 
e.g., 
by running `nmap -sV -p22 192.168.1.1`

This step involves actively probing open ports to **confirm the actual service type** (e.g., SSH vs a custom service on port 22) and extracting the **software name and version number** (e.g., `OpenSSH 8.9p1`).

**Service detection** (often called service fingerprinting): detect services on open ports—such as SSH (Secure Shell daemon), HTTP web server, RDP (Remote Desktop service), or SMB (Server Message Block).

Service detection **confirms** what service is running on open ports (e.g., SSH, but also which SSH daemon = OpenSSH = software name, and optionally its version). This is part of `-sV` in Nmap.

**Version detection** is the part of `-sV` that extracts the specific version number (e.g., OpenSSH 8.2p1).
This may also reveal **hints** about the underlying operating system, though full **OS fingerprinting** is a separate technique.


`-sV` (service/version scanning) – Scans the application layer: after finding open ports, it connects to those ports and sends probes to identify the specific service, version, and sometimes configuration (e.g., `OpenSSH 8.9p1`).

running `nmap -sV -p22 192.168.1.1`:
1. **Host discovery** – Nmap sends the four probes (ICMP echo, SYN to 443, ACK to 80, timestamp request) to see if `192.168.1.1` is alive.
2. **If the host responds** (any reply), Nmap then scans port 22 to check if it is open.
3. **If port 22 is open**, `-sV` performs version detection to identify the service (e.g., SSH version):

**`-sV` performs its own full TCP handshake (or application‑layer probe) for each open port, regardless of whether the preceding port scan used `-sS` (SYN) or `-sT` (TCP connect).**
(whether -sS or -sT is used for the port scanning)

> _On running `nmap -sV -p22 192.168.1.1`, `-sV` performs a full TCP handshake (or application‑layer probe) for each open port, to elicit a banner or response from the service._

For TCP services like SSH, `-sV` completes a full three‑way handshake (SYN, SYN‑ACK, ACK). Once the connection is established, Nmap reads the banner (if the server sends one immediately, as SSH does) or sends its own probe. The phrase “or application‑layer probe” correctly acknowledges that some services require Nmap to send data first (e.g., HTTP: `GET /`).

so, Nmap **does** complete a full TCP handshake (three-way) to **elicit a banner** or response from the service, then:

- Waits for a banner (if the service sends one)
- Sends service‑specific probe strings (e.g., `SSH-` for SSH, `HEAD / HTTP/1.0\r\n\r\n` for HTTP, etc.)
- Analyzes the response to determine service name and version.

That response **confirms** the actual service type (e.g., SSH), reveals the SSH software (e.g., OpenSSH), version number, and sometimes OS **hints**.

A typical SSH banner might read `SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5`, revealing the software (`OpenSSH`), version (`8.2p1`), and often the underlying OS distribution (`Ubuntu`). Similarly, an HTTP `GET` request to a web server on port 80 might return a header such as `Server: nginx/1.18.0`, directly identifying the software and version. 

For **UDP** or **non‑TCP** services, Nmap sends custom probes without a connection handshake.

> _When Nmap performs version detection (`-sV`), Nmap initiates a connection to the open port and sends a series of carefully crafted probes (e.g., specific protocol requests, malformed packets, or known commands). The target’s response—its banner, error messages, or behavior—acts as a fingerprint. Nmap compares this fingerprint against its internal database of known service signatures to identify the exact software and version._

The latter paragraph describes exactly how `-sV` works. The only minor nuance is that for some services (e.g., SSH), the server sends its banner _before_ Nmap sends any probe. Nmap still reads that banner as part of the fingerprint. The statement “sends a series of carefully crafted probes” is still correct as a general description; Nmap may send probes after receiving the initial banner to refine the fingerprint.

> _The TCP handshake establishes a connection; the probes are the application‑layer questions Nmap asks once connected. Both are part of version detection, but they serve different purposes._

They are distinct steps in sequence:

|Step|What happens|Example|
|---|---|---|
|**TCP handshake**|Low‑level connection establishment (SYN → SYN‑ACK → ACK).|Nmap and target agree on a TCP connection.|
|**Probes**|Application‑layer data sent _after_ the handshake (or in some cases, the handshake itself is not a probe).|For HTTP: `GET / HTTP/1.0`; for SMTP: `HELO test`; for SSH: Nmap reads the server’s banner, then sends its own SSH version string.|

**The probes are not the handshake.** The handshake opens the channel; the probes are the questions Nmap asks once the channel is open.

However, there is a subtle exception: some `-sV` probes can be sent _before_ a full handshake for certain services (e.g., a SYN scan with a TCP option that triggers a specific response). But in standard usage, the handshake happens first, then the probes.


Example 1: SSH (Port 22)

Service and version detection, 
e.g., 
nmap -sV -p22 192.168.1.1

A typical SSH banner might read `SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5`

- **Probe:** Nmap connects to port 22 and reads the initial banner sent by the SSH daemon.
- **Response:** The SSH server sends its version string:
    
    text
    
    SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5
    
- **Determination:** The banner reveals the exact software (`OpenSSH`) and version (`8.2p1`), including the operating system patch level (`Ubuntu-4ubuntu0.5`). Even if the banner is modified, Nmap can use additional probes (e.g., requesting specific cryptographic algorithms) to fingerprint the version based on supported ciphers or key exchange methods.

Example 2: HTTP Web Server (Port 80)

nmap -sV -p80 192.168.1.1

- **Probe:** Nmap sends an HTTP `GET /` request with a custom User-Agent.
- **Response:** The web server replies with an HTTP header:
    
    text
    
    Server: nginx/1.18.0 (Ubuntu)
    
- **Determination:** The `Server` header explicitly states the software (`nginx`) and version (`1.18.0`). Even if the header is suppressed or altered, Nmap can infer the version from subtle differences in how the server handles malformed requests (e.g., response codes, header ordering, or default error pages).

**Summary:**

| Service | Probe Sent       | Response Clue                                 | Extracted Info   |
| ------- | ---------------- | --------------------------------------------- | ---------------- |
| SSH     | TCP connection   | `SSH-2.0-OpenSSH_8.2p1`                       | OpenSSH 8.2p1    |
| HTTP    | `GET / HTTP/1.0` | `Server: nginx/1.18.0`                        | nginx 1.18.0     |
| SMTP    | `HELO test`      | `220 mail.example.com ESMTP Postfix (Ubuntu)` | Postfix (Ubuntu) |

#### Service and version detection Example 2: 

nmap -sV -p- 192.168.1.10

For example, running nmap -sV -p- 192.168.1.10 performs a comprehensive scan of the single host 192.168.1.10.

**`nmap -sV -p- 192.168.1.10`** – Performs a **comprehensive** scan of the single host `192.168.1.10`.
`-p-` scans all 65,535 TCP ports, and 
`-sV` enables version detection to identify service names and versions through **banner grabbing**

Syntax Explanation

| Part           | Meaning                                                                                                                                                                                                                                                                                |
| -------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `nmap`         | The command-line network scanning tool.                                                                                                                                                                                                                                                |
| `-p-`          | **Scan all ports to discover open ports via default SYN scan or TCP connect scan if run without privileges**. The hyphen without a range means ports 1 through 65535 (all TCP ports). Equivalent to `-p 1-65535` (terminology tip: here `1-65535` is the argument to the `-p` option). |
| `-sV`          | **Version detection via full TCP handshake for TCP services**. After discovering open ports, Nmap connects to the open ports to probe the services to determine their exact name, version, and sometimes additional information (e.g., `Apache httpd 2.4.41`).                         |
| `192.168.1.10` | Target IP address – a single host.                                                                                                                                                                                                                                                     |

Running `nmap -sV -p- 192.168.1.10`:
1. **Host discovery** – Nmap sends the four probes (ICMP echo, SYN to 443, ACK to 80, timestamp request) to see if `192.168.1.10` is alive.
2. **If the host responds** (any reply), Nmap then scans all ports (via default SYN scan) to check if they are open.
3. **If ports are open**, `-sV` performs version detection to identify the services (e.g., SSH version).

When you run `nmap -sV -p- 192.168.1.10`, Nmap determines which ports are **open**, **closed**, or **filtered** using a **port scanning technique (by default, SYN scan `-sS` if run with root privileges, otherwise TCP connect scan `-sT`).**  Only after that does it perform version detection (`-sV`) on the open ports.

-sS: TCP SYN stealth scan (default with root)
-sT: TCP connect scan (default without root)

Implied in the command syntax `nmap -sV -p- target` is the existence of options (flags) -sS and -sT: 

- If you run Nmap with **root/administrator privileges**, it uses the **SYN scan** (`-sS`).
- If you run **without privileges**, it falls back to the **TCP connect scan** (`-sT`).

So the syntax can be made more explicit by adding `-sS` or `-sT`. For example, if requesting a SYN scan (stealth, faster) along with version detection:

nmap -sS -sV -p- 192.168.1.10

sudo nmap -sS -sV -p- 192.168.1.10 # SYN scan (requires root)

nmap -sT -sV -p- 192.168.1.10 # TCP connect scan (no root needed)

If you run `nmap -sS -sV -p- 192.168.1.10` **without sudo or root privileges**, Nmap will not perform a SYN scan (`-sS`). Instead, it will automatically **fall back** to a TCP connect scan (`-sT`) and typically display a warning message like:

> _"SYN scan requires root privileges. Falling back to TCP connect scan."_

**`-sV` performs its own full TCP handshake (or application‑layer probe) for each open port, regardless of whether the preceding port scan used `-sS` (SYN) or `-sT` (TCP connect).**
(whether -sS or -sT is used for the port scanning)

Here’s how Nmap distinguishes between a **listening (open)** port and a **filtered** port.

1. Listening (Open) Port

A port is considered _open_ (listening) if the target machine actively responds to a connection attempt in a way that indicates acceptance.

- **SYN scan (`-sS`)** : Nmap sends a TCP packet with the SYN flag set.
    
    - **Expected response from an open port:** `SYN-ACK` (the target agrees to establish a connection).
    - Nmap immediately replies with a `RST` to tear down the half-open connection (making the scan stealthy).
        
- **TCP connect scan (`-sT`)** : Nmap completes the full three-way handshake (`SYN` → `SYN-ACK` → `ACK`), then closes the connection with `RST` or `FIN`.

> **Key takeaway:** Receiving a `SYN-ACK` (or completing a handshake) proves the port is **listening**.

2. Filtered Port

A port is marked _filtered_ when Nmap receives **no response** or an **ICMP error message** that suggests a firewall or packet filter is blocking the probe.

- **No response (timeout)** : Nmap sends the SYN packet but never receives a reply (no SYN-ACK or not even a `RST`). After retransmissions (default 10 seconds), it assumes the packet was dropped by a firewall. This is the most common indication of a filtered port.
- **ICMP unreachable (type 3, code 0, 1, 2, 3, 9, 10, 13)** : The target network or an intermediate firewall returns an ICMP error like “administratively prohibited” (code 13) or “host unreachable” (code 1). This also results in `filtered` state.

3. Closed port (not listening, but no filter)

The target sends a `RST` packet. This means the host exists and the packet reached it, but no process is listening. Nmap marks this as `closed`, not `filtered`.



**OS Fingerprinting**

The OS information derived from an SSH banner is often just the underlying distribution (e.g., Ubuntu), not a full OS fingerprint. For accurate OS detection, Nmap uses TCP/IP stack fingerprinting (`-O`), which analyzes packet responses in a different way.

**`-O` (OS fingerprinting)** – Scans the _host’s operating system_ by sending a series of crafted packets and analyzing the responses (TCP window size, IPID, initial sequence numbers, etc.) to guess the OS (e.g., `Linux 5.15` or `Windows 10`).

TCP/IP stack fingerprinting – Determining the OS and hardware characteristics of network devices based on observations of network activity of said devices.

Full OS fingerprinting (e.g., using Nmap’s `-O` flag) is a related but distinct technique that analyzes TCP/IP stack behavior rather than application banners.


**Enumeration**

Enumeration – extract detailed data (users, shares, configs) using Nmap's NSE scripts or dedicated tools.

**Enumeration** is the active process of connecting to discovered services and querying them for detailed information. This includes everything from **simple banner grabbing** (reading the initial welcome banner) to **more complex interactions** (listing users, shares, directories, hidden web paths, or authentication methods).

Common enumeration techniques include Banner Grabbing, SMB enumeration, NetBIOS Enumeration, SNMP Enumeration, and using protocols like LDAP, NTP, and SMTP.

Below are concrete examples, ordered from foundational enumeration (banner grabbing) to deeper service‑specific enumeration,
illustrating how enumeration can extract usernames, shares, and configurations.

---

### Example 1: Banner Grabbing (Foundational Enumeration)

- **Scanning result:** Nmap detects open ports and performs version detection (`-sV`), revealing e.g., `Apache httpd 2.4.41` on port 80, `OpenSSH 8.2p1` on port 22.
- **Enumeration action:** The tester connects manually (e.g., `nc`, `telnet`, or a simple HTTP request) to read the service banner.
- **Extracted data:** Service name, version, and sometimes operating system hints. This information helps narrow down default configurations and potential vulnerabilities.

```bash
# Manual banner grab on HTTP
printf "HEAD / HTTP/1.0\r\n\r\n" | nc 192.168.1.10 80
# Manual banner grab on SSH
nc 192.168.1.10 22
# Nmap banner script
nmap --script banner -p80,22 192.168.1.10
```

- **Output example:**
    
    - HTTP: `Server: Apache/2.4.41 (Ubuntu)`
    - SSH: `SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5`

"Example 1: Banner Grabbing (Foundational Enumeration)" can also be discussed under identifying services and version. For example, using Nmap, we've identified live hosts on a network. We then ran nmap -p22 192.168.1.1 for port scanning and determined it's open. We then ran nmap -sV -p22 192.168.1.1 for services and version detection. The latter corresponds to your "Example 1: Banner Grabbing (Foundational Enumeration)"?

Yes, you are **exactly right**.

- `nmap -p22 192.168.1.1` only checks if port 22 is **open** (e.g., SYN scan → SYN‑ACK or RST).
- `nmap -sV -p22 192.168.1.1` does the same port scan **plus** connects to the open port, sends probes, and grabs the banner to determine the service and version.

That second command (`-sV`) is precisely performing **banner grabbing as a foundational enumeration technique** – it extracts the SSH version string (e.g., `SSH-2.0-OpenSSH_8.2p1`). So your mapping is correct:

> **`-sV` = port scan + banner grabbing / service version detection**  
> and that banner grabbing is the first and simplest form of enumeration on that port.

Thus, Example 1 (Banner Grabbing) can indeed be discussed under “identifying services and versions” – they are two descriptions of the same action.

Banner Grabbing and Service Versioning

- **Scanning result:** Nmap detects open ports and performs version detection (`-sV`), revealing e.g., `Apache httpd 2.4.41` on port 80, `OpenSSH 7.9` on port 22.
- **Enumeration action:** The tester connects manually or uses scripts to grab banners, and cross-references known default configurations.
- **Extracted data:** For Apache, the server root, enabled modules, or even virtual hosts. For SSH, sometimes the exact version points to a specific OS distribution, narrowing down configuration assumptions.

### Example 2: SSH Enumeration (Beyond Banner Grabbing)

- **Scanning result:** Nmap shows port 22 (SSH) open, with version detection (`-sV`) revealing e.g., `OpenSSH 8.2p1`.
- **Enumeration action:** The tester moves beyond banner grabbing to enumerate supported authentication methods, host keys, and (if vulnerable) valid usernames.
- **Extracted data:** Allowed authentication methods (password, publickey, keyboard‑interactive), host key fingerprints and algorithms, SSH protocol version, and (if vulnerable to CVE‑2018‑15473 or similar) valid usernames.

```bash
nmap --script ssh-auth-methods,ssh-hostkey -p22 192.168.1.10
ssh-audit 192.168.1.10
nmap --script ssh-brute -p22 --script-args userdb=users.txt,passdb=pass.txt 192.168.1.10
```

- **Output example:**
    
    - Authentication methods: `publickey, password`
    - Host key: `ssh-rsa AAAAB3NzaC1yc2EAAA...` (fingerprint `SHA256:abc123`)
    - Usernames (if vulnerable): `root`, `admin`, `ubuntu`

---

### Example 3: HTTP Enumeration (Beyond Banner Grabbing)

- **Scanning result:** Nmap shows port 80 (HTTP) or 443 (HTTPS) open, and service detection (`-sV`) reports a web server (e.g., `nginx/1.18.0` or `Apache httpd 2.4.41`).
- **Enumeration action:** The tester moves beyond the initial banner to enumerate hidden directories, software versions, and configuration details.
- **Extracted data:** Hidden directories (e.g., `/admin`, `/backup`, `/phpmyadmin`), server headers, supported HTTP methods, framework or CMS information (WordPress, Drupal), and sometimes user emails or source code disclosures.

```bash
nmap --script http-enum,http-headers -p80 192.168.1.10
gobuster dir -u http://192.168.1.10 -w /usr/share/wordlists/dirb/common.txt
whatweb http://192.168.1.10
```

- **Output example:**
    
    - Directories: `/admin` (401 Unauthorized), `/backup.zip` (200 OK), `/robots.txt` (Disallow: `/secret`)
    - Server: `nginx/1.18.0`
    - CMS: `WordPress 5.8` (from `/wp-content/`)

---

### Summary Table

|Service (Port)|Scan Finding|Enumeration Action|Extracted Data|
|---|---|---|---|
|Generic (any)|Open port, version detected|Banner grabbing (`nc`, Nmap `banner` script)|Service name, version, OS hints|
|SMB (445)|Open port|`enum4linux`, NSE scripts|Usernames, shares, group info|
|SNMP (161)|Open port, community string|`snmpwalk`|System config, users, processes|
|LDAP (389)|Open port|`ldapsearch`, `adidnsdump`|User objects, OUs, emails|
|SSH (22)|Open port, version detected|`ssh-auth-methods`, `ssh-audit`|Auth methods, host keys, valid usernames|
|HTTP (80/443)|Open port, version detected|`http-enum`, `gobuster`, `whatweb`|Hidden directories, CMS, server headers|
|SMTP (25)|Open port, `VRFY` support|`smtp-user-enum`|Valid user accounts|

These examples show how enumeration transforms a list of open ports into actionable intelligence – exactly the step between “what’s alive” and “what can I exploit.” 
**Banner grabbing** is the simplest form of enumeration, but deeper, service‑specific techniques extract far more data.


**Passive vs Active Discovery Techniques**

Both passive and active scanning and enumeration techniques exist. 

split table into scanning + enumeration

| Type                 | Passive                                          | Active                                         |
| -------------------- | ------------------------------------------------ | ---------------------------------------------- |
| **Interaction**      | No direct contact with target                    | Direct probes and packets sent                 |
| **Detection Risk**   | Very Low                                         | High                                           |
| **Speed/Accuracy**   | Slower, less precise                             | Faster, highly detailed                        |
| **Primary Use Case** | Early recon, compliance testing, avoiding alerts | Post-recon validation, comprehensive deep dive |
| Tools???             |                                                  |                                                |

Scanning types network scanning (host discovery), port scanning, and vulnerability scanning.

Common enumeration techniques include Banner Grabbing, SMB enumeration, NetBIOS Enumeration, SNMP Enumeration, and using protocols like LDAP, NTP, and SMTP.

which of these types of scanning and types of enumeration are passive and which are active?

- Network scanning, port scanning, and vulnerability scanning are all typically active techniques because they involve sending probes to the target. However, passive network scanning does exist—analyzing traffic (e.g., with `p0f`) to infer network topology and hosts without sending packets—but it is less common and not the primary meaning in penetration testing.
- The enumeration techniques Banner Grabbing, SMB enumeration, NetBIOS Enumeration, SNMP Enumeration, and using protocols like LDAP, NTP, and SMTP are generally active as they require direct queries to the target services. There are passive variants—for example, capturing banner information from unencrypted traffic already on the wire
using packet analyzers such as?
—but in practice, enumerators actively send requests to extract the data.

Here’s a classification based on how these techniques are typically applied during a penetration test:

| Technique              | Type   | Notes                                                                                                                  |
| ---------------------- | ------ | ---------------------------------------------------------------------------------------------------------------------- |
| Network scanning       | Active | Sending probes (ICMP, ARP, etc.) to discover live hosts. Passive alternatives (e.g., `p0f`) exist but are less common. |
| Port scanning          | Active | Directly connecting to ports (SYN, Connect, UDP scans) to determine open/closed/filtered states.                       |
| Vulnerability scanning | Active | Sending specific payloads or checks to identify known vulnerabilities; requires interaction.                           |
| Banner Grabbing        | Active | Connecting to a service to read its welcome banner. Passive version is possible if traffic is already being sniffed.   |
| NetBIOS Enumeration    | Active | Sending queries to NetBIOS Name Service (UDP 137) or SMB (TCP 445) to list hosts, shares, users.                       |
| SNMP Enumeration       | Active | Using SNMP queries (UDP 161) to walk MIBs and extract system information; often relies on default community strings.   |
| LDAP Enumeration       | Active | Querying LDAP directories (TCP 389 / 636) to retrieve user objects, groups, etc.                                       |
| NTP Enumeration        | Active | Using `ntpdc` or `ntpq` to query NTP servers (UDP 123) for monlist, peers, and system information.                     |
| SMTP Enumeration       | Active | Using `VRFY`, `EXPN`, or `RCPT TO` commands (TCP 25) to validate user accounts.                                        |

In short, all three / these
scanning types and all listed enumeration techniques are predominantly active. Passive discovery usually occurs earlier, during the reconnaissance phase, and focuses on information already publicly available or observable without direct interaction.

#### Vulnerability Scanning 

- Vulnerability scanning (optional) using vulnerability scanners - can be run after port scanning (fast) or after enumeration (stealthier but slower).

In a typical penetration testing process, a dedicated vulnerability scanner like Nessus or OpenVAS is usually used after the enumeration phase, 
and often before exploitation. 
Let me break it down in context.

- xService and version detection - basic (manual) **enumeration** via banner grabbing.
- xEnumeration (beyond banner grabbing) - through Nmap’s **enumeration** scripts.
- "Vulnerability scanning" using Nmap’s NSE vulnerability detection scripts 
- Vulnerability scanning (optional) using vulnerability scanners - can be run after port scanning (fast) or after enumeration (stealthier but slower).

although Nmap’s NSE scripts can send such probes for specific CVEs,
a specialized vulnerability scanner like OpenVAS is used to discover known vulnerabilities 

A vulnerability scanner “actively communicates with the target system, sends the malicious packets and analyses the results, which can then be exported to PDF, HTML, CSV and other formats” (Rasskazov, 2013, p. 58). 

- **Enumeration may or may not find a clear path.** If enumeration reveals an easy win (e.g., a service with a default admin password), a tester might skip straight to exploitation. However, in a thorough assessment, a vulnerability scan is still valuable because:
    
    - It uncovers **missing patches** and **CVEs** that are not detectable through manual enumeration.
    - It provides **documentation** (reports, risk ratings) needed for formal assessments.
    - It can be run **authenticated** using credentials gathered during enumeration, revealing even deeper vulnerabilities.
        
- **Timing**: Vulnerability scanning is typically performed **after** enumeration, but before exploitation. Some testers run it concurrently with enumeration. Running it after enumeration allows you to use any discovered credentials for authenticated scans, which yield more accurate results.

**If enumeration does not uncover a vulnerability worth exploiting**, the vulnerability scanner becomes even more critical—it’s the primary method to identify technical vulnerabilities (e.g., unpatched software) that can provide an entry point.


#### Vulnerability identification

- Vulnerability identification - map findings to known CVEs, misconfigurations, weaknesses.

Vulnerability identification is the result of service/version detection, enumeration (beyond banner grabbing), and (if performed) vulnerability scanning. For example:

- From service/version detection: "OpenSSH 7.4" → known vulnerability CVE-xxxx.
- From enumeration: "SMB signing disabled" → vulnerability (misconfiguration).
- From vulnerability scanning: "Missing patch MS17-010" → critical vulnerability.

In practice, vulnerability identification is not a separate phase but an _ongoing analysis_ that happens as you gather information. 


**Vulnerability identification** 

=map findings to known CVEs, misconfigurations, weaknesses.

Vulnerability identification is the result of:

service/version detection (via banner grabbing), 
enumeration (beyond banner grabbing), and 
vulnerability scanning using scanners (if performed) 

Following detection, enumeration extracts specific details like user lists, network shares, DNS records, configurations, and application data from the identified services. 

The tester then analyzes all gathered information
—service versions and enumerated data
—to pinpoint potential security weaknesses such as weak configurations (e.g., default credentials, anonymous access) and known vulnerabilities that could be exploited in the next phase. 


**Vulnerability detection via Nmap – what does it mean?**

When people say Nmap can be used for “vulnerability detection,” it usually refers to **two different capabilities**, and it’s important to distinguish them:

#### a) Detection of weak configurations/misconfigurations (via enumeration)
through Nmap’s enumeration scripts
=beyond banner grabbing

- **NSE** stands for **Nmap Scripting Engine**, which is the built‑in framework within Nmap for writing and running scripts. All scripts that come with Nmap (or are written for it) are NSE scripts.

Nmap’s NSE scripts can also perform enumeration (e.g., `smb-enum-users`)

This is not vulnerability scanning in the CVEs-and-patches sense, but rather identifying issues like:

- Default or blank passwords (e.g., `mysql-empty-password` script).
- Anonymous FTP or SNMP access.
- Exposed network shares.
- Information disclosure (e.g., `http-git` finding exposed `.git` folders).

These are _configuration weaknesses_ that may lead to compromise. They are often discovered through Nmap’s enumeration scripts.

#### b) Checking for known software vulnerabilities (like a vulnerability scanner)
through Nmap’s NSE
=beyond banner grabbing 

 NSE scripts for vulnerability detection (e.g., `smb-vuln-ms17-010`) are a form of vulnerability scanning.
 
Nmap’s NSE includes **vulnerability detection scripts** that check for specific CVEs. For example:

- `smb-vuln-ms17-010` – checks if a host is vulnerable to EternalBlue.
- `http-vuln-cve2017-5638` – checks for Apache Struts2 RCE.
- `ssl-heartbleed` – tests for Heartbleed.

These scripts actively probe the service and determine whether it is vulnerable to a particular, well-known exploit. This is similar to what a dedicated vulnerability scanner (like Nessus, OpenVAS) does, but with important differences:

- **Scope**: Nmap has a limited set of vulnerability checks compared to Nessus/OpenVAS, which have thousands of plugins.    
- **Depth**: Vulnerability scanners often perform authenticated scans, configuration audits, and more nuanced checks that Nmap does not.
- **Reporting**: Nmap outputs simple text; dedicated scanners provide detailed risk ratings, remediation steps, and compliance reporting.

So, **Nmap can perform a lightweight, targeted vulnerability scan**, but it is not a replacement for tools like Nessus or OpenVAS. It is best used for quick checks during an assessment, especially for high-profile vulnerabilities.

While Nmap's Scripting Engine (NSE) can perform some enumeration, deeper techniques (e.g., NetBIOS, SNMP, LDAP querying) often require specialized tools.



**Vulnerability Exploitation**

Some NSE scripts go as far as exploitation (e.g., `http-shellshock`, `smb-vuln-ms17-010`). These scripts can actually exploit a vulnerability to gain access. So while Nmap is not a dedicated exploitation framework (like Metasploit), it _can_ perform limited exploitation. T

#### Network sniffers in the penetration testing process

Passive network sniffers can monitor and capture data packets passing through a network in real time. Sniffers operate at the Data Link layer of the network. Data sent across the LAN is sent to every machine connected to the LAN. This is a passive technique since sniffers placed by the attackers passively wait for the data to be sent and capture them. Placing a packet sniffer on a network in promiscuous mode allows a malicious intruder to capture and analyze all of the network traffic such as payloads containing confidential information.

The function of sniffers evolves across the penetration testing lifecycle, providing critical intelligence in both the reconnaissance and scanning and enumeration phases. The same sniffer, deployed once, can fulfill different roles based on the analyst's focus—shifting from mapping the network's structure to probing its deepest vulnerabilities, all without sending a single packet and thus maintaining complete stealth.

During the reconnaissance phase, a passively deployed sniffer acts as a powerful footprinting tool. The sniffer builds a foundational profile of the target by listening to network traffic, which allows the tester to compile a map of active hosts, their IP and MAC addresses, and the core network protocols in use.

The same passive data can also be used to determine more detailed characteristics of the target systems. For instance, techniques used by tools like `p0f` can analyze the subtle characteristics of TCP/IP packets—such as TCP window sizes and TTL values—to determine the operating system and other configuration properties of the communicating hosts. 

p0f is a powerful passive fingerprinting alternative. It analyzes existing network traffic rather than generating its own probes, making it invaluable when active scanning might trigger alarms or is blocked by filters. p0f identifies hosts and their OS by analyzing subtle characteristics in TCP/IP packet headers and can also infer network setups like NAT, proxies, or load balancers by examining application-layer payloads. This ability to identify operating systems and network setups like NAT or load balancers significantly enriches the target profile without any direct interaction.

As the assessment progresses, the sniffer's role deepens from mapping to detailed investigation. The analyst shifts from identifying what assets exist to enumerating what weaknesses and data they expose. This can involve a detailed analysis of the captured packet payloads to extract sensitive information like cleartext credentials or specific application commands. The discovery of an unencrypted password within a packet, for instance, is the direct identification of a critical vulnerability (and in this instance a passive form of enumeration).

### Gaining access

exploitation of vulnerabilities to gain access, and privilege escalation

The actual hacking or penetration happens in the gaining access phase.

Now true attacks are leveled against the targets enumerated in the third phase (scanning and enumeration) of the ethical hacking process.

These attacks can be as simple as accessing an open and nonsecured wireless access point and then manipulating it for whatever purpose, or as complex as writing and delivering a buffer overflow or SQL injection against a web application. (Walker, 2012, p. 10)

In the enumeration phase, we successfully obtained user account information. Now what?  We’ll go over some of the basics on escalating your current privilege level. 
If the user account is not an administrator or doesn’t have access to interesting shares, escalating access privileges is necessary. After all, the point of hacking is gaining access to data or services. 

**Privilege Escalation**

An effective or successful hack or hacking will typically entail achieving root or administrative level access on the target machine.

Basically you have four real hopes for obtaining administrator (root) privileges on
a machine... see Gaining access subsection

/
Next, we start talking about actual system hacking. 

In the gaining access phase the ethical hacker tests many of the vulnerabilities identified during the vulnerability assessment (phases 2-6 of the ethical hacking process, i.e., reconnaissance, scanning and enumeration, gaining access, maintaining access, and covering tracks) to quantify the actual risk posed by the vulnerability (Harper et al., 2011; Walker, 2017). 

In the enumeration phase, we successfully obtained user account information. 
If the user account is not an administrator or doesn’t have access to interesting shares - such as???
, escalating access privileges is necessary. After all, the point of hacking is gaining access to data or services. 
Next, we’ll go over some of the basics on escalating your current privilege level. 

lateral movement as a form/technique of privilege escalation? 

We'll go over four primary methods to gain administrator (or root) privileges on a system and best practices to maintain access and remain undetected after a successful penetration of a target system 
(also see the subsection below "Escalating privileges and maintaining stealth").

--
reword (from Walker 2012, p. 168):

Basically you have four real hopes for obtaining administrator (root) privileges on a machine. The first is to crack the password of an administrator or root account, which should be your primary aim.
The second is to take advantage of a vulnerability found in the OS, or in an application, such as unpatched security flaws, that will give you access as a privileged user. 
In addition to running vulnerability scanners such as OpenVAS and Nessus to find holes, you should be aware of disclosed or published vulnerabilities before the scanner gets the results back to you - i.e., you should already know what to look for based on recent disclosures.

Vulnerability websites and online resources that publicly disclose, track, and detail software vulnerabilities include:

Sources of Intelligence

- **CVE Details (Common Vulnerabilities and Exposures):** A dictionary of publicly known security vulnerabilities.
- **Exploit-DB:** A repository of actual exploit code for specific vulnerabilities.
- **Vendor Security Advisories:** Official notices from Microsoft, Apple, Linux distributors, etc., about patches.
- **Full Disclosure Mailing Lists:** Where researchers publish zero-day or recently patched vulnerabilities.

The third method for obtaining administrator (root) privileges on a machine is to use a tool that will hopefully provide you the access you’re looking for. 
One such tool, Metasploit, is an entire hacking suite in one and is a great
exploit-testing tool (in other words, it’s about a heck of a lot more than privilege escalation and will be discussed more as this book continues). 
You basically enter the IP address and port number of the target you’re aiming at, choose an exploit, and add a payload—Metasploit does the rest. 
Metasploit has a free version and a pay-for version, known as Metasploit Pro.

Other tools?

Finally, the last method available is **social engineering**
You can simply
put executable code in an e-mail and ask the user to click it—more often than not, they
will! Craft a PDF file to take advantage of a known Adobe flaw on an unpatched system
and send it to them—most of the time, they’ll click and open it!


### Maintaining access

Post-exploitation: maintaining access and covering tracks.

Now hackers attempt to ensure they have a way back into the compromised system.

*Back doors are left open by the attacker for future use—especially if the system in question has been turned into a zombie (a machine used to launch further attacks from) or if the system is used for further information gathering—for example, a sniffer can be placed on a compromised machine to watch traffic on a specific subnet. Access can be maintained through the use of Trojans, rootkits, or any number of other methods. (Walker, 2012, p. 10)*

The concept of “escalation of privileges” between phase 4 (gaining access) and phase 5 (maintaining access) of the ethical hacking process refers to actions taken by a hacker to promote his access to root or administrative levels.

### Covering tracks

In the covering tracks phase of the ethical hacking process, hackers attempt to conceal their presence in the compromised machines to avoid detection.

*Steps taken here consist of removing or altering log files, hiding files with hidden attributes or directories, and even using tunneling protocols to communicate with the system. If auditing is even turned on and monitored, and often it is not, log files are an indicator of attacks on a machine. Clearing the log file completely is just as big an indicator to the security administrator watching the machine, so sometimes selective editing is your best bet. Another great method to use here is simply corrupting the log file itself—whereas a completely empty log file screams an attack is in progress, files get corrupted all the time and, chances are, the administrator won’t bother to try to rebuild it. In any case, good pen testers are truly defined in this phase. (Walker, 2012, p. 10)*

The following table, Pen Source/Free Tools—for Network Penetration Testing (Shah & Mehtre, 2015, p. 45), offers a summary of common open source network penetration testing tools, including their function and operating system compatibility.

<figure><img src="../../.gitbook/assets/image (1) (1) (1) (1) (1).png" alt="Open-Source-Network-Penetration-Testing-Tools"><figcaption><p>Pen Source/Free Tools—for Network Penetration Testing (Shah &#x26; Mehtre, 2015, p. 45)</p></figcaption></figure>

### The penetration test report

Typical vulnerability management software collects the results of vulnerability scans of target systems and provides a comprehensive dashboard to present the results. 

Vulnerability management software can build trends, sort the results by criticality, and keep additional records, for example, the percentage of computers with outdated software or weak password policy. 

The software’s reporting component can generate the compliance reports against widely used standards, such as PCI DSS, ISO 27001, or against corporate policies. 

Dedicated scanners correlate findings, assign risk ratings, and identify false positives.

Nexpose and other vendors include the vulnerability management software in the package with vulnerability scanners, while other vendors (e.g., Nessus) sell the software separately.

“Primarily, the pentesters and their work is judged by their report” (Velu, 2013, p. 7). The penetration test report typically has two primary sections: the Executive Summary, intended for management, and the Technical Report, which contains detailed findings for the IT staff. The penetration test report addresses the following key considerations: who is the audience of the report (e.g., senior management or IT staff), the purpose of testing, necessary procedures are justified, and required actions stated clearly. “A report should present outcome of the whole project by including objectives, used methodology, successful exploits, root cause of those exploits and recommendations” (Chaudhary, 2013, p.18). The report will offer an assessment of technical risk, business risk, reputational risk, and compliance risk. The key part of a penetration testing is the findings: customers will want to prioritize the remediation activities according to classification of the findings.

*The final report is a collection of all of the ethical hacker’s discoveries made during the evaluation. Vulnerabilities that were found to exist are explained and avoidance procedures specified. If the ethical hacker’s activities were noticed at all, the response of the client’s staff is described and suggestions for improvements are made. If social engineering testing exposed problems, advice is offered on how to raise awareness. This is the main point of the whole exercise: it does clients no good just to tell them that they have problems. The report must include specific advice on how to close the vulnerabilities and keep them closed. The actual techniques employed by the testers are never revealed. This is because the person delivering the report can never be sure just who will have access to that report once it is in the client’s hands. (Palmer, 2001, p. 779)*

*The final report is typically delivered directly to an officer of the client organization in hard-copy form. The ethical hackers would have an ongoing responsibility to ensure the safety of any information they retain, so in most cases all information related to the work is destroyed at the end of the contract. (Palmer, 2001, p. 779)*

### Key takeaways

* Phases of the penetration testing process are planning, reconnaissance, scanning and enumeration, exploitation, post-exploitation, and reporting
* The two phases of reconnaissance, and scanning and enumeration are intelligence gathering phases that serve to prepare for an exploit strategy against a target. Each of the two phases can be either passive or active
* Reconnaissance can be passive (e.g., OSINT, WHOIS, social media) or active (e.g., DNS queries, network probing)
* Reconnaissance uncovers information about the target company:
  * Company structure (partners, subsidiaries).
  * Employee details (names, roles, email formats).
  * Network infrastructure (domains, subdomains, IP ranges).
  * Publicly exposed services (via search engines, Shodan).
* Scanning is more intrusive than reconnaissance, often active. Scanning techniques include:
  * Host discovery (ICMP, ARP, TCP/UDP probes).
  * Port scanning (TCP SYN, Connect, UDP scans).
  * OS and service fingerprinting (banner grabbing, version detection).
  * Vulnerability scanning (automated tools like Nessus, OpenVAS).
* Scanning discovers live hosts, open ports, running services, and potential vulnerabilities
* Enumeration represents deeper probing to extract usable attack surfaces:
  * User accounts (via LDAP, SMB, SMTP, RPC).
  * Network shares and services (NFS, Samba, NetBIOS).
  * Application-specific data (SQL databases, SNMP, DNS records).
  * Email lists (harvested from exposed directories or breaches).
  * Results in a refined target list (e.g., vulnerable services, weak credentials).

### References

Chaudhary, H. (2013). Writing an effective penetration testing report. _PenTest Magazine, 3_(7), pp. 18-29.

Faircloth, J. (2011). _Penetration tester’s open source toolkit_. Penetration tester’s open source toolkit. Retrieved from www.scopus.com

Graves, K. (2010). _CEH: Certified Ethical Hacker Study Guide_. Wiley Publishing.

NIST Special Publication 800-115: Technical Guide to Information Security Testing and Assessment (NIST 800-115). Retrieved January 21, 2020, from http://csrc.nist.gov/publications/nistpubs/800-115/SP800-115.pdf

Palmer, C. C. (2001). Ethical hacking. _IBM Systems Journal, 40_(3), 769-780.

Rasskazov, V. (2013). Analysing vulnerability scanning reports. _PenTest Magazine, 3_(7), pp. 51-60.

Shah, S., & Mehtre, B. M. (2015). An overview of vulnerability assessment and penetration testing techniques. _Journal of Computer Virology and Hacking Techniques, 11_(1), 27-49. doi:10.1007/s11416-014-0231-x

Velu, V. (2013). 200 OK on Audience. _PenTest Magazine, 3_(7), pp. 7-16.

Walker, M. (2012). Certified Ethical Hacker All-in-One Exam Guide. Columbus: McGraw-Hill Osborne.

Walker, M. (2017). CEH Certified Ethical Hacker All-in-One Exam Guide, Second Edition. New York, NY: McGraw-Hill Education.
