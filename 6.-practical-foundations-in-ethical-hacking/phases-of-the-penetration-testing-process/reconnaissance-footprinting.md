# Reconnaissance (footprinting)

### Introduction

Footprinting is a systematic and organized process in ethical hacking that involves gathering as much publicly available information as possible about a target organization. This initial reconnaissance phase helps ethical hackers (and malicious attackers) understand the target’s digital footprint, infrastructure, and potential vulnerabilities before launching any penetration tests. The key methods of footprinting include:

1. **Competitive Intelligence**
   * Businesses legally collect data on competitors, including customer details, products, and marketing strategies.
   * Ethical hackers can use this same approach to gather valuable insights about a target, such as technology stacks, business strategies, and potential weak points.
2. **Company Websites**
   * A primary source of information, often containing:
     * **Company history & organizational structure** (useful for social engineering).
     * **Technical details** (server types, software versions, network setups).
     * **Employee directories & contact information** (helpful for phishing attacks).
   * Many companies unintentionally expose too much technical data, making it easier for hackers to identify vulnerabilities.
3. **Job Postings & Career Boards**
   * Sites like LinkedIn, Monster, and Dice reveal:
     * **Specific technologies in use** (e.g., "Windows Server 2016, Cisco firewalls").
     * **Software versions** (helping hackers match exploits to known vulnerabilities).
     * **Internal IT roles & responsibilities** (indicating security gaps).
   * Job descriptions can essentially serve as a blueprint of the company’s IT infrastructure.
4. **Social Media & Professional Networks**
   * Platforms like LinkedIn, Facebook, and Twitter provide:
     * **Employee profiles** (roles, departments, connections).
     * **Company culture & internal issues** (layoffs, disgruntled employees).
     * **Real-time updates** (mergers, new tech deployments).
   * Hackers can exploit personal details for social engineering attacks (e.g., impersonating IT staff).
5. **Website Mirroring & Historical Archives**
   * Tools like **BlackWidow, Wget, and TeleportPro** allow copying entire websites for offline analysis.
   * **Archive.org (Wayback Machine) & Google Cache** can retrieve deleted or modified content, exposing old but still relevant vulnerabilities.
   * Even if a company removes sensitive data, archived versions may still be accessible.

#### Censys

Censys is primarily a tool for the reconnaissance phase, specifically the Footprinting (Faircloth, 2011) stage. Here is the detailed breakdown:

**Primary Role: Reconnaissance (Footprinting)**

The core function of Censys is to provide a pre-scanned, searchable index of Internet-facing assets. Its output aligns with the objectives of the reconnaissance phase:

- **Objective:** "To mine as many DNS host names as possible... and translate those into IP addresses or IP address ranges."
    
- **Censys Output:** It directly provides lists of:
    
    - **IP Addresses and Ranges** associated with an organization.
    - **DNS Hostnames** and associated certificates.
    - **Open Ports** on those IPs (e.g., it tells you _that_ port 443 is open, not necessarily what specific software is running on it beyond a basic banner).
    - **Network Blocks** and autonomous systems (ASNs).

This output is a goldmine for building the initial target list and understanding the organization's public attack surface **without sending a single packet to the target yourself**. The search itself is a passive act from the target's perspective.

**Bridging into Scanning & Enumeration**

While its primary home is reconnaissance, the data provided by Censys can directly enable and accelerate the scanning and enumeration phase. It blurs the line in the following way:

- Censys often collects and displays **banners** and **service version information** from the ports it scans. When a penetration tester uses this pre-collected version data to identify a specific vulnerability (e.g., seeing `Apache 2.4.49` which is vulnerable to CVE-2021-41773), they are effectively using Censys to perform a form of **passive vulnerability enumeration**.
- In this sense, a tester uses Censys for reconnaissance ("find all IPs for company X with port 443 open") and then immediately uses its detailed data for initial enumeration ("and now I see that this specific IP is running a vulnerable version of Apache").

In summary, a penetration tester uses Censys during the reconnaissance (Footprinting) phase to quickly generate a highly accurate map of a target's public-facing assets—IPs, domains, and open ports. The intelligence gleaned from Censys, particularly service banners and certificate details, can then immediately inform the subsequent scanning and enumeration phase by highlighting specific systems and services worthy of more targeted, active investigation.
### Footprinting with DNS

Footprinting with DNS involves exploring DNS records (directions to or for a specific type of resource).

Some records provide IP addresses for individual systems within your network, whereas others provide addresses for your e-mail servers. Some provide pointers to other DNS servers, which are designed to help people find what they’re looking for. (Walker, 2012, p. 62)

The record types held within a company's DNS system can tell a hacker valuable information about the network layout, such as which server in the network holds and manages all the DNS records, where the e-mail servers are located, and where all the public-facing websites actually reside. All this information can be determined by examining the DNS record types.

<figure><img src="../../.gitbook/assets/image (2) (1).png" alt="DNS record types"><figcaption><p>Source: Walker (2012, p. 63)</p></figcaption></figure>

DNS (Domain Name System) is a foundational component of the internet, acting as a directory that translates human-readable domain names (like _example.com_) into machine-readable IP addresses (like \*192.0.2.1\*). For ethical hackers and penetration testers, DNS is a goldmine of reconnaissance data, revealing critical details about a target’s network infrastructure. This discussion explores how attackers (and defenders) leverage DNS for footprinting, including key DNS records, tools, and techniques.

**1. DNS Records and Their Significance**

DNS records store different types of information about a domain. By querying these records, an attacker can map out a target’s servers, services, and network architecture. The most important DNS records for footprinting include:

* **A (Address) Records** – Maps a hostname to an IPv4 address.
  * Example: [_www.example.com_](http://www.example.com/) _→ 192.0.2.1_
  * Attackers use this to identify live web servers and other publicly accessible hosts.
* **AAAA (IPv6 Address) Records** – Similar to A records but for IPv6 addresses.
  * Example: [_www.example.com_](http://www.example.com/) _→ 2001:db8::1_
  * Useful in networks transitioning to IPv6.
* **MX (Mail Exchange) Records** – Identifies mail servers responsible for receiving email for the domain.
  * Example: _example.com → mail.example.com (priority 10)_
  * Attackers target email servers for phishing or SMTP-based attacks.
* **NS (Name Server) Records** – Specifies the authoritative DNS servers for the domain.
  * Example: _example.com → ns1.example.com, ns2.example.com_
  * Reveals where DNS queries are resolved, potentially exposing internal or secondary DNS servers.
* **CNAME (Canonical Name) Records** – Provides aliases for hostnames.
  * Example: _ftp.example.com → fileserver.example.com_
  * Helps attackers discover additional subdomains or services.
* **TXT (Text) Records** – Contains arbitrary text, often used for verification, SPF (Sender Policy Framework), or DKIM (DomainKeys Identified Mail).
  * Example: \*"v=spf1 mx -all"\* (indicates only MX servers can send email for the domain)
  * May expose security policies or misconfigurations.
* **SOA (Start of Authority) Record** – Contains administrative details about the DNS zone, including:
  * Primary DNS server
  * Administrator email (often in the format [_hostmaster@example.com_](https://mailto:hostmaster@example.com/))
  * Serial number (for version tracking)
  * Refresh/retry/expire intervals (for zone transfers)
  * Default TTL (Time to Live)
  * Attackers can use this to identify key servers and potential misconfigurations.
* **PTR (Pointer) Records** – Used for reverse DNS lookups, mapping an IP address back to a hostname.
  * Example: _192.0.2.1 →_ [_www.example.com_](http://www.example.com/)
  * Helps attackers confirm ownership of IP ranges and discover additional hosts.

**2. Zone Transfers (AXFR Requests) – A Critical Vulnerability**

A **zone transfer** is a mechanism where a secondary DNS server requests a full copy of the DNS records from the primary server. While useful for redundancy, a **misconfigured DNS server may allow unauthorized zone transfers**, effectively leaking the entire DNS database.

* **How Attackers Exploit This:**
  *   Using tools like `dig` or `nslookup`, an attacker can request a zone transfer:

      bash

      ```
      dig @ns1.example.com example.com AXFR  
      ```
  * If successful, this returns all DNS records, exposing internal hosts, subdomains, and services.
* **Defensive Measures:**
  * Restrict zone transfers to authorized secondary servers only.
  * Implement Access Control Lists (ACLs) on DNS servers.

**3. DNS Lookup Tools for Footprinting**

Several command-line tools are used to query DNS records:

* **`nslookup`** (Windows/Linux) – A versatile tool for manual DNS queries.
  *   Interactive mode allows for multiple queries:

      bash

      ```
      nslookup  
      > set type=MX  
      > example.com  
      ```
  *   Non-interactive mode for quick lookups:

      bash

      ```
      nslookup -type=NS example.com  
      ```
* **`dig` (Linux/Unix)** – More powerful than `nslookup`, providing detailed responses.
  *   Example:

      bash

      ```
      dig example.com MX  
      dig +short example.com A  
      dig @ns1.example.com example.com AXFR  
      ```
* **`whois`** – Retrieves domain registration details, including:
  * Registrar information
  * Domain owner contact details (sometimes redacted)
  * Name servers
  * Creation/expiration dates
  *   Example:

      bash

      ```
      whois example.com  
      ```

**4. Reverse DNS Lookups (Mapping IPs to Hostnames)**

By querying **PTR records**, attackers can determine which hostnames are associated with an IP address. This is useful for:

* Identifying additional servers in the same subnet.
* Discovering internal naming conventions (e.g., _web1.example.com, db1.example.com_).

Example using `dig`:

bash

```
dig -x 192.0.2.1  
```

**5. DNS Cache Snooping**

Some DNS servers cache responses to improve performance. Attackers can probe these caches to discover:

* Recently visited domains (useful for profiling user activity).
* Internal hostnames that may not be publicly listed.

### Summary/key takeaways

Footprinting is a critical first step in ethical hacking, relying on open-source intelligence (OSINT) to map out a target’s physical and digital presence. With footprinting, we want to gather information about network architecture (size, design, equipment brands and specifications), websites, who’s who in the company and any contact information, and the target’s geographical location (address).

DNS footprinting is a passive yet highly effective reconnaissance technique. By analyzing DNS records, performing zone transfers (if misconfigured), and using tools like `dig`, `nslookup`, and `whois`, ethical hackers can gather extensive intelligence about a target’s network. Defenders must ensure proper DNS hardening—such as restricting zone transfers and minimizing exposed records—to mitigate these risks.

✔ **DNS records reveal critical network details** (servers, mail systems, subdomains).\
✔ **Zone transfers are a major security risk**—always restrict them.\
✔ **Tools like `dig`, `nslookup`, and `whois` are essential** for footprinting.\
✔ **Reverse DNS lookups expose additional hosts** and naming schemes.
