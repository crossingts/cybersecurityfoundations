# Scanning and enumeration techniques and tools

#### **Scanning vs. Enumeration: Phases, Techniques & Passive/Active Breakdown**

To clearly distinguish between **scanning** and **enumeration**, we'll break them into **two separate phases**, then categorize techniques as **passive** or **active**.

***

### **1. Scanning Phase**

**Goal:** Discover live hosts, open ports, services, and potential vulnerabilities.

#### **Sub-Phases & Techniques**

| **Scanning Type**                               | **Passive Techniques**                                                                                                                                                       | **Active Techniques**                                                                                                                                                                            |
| ----------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Network Scanning** (Host Discovery)           | <p>- <strong>Shodan/Censys searches</strong><br>- <strong>Passive DNS lookups</strong> (SecurityTrails)<br>- <strong>ARP cache snooping</strong> (if already on network)</p> | <p>- <strong>ARP scans</strong> (<code>arp-scan -l</code>)<br>- <strong>ICMP ping sweeps</strong> (<code>nmap -sn</code>)<br>- <strong>TCP ping scans</strong> (<code>nmap -PS80,443</code>)</p> |
| **Port Scanning** (Service Discovery)           | <p>- <strong>Analyzing firewall logs</strong><br>- <strong>Searching leaked scan data</strong> (e.g., BinaryEdge)</p>                                                        | <p>- <strong>TCP SYN scan</strong> (<code>nmap -sS</code>)<br>- <strong>TCP Connect scan</strong> (<code>nmap -sT</code>)<br>- <strong>UDP scan</strong> (<code>nmap -sU</code>)</p>             |
| **Vulnerability Scanning** (Weakness Detection) | <p>- <strong>Searching Exploit-DB for service versions</strong><br>- <strong>Checking CVE databases</strong> (NVD)</p>                                                       | <p>- <strong>NSE scripts</strong> (<code>nmap --script vuln</code>)<br>- <strong>Nessus/OpenVAS scans</strong><br>- <strong>Automated vuln scanners</strong> (Nikto for web)</p>                 |

***

### **2. Enumeration Phase**

**Goal:** Extract detailed info (users, shares, configs, app data) from discovered services.

#### **Common Enumeration Techniques**

| **Enumeration Type**        | **Passive Techniques**                                                                                                                    | **Active Techniques**                                                                                                                                                       |
| --------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Banner Grabbing**         | <p>- <strong>Searching Shodan for service banners</strong><br>- <strong>Reviewing cached HTTP responses</strong> (Google/Archive.org)</p> | <p>- <strong>Netcat/Telnet connections</strong> (<code>nc 192.168.1.1 80</code>)<br>- <strong>Nmap service detection</strong> (<code>nmap -sV</code>)</p>                   |
| **NetBIOS/SMB Enumeration** | - **Reviewing public SMB leaks** (VirusTotal)                                                                                             | <p>- <strong><code>enum4linux</code></strong><br>- <strong><code>smbclient -L //target</code></strong><br>- <strong><code>nmap --script smb-enum-shares</code></strong></p> |
| **SNMP Enumeration**        | - **Checking default community strings in logs**                                                                                          | <p>- <strong><code>snmpwalk -c public -v1 target</code></strong><br>- <strong><code>onesixtyone</code> (brute-force communities)</strong></p>                               |
| **LDAP Enumeration**        | - **Searching public directory leaks**                                                                                                    | <p>- <strong><code>ldapsearch</code> queries</strong><br>- <strong><code>nmap --script ldap-search</code></strong></p>                                                      |
| **NTP Enumeration**         | - **Checking NTP pool leaks**                                                                                                             | <p>- <strong><code>ntpdc -c monlist target</code></strong> (old)<br>- <strong><code>nmap --script ntp-info</code></strong></p>                                              |
| **SMTP Enumeration**        | - **Checking breached email lists**                                                                                                       | <p>- <strong><code>smtp-user-enum</code></strong><br>- <strong><code>nmap --script smtp-enum-users</code></strong></p>                                                      |

***

#### **Key Takeaways**

1. **Scanning** → Finds **what exists** (hosts, ports, services).
   * Passive: No direct interaction (OSINT, cached data).
   * Active: Direct probing (Nmap, Nessus).
2. **Enumeration** → Extracts **useful data** (users, shares, configs).
   * Passive: Leaked data, historical records.
   * Active: Direct queries (LDAP, SMB, SNMP).

#### **When to Use Which?**

* **Passive** → Early recon, avoiding detection.
* **Active** → Post-recon, deeper exploitation prep.
