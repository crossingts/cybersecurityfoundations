# Scanning and enumeration tools

A technical breakdown of the scanning and enumeration phase in penetration testing, using open-source tools:

#### **1. Host Discovery (Identifying Live Hosts)**

**Objective:** Find active devices in the target network.\
**Tools & Techniques:**

* **ARP Scanning (Layer 2)**
  * `arp-scan` (Linux) – Fast LAN discovery.
  * `nmap -PR <target>` (ARP ping scan).
* **ICMP Ping Sweep (Layer 3)**
  * `fping -g <subnet>` (Fast parallel ping).
  * `nmap -sn <target>` (No port scan, just host discovery).
* **TCP/UDP Ping (Evading ICMP Filters)**
  * `nmap -PS <port> <target>` (TCP SYN ping).
  * `nmap -PU <port> <target>` (UDP ping).
* **Passive Discovery (Sniffing)**
  * `tcpdump` / `Wireshark` (Analyze network traffic).
  * `netdiscover -i eth0 -r <subnet>` (Passive ARP reconnaissance).

***

#### **2. Port Scanning (Identifying Open Ports & Services)**

**Objective:** Determine open ports and running services.\
**Tools & Techniques:**

* **TCP Connect Scan (`-sT`)** – Full 3-way handshake.
* **TCP SYN (Stealth) Scan (`-sS`)** – Half-open scan (no session completion).
* **UDP Scan (`-sU`)** – Slower but crucial for DNS, DHCP, SNMP.
* **Version Detection (`-sV`)** – Identify service versions.
* **OS Fingerprinting (`-O`)** – Guess OS based on TCP/IP stack.
* **Aggressive Scan (`-A`)** – Combines OS, version, and script scanning.

**Open-Source Tools:**

* `nmap` (Primary tool for all scan types).
* `masscan` (Very fast, Internet-scale scanning).
* `rustscan` (Fast port scanner with auto Nmap integration).

**Example Commands:**

bash

```
nmap -sS -p- -T4 -Pn <target>  # SYN scan all ports
nmap -sU -p 53,161,123 <target>  # Check common UDP ports
nmap -sV -O -A -T4 <target>  # Aggressive scan
```

***

#### **3. Service Enumeration (Banner Grabbing & Deep Inspection)**

**Objective:** Extract detailed service info (versions, configurations).\
**Tools & Techniques:**

* **Banner Grabbing**
  * `nc -nv <target> <port>` (Netcat manual grab).
  * `nmap -sV --script=banner <target>`.
* **SNMP Enumeration**
  * `snmpwalk` (Query SNMP devices).
  * `onesixtyone` (Fast SNMP community string brute-forcing).
* **SMB Enumeration**
  * `smbclient -L //<target>` (List SMB shares).
  * `enum4linux -a <target>` (Comprehensive SMB enum).
* **DNS Enumeration**
  * `dnsrecon -d <domain>` (Zone transfers, subdomains).
  * `dig axfr @<DNS-server> <domain>` (Test zone transfer).
* **HTTP/HTTPS Enumeration**
  * `gobuster dir -u <URL> -w <wordlist>` (Directory brute-forcing).
  * `nikto -h <URL>` (Web server vulnerabilities).
  * `whatweb <URL>` (Identify web tech stack).

***

#### **4. Vulnerability Scanning (Initial Weakness Identification)**

**Objective:** Find known vulnerabilities in services.\
**Open-Source Tools:**

* `OpenVAS` (Comprehensive vulnerability scanner).
* `Nmap NSE Scripts` (`--script vuln` for CVE checks).
* `vuls` (Agent-based vulnerability scanner).

**Example:**

bash

```
nmap --script vuln <target>  # Check for known CVEs
openvas-start  # Launch OpenVAS web interface
```

***

#### **5. Network Mapping (Topology & Firewall Analysis)**

**Objective:** Understand network layout and filtering rules.\
**Tools & Techniques:**

* **Traceroute Analysis**
  * `traceroute` / `mtr` (Path discovery).
  * `nmap --traceroute <target>`.
* **Firewall Evasion**
  * `nmap -f` (Fragment packets).
  * `nmap --data-length 50` (Add random data).
* **Traffic Analysis**
  * `Wireshark` / `TShark` (Deep packet inspection).

***

#### **Summary Workflow**

1. **Host Discovery** → `arp-scan`, `nmap -sn`.
2. **Port Scanning** → `nmap -sS -p-`.
3. **Service Enumeration** → `smbclient`, `snmpwalk`, `gobuster`.
4. **Vulnerability Scanning** → `OpenVAS`, `nmap --script vuln`.
5. **Network Mapping** → `traceroute`, `Wireshark`.
