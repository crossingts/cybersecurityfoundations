---
description: >-
  This section covers important defensive cybersecurity technologies such as
  firewalls, IDS/IPS, network security event management (SIEM), and packet
  analyzers
---

# Defensive cybersecurity technologies

## Learning objectives

* Point 1
* Point 2

This section looks at popular open source defensive cybersecurity technologies, exploring their key advantages/characteristics and deployment (use cases). Key categories of defensive technologies covered include host/network firewalls (e.g., OPNsense, pfilter, and nftables), IDS/IPS (e.g., Suricata and Snort), network security monitoring/SIEM (e.g., Wazuh), and packet analyzers (e.g., Wireshark and tcpdump).

## Topics covered in this section

* **Firewalls**
* **IDS/IPS**
* **SIEM/EDR**
* **Packet analyzers**

### Firewalls

Popular open source host and network firewalls include iptables, nftables, ufw, pf, OPNsense, and pfSense (CE).

### IDS/IPS

Popular open source NIDS and HIDS include Suricata, Snort, Wazuh, OSSEC, Fail2Ban, Zeek (formerly Bro), Security Onion, and OpenWIPS-NG.

### SIEM/EDR

Popular open source SIEM/EDR (Security Information and Event Management/Endpoint Detection and Response) technologies include Wazuh, TheHive, Zeek, OSSEC, Suricata, and Velociraptor.

#### Wazuh (SIEM/XDR)

The Wazuh Security Information and Event Management (SIEM) solution is a centralized platform for aggregating and analyzing telemetry in real time for threat detection and compliance. Wazuh collects event data from various sources like endpoints, network devices, cloud workloads, and applications for broader security coverage. (wazuh.com)

The Wazuh Extended Detection and Response (XDR) platform provides a comprehensive security solution that detects, analyzes, and responds to threats across multiple IT infrastructure layers. Wazuh collects telemetry from endpoints, network devices, cloud workloads, third-party APIs, and other sources for unified security monitoring and protection. (wazuh.com)

Wazuh is an open-source security monitoring platform that provides SIEM (log analysis) and EDR (endpoint monitoring and response) functionalities, enabling centralized visibility, threat detection, compliance monitoring, and automated mitigation.

1. **SIEM (Security Information and Event Management)**\
   Wazuh provides log collection, analysis, and correlation, which are core SIEM functionalities. It can aggregate logs from various sources (network devices, endpoints, and cloud services) and apply rules to detect threats.
2. **EDR (Endpoint Detection and Response)** \
   Wazuh provides EDR capabilities (file integrity monitoring, process monitoring, behavioral analysis, and automated responses).
3. **Centralized Visibility & Threat Mitigation**\
   Wazuh offers a centralized dashboard for monitoring security events across endpoints, supports active responses (e.g., blocking malicious IPs), and integrates with threat intelligence feeds.

**How Wazuh Works:**

1. **Log Collection**
   * Wazuh collects logs from various sources, including:
     * **Network devices** (firewalls, routers, switches via syslog, SNMP, etc.).
     * **Endpoints** (servers, workstations, cloud instances using the Wazuh agent).
     * **Third-party APIs** (cloud services like AWS, Azure, Office 365, etc.).
     * **Security tools** (IDS/IPS, antivirus, vulnerability scanners).
2. **Log Analysis & Correlation**
   * Wazuh **normalizes and parses** logs into a structured format.
   * It applies **rules** (predefined & custom) to detect suspicious activity.
   * It **correlates events** (e.g., multiple failed logins + a successful login from a new IP → potential brute-force attack).
3. **Alerting on Threats**
   * When a rule is triggered, Wazuh generates an **alert**.
   * Alerts can be sent via email, SIEM integrations (Elasticsearch, Splunk), or other notification methods.
   * Wazuh also provides **active monitoring** (e.g., checking for unauthorized changes in files, detecting malware) and **automated responses** (e.g., blocking an IP after too many failed logins).

### Packet analyzers

#### Wireshark

Wireshark is primarily a defensive (security monitoring) tool, but it can also be used in offensive security (ethical hacking) scenarios.

**Wireshark Defensive Uses:**

1. **Traffic Analysis for Security Monitoring**
   * Wireshark’s core function is capturing and analyzing network traffic, which is essential for detecting anomalies, intrusions, and malicious activity (e.g., malware C2 traffic, suspicious connections).
   * Security teams use it to inspect packets for signs of attacks (e.g., port scans, unusual protocols, data exfiltration).
2. **Incident Response & Forensics**
   * After a breach, analysts use Wireshark to review packet captures (PCAPs) to understand attack vectors, lateral movement, and data leaks.
   * It helps reconstruct events by examining raw network data.
3. **Network Troubleshooting (Non-Attack Use Cases)**
   * IT admins and defenders use Wireshark to diagnose connectivity issues, misconfigurations, and performance problems—not just security threats.
4. **Passive Tool (No Active Exploitation)**
   * Wireshark doesn’t send packets or exploit vulnerabilities; it only observes traffic. Offensive tools (e.g., Metasploit, Nmap) actively interact with targets.

**Wireshark Offensive Uses (Secondary Role):**

While defensive use is primary, ethical hackers and attackers can leverage Wireshark for:

* **Reconnaissance**: Capturing unencrypted credentials, session tokens, or sensitive data in transit.
* **Man-in-the-Middle (MITM) Analysis**: Inspecting traffic during red-team engagements (e.g., ARP spoofing attacks).
* **Protocol Reverse-Engineering**: Studying proprietary protocols for vulnerabilities.

However, these offensive uses typically require additional tools (e.g., Ettercap, BetterCAP) to actively manipulate traffic—Wireshark alone is just the analyzer.

Wireshark is **defensive-first** because its primary purpose is monitoring, analysis, and defense. Its core value lies in visibility—whether for protecting or probing a network.

Here’s a concise table summarizing Wireshark’s dual-use capabilities in **defensive (security monitoring)** and **offensive (ethical hacking)** contexts:

| **Category**         | **Defensive Use (Security Monitoring)**                                                                                                              | **Offensive Use (Ethical Hacking)**                                                                                                          |
| -------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| **Primary Role**     | Traffic inspection, threat detection, and incident response.                                                                                         | Reconnaissance, protocol analysis, and attack validation.                                                                                    |
| **Key Functions**    | <p>- Detect malware C2 traffic.<br>- Analyze intrusion attempts.<br>- Troubleshoot network issues.<br>- Forensic investigations (PCAP analysis).</p> | <p>- Capture unencrypted credentials.<br>- Analyze MITM attack results.<br>- Reverse-engineer protocols.<br>- Validate exploit payloads.</p> |
| **Tool Interaction** | Used alongside SIEMs, IDS/IPS (e.g., Snort), and firewalls.                                                                                          | Paired with exploitation tools (e.g., Metasploit, Responder).                                                                                |
| **Activity Type**    | **Passive**: Observes traffic without modification.                                                                                                  | **Supportive**: Analyzes traffic generated by active attacks.                                                                                |
| **Examples**         | <p>- Identifying a ransomware beacon.<br>- Investigating a data exfiltration attempt.</p>                                                            | <p>- Sniffing FTP credentials.<br>- Debugging a custom exploit's network behavior.</p>                                                       |

Table: Wireshark’s dual-use capabilities
