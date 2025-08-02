# Zeek

Zeek (formerly Bro) is a powerful network analysis framework, widely used in research and enterprises. Zeek is dominant in network visibility—it has the capability to provide deep, protocol-aware monitoring and logging of network activity. Zeek focuses on analyzing network traffic at the application layer, generating structured logs that answer:

* **Who** is communicating? (IPs, devices, users)
* **What** are they doing? (HTTP requests, DNS queries, SSL certificates, SSH logins, etc.)
* **When/Where/How** is it happening? (Timestamps, geolocation, protocol behavior)

Unlike tools that just alert on threats (e.g., Snort/Suricata), Zeek **records everything** in a way that’s useful for:

* **Forensics** (e.g., "What files were downloaded over HTTP?")
* **Threat hunting** (e.g., "Find all DNS queries to known malicious domains")
* **Behavioral analysis** (e.g., "Detect unusual SSH login patterns")

**Zeek vs. Traditional Monitoring Tools**

| **Aspect**        | **Zeek**                                | **Traditional Network Monitoring** (e.g., Nagios, PRTG, Zabbix) |
| ----------------- | --------------------------------------- | --------------------------------------------------------------- |
| **Primary Focus** | Security-relevant network activity      | Availability, bandwidth, latency, uptime                        |
| **Data Output**   | Logs (e.g., `conn.log`, `http.log`)     | Metrics (e.g., throughput, packet loss, jitter)                 |
| **Use Case**      | Threat detection, forensics, compliance | Network health, SLA monitoring                                  |
| **Protocols**     | Deep parsing (HTTP, DNS, SSL, etc.)     | SNMP, NetFlow, ICMP                                             |
| **Tool Examples** | Suricata (for comparison)               | Cacti, SmokePing, SolarWinds                                    |

**Why Zeek Isn’t a Traditional IPS**

* **No Real-Time Blocking**: Zeek logs and alerts but doesn’t actively drop packets (unlike Suricata in IPS mode).
* **Passive Analysis**: It reconstructs sessions and extracts metadata but doesn’t manipulate traffic.
* **Flexible, Not Prescriptive**: You define what to log (e.g., "all HTTP User-Agent strings"), rather than relying on fixed rules.

**Example of Zeek’s Visibility**

A single HTTPS connection generates logs with:

* **SSL/TLS details** (certificate issuer, cipher suites)
* **Timing/duration** of the session
* **Associated DNS query** that resolved the domain
* **Linked files** (e.g., downloaded executables)

This is invaluable for detecting:

* **Malware C2 channels** (e.g., unusual SSL certs)
* **Data exfiltration** (e.g., large, unexpected uploads)
* **Policy violations** (e.g., unauthorized cloud services).

**When to Pair Zeek with Other Tools**

* **For IPS**: Combine Zeek with **Suricata** (blocking) + **Wazuh** (host-level correlation).
* **For Dashboards**: Pipe Zeek logs to **Elasticsearch + Kibana** or **Splunk**.
* **For Performance Monitoring**: Use **NetFlow** (pmacct) or **SNMP**.

Zeek offers **deep protocol-level visibility** by analyzing raw network traffic and generating structured logs (e.g., HTTP requests, DNS queries, SSL certificates), enabling detailed forensic investigations and behavioral analysis—unlike traditional monitoring tools that focus only on performance metrics (bandwidth, uptime). Zeek passively reconstructs network activity into actionable security data without blocking traffic.
