---
description: >-
  This section covers important defensive security technologies such as packet
  analyzers, intrusion detection/intrusion prevention, SIEM, and firewalls
---

# Defensive cybersecurity technologies

• Describe common defensive security technologies such as packet analyzers (e.g., Wireshark), IDS/IPS (e.g., Suricata and Snort), network security monitoring/SIEM (e.g., Wazuh), and host/network firewalls (e.g., OPNsense, pfilter, and nftables).

#### nftables firewall to optimize traffic flow

• Default to connection denial for inbound traffic

• Limit accessible ports and hosts with an allow list

#### Wazuh (SIEM) as a network security monitoring tool

Wazuh is primarily a SIEM and HIDS tool with log analysis and file integrity monitoring capabilities, great for centralized visibility and incident response.

* It collects and correlates logs from multiple sources (network devices, servers, cloud services).
* It does not replace a traditional NIDS like Suricata but can integrate with them—IDS provides raw threat data, while SIEM helps make sense of IDS alerts.
* It provides compliance monitoring (e.g., PCI DSS, GDPR) and incident response features.

The Wazuh Security Information and Event Management (SIEM) solution is a centralized platform for aggregating and analyzing telemetry in real time for threat detection and compliance. Wazuh collects event data from various sources like endpoints, network devices, cloud workloads, and applications for broader security coverage. (wazuh.com)

The Wazuh Extended Detection and Response (XDR) platform provides a comprehensive security solution that detects, analyzes, and responds to threats across multiple IT infrastructure layers. Wazuh collects telemetry from endpoints, network devices, cloud workloads, third-party APIs, and other sources for unified security monitoring and protection. (wazuh.com)

#### **Comparison Table: SIEM vs. IDS/IPS vs. Firewalls vs. EDR**

| Feature                   | **SIEM (Wazuh, Splunk)**              | **IDS/IPS (Snort, Suricata)**           | **Firewall (nftables, iptables, pfSense)** | **EDR (CrowdStrike, Wazuh EDR)**             |
| ------------------------- | ------------------------------------- | --------------------------------------- | ------------------------------------------ | -------------------------------------------- |
| **Primary Role**          | Log correlation, alerting, compliance | Detect/block malicious traffic          | Filter traffic based on rules              | Detect/respond to endpoint threats           |
| **Detection Method**      | Rule-based + anomaly (if configured)  | Signature + anomaly detection           | Rule-based (allow/deny)                    | Behavioral analysis + threat intelligence    |
| **Prevention Capability** | No (alerting only)                    | **IPS can block**, IDS alerts           | **Blocks traffic** based on rules          | **Can block processes**, isolate hosts       |
| **Data Source**           | Logs (network, endpoints, apps)       | Network traffic (packet **inspection**) | Network traffic (L3/L4 **filtering**)      | Endpoint processes, memory, files            |
| **Scope**                 | Broad (entire infrastructure)         | Network-focused                         | Network perimeter/internal segmentation    | Endpoint-focused (workstations, servers)     |
| **Best For**              | Incident investigation, compliance    | Real-time threat blocking               | Access control, network segmentation       | Advanced malware, lateral movement detection |

A mature security stack combines:

1. **Firewall** → Blocks unauthorized access.
2. **IDS/IPS** → Stops known attacks in traffic.
3. **NTA** → Detects stealthy threats in network flows.
4. **SIEM** → Correlates alerts from all sources.
5. **EDR** → Hunts for endpoint compromises.
