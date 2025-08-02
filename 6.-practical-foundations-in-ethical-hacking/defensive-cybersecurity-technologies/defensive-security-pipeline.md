# Defensive security pipeline

**Comparison Table: Firewalls vs. IDS/IPS vs. SIEM vs. EDR**

| Feature                   | **Firewall (nftables, iptables, pfSense)** | **IDS/IPS (Snort, Suricata)**       | **SIEM (Wazuh, Splunk)**              | **EDR (CrowdStrike, Wazuh EDR)**             |
| ------------------------- | ------------------------------------------ | ----------------------------------- | ------------------------------------- | -------------------------------------------- |
| **Primary Role**          | Filter traffic based on rules              | Detect/block malicious traffic      | Log correlation, alerting, compliance | Detect/respond to endpoint threats           |
| **Detection Method**      | Rule-based (allow/deny)                    | Signature + anomaly detection       | Rule-based + anomaly (if configured)  | Behavioral analysis + threat intelligence    |
| **Prevention Capability** | Blocks traffic based on rules              | IPS can block, IDS alerts           | No (alerting only)                    | Can block processes, isolate hosts           |
| **Data Source**           | Network traffic (L3/L4 filtering)          | Network traffic (packet inspection) | Logs (network, endpoints, apps)       | Endpoint processes, memory, files            |
| **Scope**                 | Network perimeter/internal segmentation    | Network-focused                     | Broad (entire infrastructure)         | Endpoint-focused (workstations, servers)     |
| **Best For**              | Access control, network segmentation       | Real-time threat blocking           | Incident investigation, compliance    | Advanced malware, lateral movement detection |

A mature security stack combines:

1. **Firewall** → Blocks unauthorized access.
2. **IDS/IPS** → Stops known attacks in traffic.
3. **SIEM** → Correlates alerts from all sources.
4. **EDR** → Hunts for endpoint compromises.
5. **NTA (Network Trafific Analysis)** → Detects stealthy threats in network flows.
