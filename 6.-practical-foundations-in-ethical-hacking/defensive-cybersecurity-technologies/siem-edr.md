# SIEM/EDR

Popular open source SIEM/EDR (Security Information and Event Management/Endpoint Detection and Response) technologies ranked by approximate popularity and usage:

#### **1. Wazuh (SIEM + EDR)**

* **Popularity:** High (widely used in enterprises)
* **Features:**
  * Combines SIEM and EDR capabilities.
  * Log analysis, file integrity monitoring, vulnerability detection.
  * Real-time threat detection with rules from MITRE ATT\&CK.
  * Supports Windows, Linux, macOS, and cloud environments.
  * Integrates with Elasticsearch for visualization.

#### **2. TheHive (SIEM + Incident Response)**

* **Popularity:** High (especially for incident response)
* **Features:**
  * Case management and collaboration for security teams.
  * Integrates with MISP (Threat Intelligence Platform).
  * Supports automation via Cortex analyzers.
  * Helps in tracking and analyzing security incidents.

#### **3. Zeek (formerly Bro) (Network SIEM)**

* **Popularity:** High (especially for network monitoring)
* **Features:**
  * Network traffic analysis and logging.
  * Protocol-aware, generating detailed logs for HTTP, DNS, FTP, etc.
  * Can be used as a network security monitor (NSM).
  * Often paired with SIEMs for deeper analysis.

#### **4. OSSEC (HIDS - Host-based IDS + EDR)**

* **Popularity:** Medium (legacy but still widely used)
* **Features:**
  * File integrity monitoring, log analysis, rootkit detection.
  * Real-time alerting for suspicious activities.
  * Supports Windows, Linux, macOS, and BSD.
  * Often integrated with SIEMs like Wazuh.

#### **5. Suricata (Network IDS/IPS + EDR-like features)**

* **Popularity:** Medium (popular for intrusion detection)
* **Features:**
  * High-performance network IDS/IPS.
  * Real-time traffic inspection with rules (like Snort).
  * Supports file extraction and TLS/SSL logging.
  * Can be used alongside SIEMs for threat detection.

#### **6. Velociraptor (EDR + Digital Forensics)**

* **Popularity:** Growing (especially for DFIR)
* **Features:**
  * Endpoint visibility and forensic analysis.
  * Hunts for threats using VQL (Velociraptor Query Language).
  * Collects artifacts from endpoints for investigation.
  * Used by incident responders for live forensics.

***

**Notes:**

* **MISP (Threat Intelligence Platform)** – Often used alongside SIEMs for sharing threat indicators.
* **Elastic Security (SIEM + EDR)** – While Elasticsearch is open-source, some advanced EDR features require a paid license.

#### **Summary:**

* **Best Open-Source SIEM:** Wazuh (all-in-one) / TheHive (incident response).
* **Best Open-Source EDR:** Wazuh (basic EDR) / Velociraptor (advanced forensics).
* **Best Network Monitoring:** Zeek / Suricata.
