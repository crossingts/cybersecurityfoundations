# IDS/IPS

Popular open source Intrusion Detection Systems/Intrusion Prevention Systems (IDS/IPS) ordered by relative popularity:&#x20;

#### **Suricata**

* **Type**: High-performance NIDS/NIPS
* **Features**:
  * Multi-threaded, supports **HTTP/2, TLS, and file extraction**.
  * **EVE JSON logs** for easy SIEM integration.
  * Supports **Lua scripting** for advanced detection.
* **Use Case**: Enterprise networks, high-speed traffic analysis.
* **Website**: [https://suricata.io/](https://suricata.io/)

#### **Snort**

* **Type**: Signature-based NIDS/NIPS
* **Features**:
  * Lightweight, rule-based detection.
  * Large community rule sets (Emerging Threats, Talos).
  * Can be used inline (IPS mode).
* **Use Case**: Small to medium networks, basic threat detection.
* **Website**: [https://www.snort.org/](https://www.snort.org/)

#### **Wazuh**

* **Type**: HIDS + SIEM (Fork of OSSEC with extended features)
* **Features**:
  * Combines **HIDS, log analysis, file integrity monitoring, and vulnerability detection**.
  * Integrates with **Elasticsearch** for visualization.
* **Use Case**: Endpoint security, compliance (PCI DSS, GDPR), and threat detection.
* **Website**: [https://wazuh.com/](https://wazuh.com/)

#### **OSSEC**

* **Type**: Host-based IDS (HIDS)
* **Features**:
  * Monitors file integrity, log analysis, rootkit detection, and active responses.
  * Can be used as a **centralized log analysis tool**.
* **Use Case**: Server security, compliance monitoring, and log-based intrusion detection.
* **Website**: [https://www.ossec.net/](https://www.ossec.net/)

#### **Fail2Ban**

* **Type**: Lightweight IPS (for log-based blocking)
* **Features**:
  * Scans log files (e.g., SSH, Apache) and bans malicious IPs.
  * Uses **iptables/nftables** for blocking.
* **Use Case**: Protecting servers from brute-force attacks.
* **Website**: [https://www.fail2ban.org/](https://www.fail2ban.org/)

#### **Zeek (formerly Bro)**

* **Type**: Network Analysis Framework (NIDS)
* **Features**:
  * Focuses on network traffic analysis rather than signature-based detection.
  * Generates detailed logs for protocols, files, and connections.
  * Highly customizable with scripting (Bro scripting language).
* **Use Case**: Best for network monitoring, forensics, and anomaly detection.
* **Website**: [https://zeek.org/](https://zeek.org/)

#### **Security Onion**

* **Type**: Network Security Monitoring (NSM) Suite (includes Suricata, Zeek, and other tools)
* **Features**:
  * Combines Suricata (IDS/IPS), Zeek (network analysis), and Elastic Stack (log analysis).
  * Provides a full **SIEM-like** environment for threat detection.
* **Use Case**: Enterprise-grade network security monitoring.
* **Website**: [https://securityonion.net/](https://securityonion.net/)

#### **AIDE (Advanced Intrusion Detection Environment)**

* **Type**: File Integrity Checker (HIDS)
* **Features**:
  * Creates a database of file hashes and detects unauthorized changes.
* **Use Case**: Server security & compliance auditing.
* **Website**: [http://aide.sourceforge.net/](http://aide.sourceforge.net/)

#### **Samhain**

* **Type**: HIDS (File integrity, log monitoring)
* **Features**:
  * Monitors file changes, rootkits, and suspicious processes.
  * Supports **centralized logging** and stealth operation.
* **Use Case**: Server integrity monitoring.
* **Website**: [https://www.la-samhna.de/samhain/](https://www.la-samhna.de/samhain/)

**OpenWIPS-NG**

* **Type**: Wireless IPS (WIPS)
* **Features**:
  * Detects and prevents **Wi-Fi attacks** (rogue APs, deauth attacks).
  * Works with **RF sensors** for wireless monitoring.
* **Use Case**: Wireless network security.
* **Website**: [https://openwips-ng.org/](https://openwips-ng.org/)

#### **Summary Table**

| **Tool**           | **Type**                   | **Best For**                              | Features |
| ------------------ | -------------------------- | ----------------------------------------- | -------- |
| **Suricata**       | High-performance NIDS/NIPS | High-speed networks, modern threats       |          |
| **Snort**          | Signature-based NIDS/NIPS  | Small/medium networks, legacy setups      |          |
| **Wazuh**          | HIDS + SIEM                | Endpoint security, compliance             |          |
| **OSSEC**          | HIDS                       | Log analysis, file integrity monitoring   |          |
| **Fail2Ban**       | Lightweight IPS            | Brute-force protection                    |          |
| **Zeek (Bro)**     | NIDS (Traffic Analysis)    | Network forensics, anomaly detection      |          |
| **Security Onion** | NSM Suite                  | Full network monitoring (Suricata + Zeek) |          |
| **AIDE**           | File Integrity             | Server security auditing                  |          |
| **Samhain**        | HIDS                       | Stealth monitoring, rootkit detection     |          |
| **OpenWIPS-NG**    | Wireless IPS               | Wi-Fi security                            |          |

#### **Which One Should You Choose?**

* **For network-based detection**: **Zeek** (if you need deep traffic analysis) or **Security Onion** (for a full SIEM-like setup).
* **For host-based security**: **Wazuh** (modern OSSEC fork with SIEM features) or **OSSEC**.
* **For wireless security**: **OpenWIPS-NG**.
* **For lightweight log-based blocking**: **Fail2Ban**.

***

**Snort vs. Suricata Key Differences and Similarities**

| **Feature**          | **Snort**                            | **Suricata**                        |
| -------------------- | ------------------------------------ | ----------------------------------- |
| **Detection Type**   | Signature-based NIDS/NIPS            | Signature + anomaly-based NIDS/NIPS |
| **Performance**      | Single-threaded                      | Multi-threaded (scales better)      |
| **Rule Sources**     | Talos, Emerging Threats (ET)         | ET Open, ET Pro, custom Lua rules   |
| **IPS Mode**         | Yes (inline via `afpacket`/`nfq`)    | Yes (inline via `nfqueue`)          |
| **Protocol Support** | Basic (HTTP, DNS, etc.)              | Advanced (HTTP/2, TLS, QUIC)        |
| **File Extraction**  | Limited (via preprocessors)          | Built-in (PCAP, files, TLS logs)    |
| **Logging Format**   | Plaintext, unified2 binary           | EVE JSON (SIEM-friendly)            |
| **Scripting**        | Limited (preprocessors in C)         | Lua scripting for advanced rules    |
| **Hardware Usage**   | Lower RAM/CPU                        | Higher RAM (due to multithreading)  |
| **Best For**         | Small/medium networks, legacy setups | High-speed networks, modern threats |

#### **Key Takeaways**

* **Snort** is simpler, lightweight, and ideal for smaller deployments.
* **Suricata** is more scalable, with modern protocol support and better SIEM integration.
* Both support **inline IPS mode**, but Suricata handles encrypted traffic (TLS) better.
