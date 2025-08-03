# Packet analyzers

Popular open source packet analyzers ranked by approximate popularity and usage, along with their key features:

#### **1. Wireshark**

* **Most widely used** GUI-based packet analyzer.
* Supports **deep inspection** of hundreds of protocols.
* Live capture & offline analysis.
* Cross-platform (Windows, Linux, macOS).
* Advanced filtering (BPF syntax) and decryption support (TLS, SSL).

#### **2. TShark (CLI version of Wireshark)**

* Command-line equivalent of Wireshark.
* Ideal for **scripting & automation**.
* Same powerful dissection capabilities as Wireshark.
* Output in JSON, CSV, XML, and other formats.

#### **3. tcpdump**

* **Lightweight CLI packet sniffer** for Unix-like systems.
* Uses **BPF (Berkeley Packet Filter)** for efficient capture.
* Minimal overhead, great for remote servers.
* Output can be piped into Wireshark for analysis.

#### **4. Zeek (formerly Bro)**

* **Network security monitoring** tool, not just a sniffer.
* Focuses on **behavioral analysis** (e.g., detecting anomalies).
* Generates high-level logs (HTTP, DNS, SSH) instead of raw packets.
* Scriptable for custom traffic analysis.

#### **5. Suricata**

* **Real-time IDS/IPS (Intrusion Detection/Prevention System)**.
* Multi-threaded for **high-speed traffic analysis**.
* Supports **automated threat detection** (signature & anomaly-based).
* Can export PCAPs for further analysis.

#### **6. Snort**

* One of the oldest **open-source IDS/IPS** tools.
* Rule-based detection (malware, exploits, port scans).
* Can work in **sniffer, logger, or IPS mode**.
* Large community rule sets available.

#### **7. Arkime (formerly Moloch)**

* **Large-scale packet capture & indexing** (for full traffic retention).
* Web-based interface for searching and analyzing stored PCAPs.
* Used by enterprises and ISPs for **forensic analysis**.

#### **Recommendations Based on Use Cases**

| **Use Case**                      | **Best Tool(s)**           | **Why?**                                                                         |
| --------------------------------- | -------------------------- | -------------------------------------------------------------------------------- |
| **General Troubleshooting**       | Wireshark, TShark          | Deep protocol inspection, user-friendly GUI (Wireshark), CLI scripting (TShark). |
| **High-Speed Packet Capture**     | tcpdump, Suricata          | Low overhead (tcpdump), multi-threaded analysis (Suricata).                      |
| **Security Monitoring (IDS/IPS)** | Suricata, Zeek, Snort      | Real-time threat detection, signature & anomaly-based analysis.                  |
| **Network Forensics**             | Arkime (Moloch), Wireshark | Long-term packet storage (Arkime), detailed analysis (Wireshark).                |
| **Automation & Scripting**        | TShark, tcpdump            | Easily integrated into scripts (TShark for JSON/CSV, tcpdump for BPF).           |
| **Behavioral Analysis**           | Zeek (Bro)                 | Generates high-level logs (e.g., HTTP sessions) instead of raw packets.          |

**Additional Notes:**

* For **enterprise-scale analysis**, **Arkime + Suricata** is a powerful combo.
* For **low-level debugging**, **tcpdump + Wireshark** is the gold standard.
* For **threat hunting**, **Zeek + Suricata** provides both logging and real-time detection.
