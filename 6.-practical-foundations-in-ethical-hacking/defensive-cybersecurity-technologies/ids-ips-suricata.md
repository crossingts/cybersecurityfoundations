# IDS/IPS—Suricata



### Snort vs. Suricata

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
