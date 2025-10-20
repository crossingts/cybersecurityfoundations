# Packet analyzers

## Learning objectives

* Point 1
* Point 2

This section covers...

## Topics covered in this section

* **Point 1**
* **Point 2**

Packet analyzers, also known as network sniffers or protocol analyzers or network analyzers, are essential tools for monitoring, troubleshooting, and securing network traffic. Packet analyzers capture raw data packets traversing a network, decode their headers and payloads, and present them in a human-readable format.

Effective network security requires real time awareness of the activities taking place on the network, to verify that the network policy is not being violated by any user or misconfiguration.

Active techniques to periodically scan the network have two disadvantages. First, they are intrusive, they introduce traffic into the network which consumes considerable bandwidth. Second, scanning can miss an activity, for example, when a specific port is probed with a specific protocol, because these look for a particular activity. These drawbacks can be addressed by using passive techniques where no traffic is introduced into the network. “Passive techniques have been in use in both defensive and offensive approaches for years but have only appeared recently in commercial products” (Treurniet, 2004, p. 1). “A sniffer is strategically placed on the network and the traffic is examined as it passes by. The behaviour of the traffic can be compared to an established policy for deviations” (Treurniet, 2004, p. iv). The passive technique can also identify information leaking form the network that could be used by malicious hackers. Attackers expect that active methods are used by organizations to test their own networks, so it “stands to reason, then, that more experienced attackers would also employ passive methods to obtain network information” (Treurniet, 2004, p. 2). Thus continuous surveillance or monitoring can be achieved using passive network sniffers to assess the security of a network.

Understanding packet analyzers is crucial for diagnosing connectivity issues, verifying routing and switching behavior, and detecting security threats such as unauthorized access or malware. Packet analyzers operate at different layers of the OSI model, with some focusing on low-level frame analysis (Ethernet, ARP) while others specialize in application-layer protocols (HTTP, DNS, VoIP).

Modern packet analyzers support filtering (e.g., BPF syntax in tcpdump), decryption (for TLS/SSL traffic with the right keys), and statistical analysis (e.g., throughput, latency). Some packet analyzers, like Wireshark, provide deep protocol dissection, while others, like Zeek and Suricata, focus on behavioral analysis and intrusion detection. Whether used for network forensics, performance tuning, or security auditing, packet analyzers are indispensable for network engineers, cybersecurity professionals, and system administrators.

* Become familiar with popular open source packet analyzers, their key features, and their common use cases

### **BPF (Berkeley Packet Filter) syntax in tcpdump**

BPF is a highly efficient packet-filtering mechanism used by tools like `tcpdump`, Wireshark, and Linux's `libpcap` to capture only the network traffic that matches specific criteria. Instead of capturing all packets and filtering them later (which is resource-intensive), BPF applies filters at the kernel level, reducing CPU and memory usage.

**Key Features of BPF Syntax in tcpdump:**

* **Expressive filtering**: Can match packets based on protocols (e.g., `tcp`, `udp`), IPs (`host 192.168.1.1`), ports (`port 80`), and even byte-level offsets.
* **Logical operators**: Supports `and` (`&&`), `or` (`||`), and `not` (`!`).
* **Directional filters**: Can filter by source/destination (`src`, `dst`).

**Example BPF Filters in tcpdump:**

sh

```
tcpdump 'tcp port 80 and host 192.168.1.1'  # Captures HTTP traffic to/from 192.168.1.1  
tcpdump 'icmp'                              # Captures only ICMP (ping) packets  
tcpdump 'udp and not port 53'               # Captures UDP traffic except DNS  
```

### Packet analyzers

Popular open source packet analyzers include Wireshark, tcpdump, Zeek, Snort, and Arkime.

Technology focus: Wireshark and tcpdump.

#### Packet analyzers key features

#### **1. Wireshark**

* **Type**: GUI-based packet analyzer
* **Key Features**:
  * **Deep protocol dissection** (supports 3,000+ protocols).
  * **Live capture** + **offline analysis** (PCAP files).
  * **Filtering** (BPF syntax, e.g., `tcp.port == 443`).
  * **Visualization** (flow graphs, I/O graphs).
  * **Decryption** (TLS/SSL with keys, WEP/WPA).
  * **Cross-platform** (Windows, Linux, macOS).
* **Use Case**: Deep protocol inspection and troubleshooting via GUI.

#### **2. tcpdump**

* **Type**: CLI packet analyzer
* **Key Features**:
  * **Lightweight**, low-overhead capture.
  * **BPF filtering** (e.g., `tcpdump -i eth0 'port 80'`).
  * **Save to PCAP** for later analysis.
  * **No GUI** (often used with Wireshark for analysis).
  * **Ubiquitous** (preinstalled on most Unix-like systems).
* **Use Case**: Lightweight CLI packet capture for quick traffic analysis.

#### **3. Zeek (formerly Bro)**

* **Type**: Network Traffic Analyzer (NTA)
* **Key Features**:
  * **Protocol-aware logging** (generates `.log` files for HTTP, DNS, SSL, etc.).
  * **Behavioral analysis** (e.g., detecting C2 traffic).
  * **No live packet inspection** (post-capture analysis).
  * **Custom scripting** (Zeek scripts for advanced detection).
* **Use Case**: Generates structured network logs for forensic analysis.

#### **4. Snort**

* **Type**: NIDS (Network Intrusion Detection System)
* **Key Features**:
  * **Packet capture + rule-based detection** (signatures).
  * **Real-time traffic analysis** (alerts on malicious activity).
  * **Can dump PCAPs** of suspicious traffic.
  * **CLI-based** (no native GUI).
* **Use Case**: Rule-based NIDS for real-time traffic inspection and alerting.

#### **5. Arkime** (formerly Moloch)

* **Type**: Large-scale packet capture + analysis
* **Key Features**:
  * **Indexes and stores PCAPs** for long-term analysis.
  * **Web GUI** for searching/filtering traffic.
  * **Scalable** (handles multi-gigabit traffic).
  * **Integrates with Suricata/Wazuh** for alerts.
* **Use Case**: Large-scale PCAP storage and indexed traffic analysis.

**Packet Analyzers Comparison Table**

| Tool          | Type             | Interface | Live Capture | Protocol Decoding | Key Strengths                        | Best For                         |
| ------------- | ---------------- | --------- | ------------ | ----------------- | ------------------------------------ | -------------------------------- |
| **Wireshark** | Packet Analyzer  | GUI       | Yes          | 3,000+ protocols  | Deep inspection, visualization       | Troubleshooting, forensics       |
| **tcpdump**   | Packet Sniffer   | CLI       | Yes          | Basic protocols   | Lightweight, scripting-friendly      | Quick captures, server debugging |
| **Zeek**      | Traffic Analyzer | CLI/Logs  | No\*         | 50+ protocols     | Behavioral analysis, logging         | Network forensics, research      |
| **Snort**     | NIDS             | CLI       | Yes          | Limited           | Rule-based detection, PCAP dumping   | Security monitoring              |
| **Arkime**    | PCAP Storage     | Web GUI   | Yes          | 100+ protocols    | Scalable, long-term packet retention | SOCs, large networks             |

**Packet Analyzers Selection Guide**

| Your Primary Need                                                 | Recommended Tool(s) | Key Reason                                                                                                                                                        |
| ----------------------------------------------------------------- | ------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Deep, interactive protocol analysis with a GUI**                | **Wireshark**       | The definitive tool for deep packet inspection, decryption, and visualization. Ideal for **general troubleshooting** and detailed **network forensics**.          |
| **Automation & scripting with structured output (JSON/CSV)**      | **TShark**          | The command-line version of Wireshark, easily integrated into scripts for **automation** and outputs in JSON/CSV for easy parsing.                                |
| **Quick, scriptable packet capture from the command line**        | **tcpdump**         | Lightweight, ubiquitous, and perfect for capturing traffic on servers or for **automation**. Excellent for **high-speed packet capture** due to its low overhead. |
| **Behavioral analysis and structured logging of network traffic** | **Zeek (Bro)**      | Generates high-level, structured logs (e.g., HTTP sessions) instead of raw packets, perfect for **behavioral analysis** and **security monitoring**.              |
| **Large-scale, indexed packet capture and retention**             | **Arkime (Moloch)** | Designed for storing and quickly searching PCAPs across high-traffic networks. The best choice for long-term storage in **network forensics**.                    |
| **High-speed packet capture and real-time threat detection**      | **Suricata**        | Multi-threaded for performance, offering **high-speed capture** and **real-time threat detection** via signature and anomaly-based analysis (IDS/IPS).            |
| **Established, open-source intrusion detection/prevention**       | **Snort**           | A widely-deployed and robust engine for **security monitoring (IDS/IPS)** using signature, protocol, and anomaly-based inspection.                                |

**Summary**

* For deep analysis: Wireshark (GUI) or tcpdump (CLI).
* For traffic logging: Zeek (creates structured logs).
* For security monitoring: Snort (NIDS mode).
* For large-scale PCAP storage: Arkime (web-based).
* For enterprise-scale analysis, Arkime + Suricata is a powerful combo.
* For low-level debugging, tcpdump + Wireshark is the gold standard.
* For threat hunting, Zeek + Suricata provides both logging and real-time detection.

### References

Sanders, C. (2017). _Practical packet analysis: Using Wireshark to solve real-world network problems_ (3rd ed.). No Starch Press.
