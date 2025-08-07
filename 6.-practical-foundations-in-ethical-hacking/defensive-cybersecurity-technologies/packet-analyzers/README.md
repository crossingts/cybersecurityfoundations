# Packet analyzers

## Topics covered

* **Packet analyzers background**
* **Popular open source packet analyzers**
* **Technology focus: Wireshark and tcpdump**

### Packet analyzers background

Packet analyzers, also known as network sniffers or protocol analyzers or network analyzers, are essential tools for monitoring, troubleshooting, and securing network traffic. Packet analyzers capture raw data packets traversing a network, decode their headers and payloads, and present them in a human-readable format.&#x20;

Effective network security requires real time awareness of the activities taking place on the network, to verify that the network policy is not being violated by any user or misconfiguration. A network can be periodically scanned to obtain real-time awareness.&#x20;

Active techniques to periodically scan the network have two disadvantages. First, they are intrusive, they introduce traffic into the network which consumes considerable bandwidth. Second, scanning can miss an activity, for example, when a specific port is probed with a specific protocol, because these look for a particular activity. These drawbacks can be addressed by using passive techniques where no traffic is introduced into the network. “Passive techniques have been in use in both defensive and offensive approaches for years but have only appeared recently in commercial products” (Treurniet, 2004, p. 1). “A sniffer is strategically placed on the network and the traffic is examined as it passes by. The behaviour of the traffic can be compared to an established policy for deviations” (Treurniet, 2004, p. iv). The passive technique can also identify information leaking form the network that could be used by malicious hackers. Attackers expect that active methods are used by organizations to test their own networks, so it “stands to reason, then, that more experienced attackers would also employ passive methods to obtain network information” (Treurniet, 2004, p. 2). Thus continuous surveillance or monitoring can be achieved using passive network sniffers to assess the security of a network.

Understanding packet analyzers is crucial for diagnosing connectivity issues, verifying routing and switching behavior, and detecting security threats such as unauthorized access or malware. Packet analyzers operate at different layers of the OSI model, with some focusing on low-level frame analysis (Ethernet, ARP) while others specialize in application-layer protocols (HTTP, DNS, VoIP).

Modern packet analyzers support filtering (e.g., BPF syntax in tcpdump), statistical analysis (e.g., throughput, latency), and decryption (for TLS/SSL traffic with the right keys). Some packet analyzers, like Wireshark, provide deep protocol dissection, while others, like Zeek and Suricata, focus on behavioral analysis and intrusion detection. Whether used for network forensics, performance tuning, or security auditing, packet analyzers are indispensable for network engineers, cybersecurity professionals, and system administrators.

#### **BPF (Berkeley Packet Filter)**

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

BPF is crucial for efficient packet analysis, especially in high-traffic networks.

**Decryption for TLS/SSL Traffic**

Modern encrypted protocols like **TLS (used in HTTPS, VPNs, etc.)** prevent packet analyzers from inspecting payloads by default. However, some tools (like Wireshark) can **decrypt TLS/SSL traffic** if provided with the necessary decryption keys.

**What Are The Necessary Decryption Keys?**

* **Pre-master secret key (for RSA-based TLS)**: If you have the server’s private key, Wireshark can decrypt traffic.
* **Session keys (for TLS 1.3 and forward)**: Requires logging the session keys during the handshake (e.g., via `SSLKEYLOGFILE` in browsers).
* **PSK (Pre-Shared Key)**: Used in some VPNs or custom encrypted apps.

**How It Works in Wireshark:**

1. **Configure Wireshark** to use the `SSLKEYLOGFILE` (exported by Chrome/Firefox).
2. **Provide the server’s private key** (if decrypting RSA-based HTTPS).
3. Wireshark **automatically decrypts** TLS traffic in real-time.

**Example Setup:**

sh

```
# Set SSLKEYLOGFILE in Linux/Mac before opening a browser  
export SSLKEYLOGFILE=/tmp/sslkeys.log  
```

Then, in Wireshark:\
`Edit → Preferences → Protocols → TLS → (Pre)-Master-Secret log filename` → Point to `sslkeys.log`.

**Limitations:**

* Decrypts HTTPS traffic only if session keys or private keys are available.
* **Cannot decrypt without keys**: If traffic uses **perfect forward secrecy (PFS)**, you must capture keys live (not retroactively).
* **Not all protocols supported**: Some custom encryption (e.g., proprietary VPNs) may not be decryptable.

### Popular open source packet analyzers

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
