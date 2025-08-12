# tcpdump cheat sheet for netadmins/sysadmins

A quick-reference guide for packet capture, filtering, and network analysis using TCPDump—essential for netadmins and sysadmins troubleshooting connectivity, monitoring traffic, and diagnosing security issues.

This cheat sheet covers:

✔ **Basic & advanced packet capture**\
✔ **Filtering by host, port, protocol, and more**\
✔ **Output customization & performance tuning**\
✔ **Real-world use cases (HTTP, DNS, SSH, etc.)**

## **TCPDump Cheat Sheet for NetAdmins & SysAdmins**

_Packet Capture, Filtering, and Analysis_

***

### **1. Basic Capture**

#### **Capture on Any Interface**

sh

```
tcpdump -i any  
```

* `-i any`: Listen on all interfaces.

#### **Capture on Specific Interface**

sh

```
tcpdump -i eth0  
```

* `-i eth0`: Listen on `eth0`.

#### **Save Capture to File**

sh

```
tcpdump -i eth0 -w capture.pcap  
```

* `-w`: Write raw packets to file (`.pcap` format).

#### **Read from a PCAP File**

sh

```
tcpdump -r capture.pcap  
```

* `-r`: Read from a saved capture file.

#### **Limit Number of Packets**

sh

```
tcpdump -c 100  
```

* `-c 100`: Capture only 100 packets.

***

### **2. Filtering Traffic**

#### **Filter by Host (IP)**

sh

```
tcpdump host 192.168.1.100  
```

* Capture traffic **to/from** `192.168.1.100`.

#### **Filter by Source/Destination IP**

sh

```
tcpdump src 192.168.1.1  
tcpdump dst 192.168.1.100  
```

* `src`: Only **source** IP.
* `dst`: Only **destination** IP.

#### **Filter by Port**

sh

```
tcpdump port 80  
tcpdump portrange 20-23  
```

* `port`: Single port.
* `portrange`: Range of ports.

#### **Filter by Protocol**

sh

```
tcpdump icmp  
tcpdump tcp  
tcpdump udp  
tcpdump arp  
```

* Capture only specific protocols.

#### **Filter by Network (CIDR)**

sh

```
tcpdump net 192.168.1.0/24  
```

* Capture traffic within a subnet.

#### **Combine Filters (AND/OR)**

sh

```
tcpdump "src 192.168.1.1 and (dst port 80 or dst port 443)"  
```

* Use `and`, `or`, `not` for complex filters.

***

### **3. Advanced Filtering (BPF Syntax)**

#### **Filter by TCP Flags**

sh

```
tcpdump 'tcp[tcpflags] & (tcp-syn|tcp-ack) != 0'  
```

* `tcp-syn`: SYN packets.
* `tcp-ack`: ACK packets.
* `tcp-rst`: RST packets.

#### **Filter by Packet Size**

sh

```
tcpdump greater 1000  
tcpdump less 500  
```

* `greater`: Packets larger than X bytes.
* `less`: Packets smaller than X bytes.

#### **Filter by MAC Address**

sh

```
tcpdump ether host 00:1A:2B:3C:4D:5E  
```

* Capture traffic **to/from** a MAC address.

#### **Filter VLAN Traffic**

sh

```
tcpdump vlan 100  
```

* Capture traffic on VLAN 100.

***

### **4. Output & Verbosity**

#### **Show IPs Instead of Hostnames**

sh

```
tcpdump -n  
```

* `-n`: Disable DNS resolution (faster).

#### **Verbose Output**

sh

```
tcpdump -v  
tcpdump -vv  
tcpdump -vvv  
```

* `-v`: More details (checksum, TTL, etc.).

#### **Print Packet Contents (Hex & ASCII)**

sh

```
tcpdump -XX  
```

* `-XX`: Full packet hex dump.

#### **Show Absolute Sequence Numbers**

sh

```
tcpdump -S  
```

* `-S`: Displays raw TCP sequence numbers.

#### **Timestamps**

sh

```
tcpdump -tttt  
```

* `-tttt`: Human-readable timestamps.

***

### **5. Advanced Capture & Analysis**

#### **Capture Only HTTP Traffic**

sh

```
tcpdump -i eth0 port 80 -A  
```

* `-A`: Print ASCII (useful for HTTP headers).

#### **Capture FTP Passwords (Cleartext)**

sh

```
tcpdump -i eth0 port 21 -A  
```

* FTP sends credentials in plaintext.

#### **Capture DNS Queries**

sh

```
tcpdump -i eth0 port 53  
```

* Monitor DNS requests/responses.

#### **Capture ICMP (Ping/Traceroute)**

sh

```
tcpdump -i eth0 icmp  
```

* Useful for troubleshooting connectivity.

#### **Capture Only SYN Packets (New Connections)**

sh

```
tcpdump 'tcp[13] & 2 != 0'  
```

* Filters TCP SYN packets (new connections).

***

### **6. Performance & Storage Optimization**

#### **Limit Packet Size**

sh

```
tcpdump -s 96  
```

* `-s 96`: Capture only first 96 bytes (reduces size).

#### **Rotate Capture Files**

sh

```
tcpdump -i eth0 -w capture_%Y-%m-%d.pcap -G 3600  
```

* `-G 3600`: Rotate file every hour.

#### **Stop After X MB**

sh

```
tcpdump -i eth0 -C 100 -w capture.pcap  
```

* `-C 100`: Split files every 100MB.

#### **Run in Background**

sh

```
tcpdump -i eth0 -w capture.pcap &  
```

* `&`: Run in background (use `jobs` to check).

***

### **7. Common Use Cases**

| **Task**                   | **Command**                                          |
| -------------------------- | ---------------------------------------------------- |
| **Capture HTTP traffic**   | `tcpdump -i eth0 port 80 -A`                         |
| **Capture SSH traffic**    | `tcpdump -i eth0 port 22`                            |
| **Find suspicious IPs**    | `tcpdump -n "src net 192.168.1.0/24"`                |
| **Monitor VoIP (SIP/RTP)** | `tcpdump -i eth0 port 5060 or portrange 10000-20000` |
| **Detect ARP Spoofing**    | `tcpdump -i eth0 arp`                                |

***

### **8. Quick Reference Table**

| **Option**     | **Description**       |
| -------------- | --------------------- |
| `-i eth0`      | Listen on `eth0`      |
| `-w file.pcap` | Save to file          |
| `-r file.pcap` | Read from file        |
| `-c 100`       | Capture 100 packets   |
| `-n`           | Disable DNS lookup    |
| `-v`           | Verbose output        |
| `-XX`          | Hex + ASCII dump      |
| `src/dst`      | Filter by source/dest |
| `port 80`      | Filter by port        |
| `icmp/tcp/udp` | Filter by protocol    |

***

**Pro Tips:**\
✔ Use `-n` for faster captures (avoids DNS lookups).\
✔ Combine with `grep` for deeper analysis:

sh

```
tcpdump -i eth0 -A | grep "GET /"  
```

✔ Always **verify permissions** before capturing (`sudo` often required).

**For More:**

* `man tcpdump`
* [BPF Filter Syntax](https://www.tcpdump.org/manpages/pcap-filter.7.html)

***

### tcpdump’s offensive use cases with command examples

**1. Sniffing Plaintext Credentials**

**Purpose**: Capture unencrypted usernames, passwords, or session tokens.

**Commands & Techniques**

*   **HTTP Basic Auth**:

    sh

    ```
    tcpdump -i eth0 'port 80 and tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x41555448' -A
    ```

    * Filters HTTP traffic for `AUTH` strings (Base64 credentials).
*   **FTP/Telnet Credentials**:

    sh

    ```
    tcpdump -i eth0 'port 21 or port 23' -A -l | grep -i 'user\|pass'
    ```

    * Captures FTP/Telnet login attempts in plaintext.

***

**2. Reconnaissance (Network Mapping)**

**Purpose**: Identify live hosts, open ports, and services.

**Commands & Techniques**

*   **Detect ARP Requests** (Local Network):

    sh

    ```
    tcpdump -i eth0 'arp' -nn
    ```

    * Lists devices on the same subnet.
*   **Capture ICMP (Ping Sweeps)**:

    sh

    ```
    tcpdump -i eth0 'icmp[icmptype] == icmp-echo' -nn
    ```

    * Reveals hosts responding to ping probes.

***

**3. Man-in-the-Middle (MitM) Attacks**

**Purpose**: Intercept/modify traffic between two parties.

**Commands & Techniques**

*   **ARP Spoofing Traffic Capture**:

    sh

    ```
    tcpdump -i eth0 'host 192.168.1.105 and not arp' -w victim.pcap
    ```

    * Captures all traffic to/from a victim IP (after ARP poisoning).
*   **Session Hijacking (Cookies)**:

    sh

    ```
    tcpdump -i eth0 'port 80 and (tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x434f4f4b)' -A
    ```

    * Filters HTTP traffic for `COOK` (cookie headers).

***

**4. Exploit Development Support**

**Purpose**: Analyze protocols/apps for vulnerabilities.

**Commands & Techniques**

*   **Capture Vulnerable Protocols**:

    sh

    ```
    tcpdump -i eth0 'port 161 and udp' -w snmp_traffic.pcap
    ```

    * Captures SNMP (UDP/161) traffic for protocol analysis.
*   **Detect Buffer Overflow Patterns**:

    sh

    ```
    tcpdump -i eth0 'tcp port 9999 and greater 1000' -X
    ```

    * Inspects large payloads sent to a custom service (e.g., for crash analysis).

***

**5. Data Exfiltration Monitoring**

**Purpose**: Identify data being smuggled out of a network.

**Commands & Techniques**

*   **DNS Tunneling Detection**:

    sh

    ```
    tcpdump -i eth0 'dst port 53 and length > 100' -nn
    ```

    * Flags long DNS queries (possible tunneling).
*   **HTTP File Uploads**:

    sh

    ```
    tcpdump -i eth0 'port 80 and tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x504f5354' -A
    ```

    * Captures HTTP `POST` requests (file uploads).

***

**Key Takeaways**

* **Offensive Power**: tcpdump can be weaponized for stealthy attacks.
* **Critical Mitigation**:
  * Encrypt all traffic (SSH/TLS/IPSec).
  * Use VLANs/port security to limit sniffing.
  * Monitor for unauthorized tcpdump processes.
