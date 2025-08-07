# tcpdump

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
