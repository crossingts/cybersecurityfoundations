# Packet analyzers — Quiz

### Packet analyzers

**1. A network analyst needs a tool for deep, interactive protocol dissection to troubleshoot a complex network issue, preferring a graphical user interface. Which tool is the best choice for this task? (Choose one answer)**\
a) tcpdump\
b) Zeek\
c) **Wireshark**\
d) Snort

**2. Which tool is primarily designed for large-scale, indexed packet capture and long-term storage, making it ideal for Security Operations Centers (SOCs) analyzing high-traffic networks? (Choose one answer)**\
a) tcpdump\
b) Zeek\
c) Snort\
d) **Arkime**

**3. The Berkeley Packet Filter (BPF) syntax is a crucial feature of tools like tcpdump. What is its primary advantage? (Choose one answer)**\
a) It automatically decrypts TLS/SSL traffic for easy analysis\
b) **It applies filters at the kernel level to capture only specified traffic, reducing resource usage**\
c) It generates structured logs of network sessions for forensic review\
d) It provides a web-based interface for searching through captured packets

**4. An engineer wants to capture only UDP traffic that is NOT DNS-related. Which of the following is a valid tcpdump command using BPF syntax to achieve this? (Choose one answer)**\
a) tcpdump 'udp and port 53'\
b) tcpdump 'not udp and not port 53'\
c) **tcpdump 'udp and not port 53'**\
d) tcpdump 'udp or port 53'

**5. According to the lesson, what is a key advantage of using passive techniques like packet sniffers for network monitoring, as opposed to active scanning techniques? (Choose one answer)**\
a) They can automatically block malicious traffic in real-time\
b) They are better at probing specific ports and protocols on demand\
c) **They are non-intrusive and do not introduce additional traffic onto the network**\
d) They provide deeper protocol dissection for application-layer protocols
