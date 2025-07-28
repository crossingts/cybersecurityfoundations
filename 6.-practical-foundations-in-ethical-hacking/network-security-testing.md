# Network security testing

### Introduction

Network admins perform various monitoring and testing activities to ensure smooth and secure network operation. These activities include:

• **Connectivity testing/troubleshooting** (basic netadmin) using such tools/technologies as ping, traceroute, whois, nslookup, dig, netstat, nbtstat, arp, and syslog.

• **Network availability monitoring** (part of Network Management System) to determine the availability of network resources to the users using such tools as Big Brother, OpenNMS, and Nagios. Network availability monitoring is "the concept of observing, measuring, and comparing the performance of a computer network using both technology and personnel". The purpose of network availability monitoring is "to detect faults within a network and ensure steady network operations" (Deveriya, 2005, p. 270).

Typically, a network-monitoring system is comprised of Windows- or UNIX-based network-ready computers loaded with network-monitoring software. The network-monitoring system polls the monitored nodes at regular intervals to determine the overall health of the network and its components. Based on the polled results, the network-monitoring system generates alerts. These alerts can be e-mailed, sent through pager messages, or relayed through a web page. The network-monitoring system also stores the historical data for reporting and trending. (Deveriya, 2005, p. 270)

Key concepts related to network availability monitoring include SLAs (Service-Level Agreements), MTTR (mean time to repair), and Five Nines.

• **Network performance monitoring** (part of NMS) to determine the adequacy of key performance parameters of network devices and links using such tools as MRTG and Cacti. Network performance monitoring is "the process of collecting, storing, and analyzing network statistics" (Deveriya, 2005, p. 314).&#x20;

Typically, performance-monitoring systems use the Simple Network Management Protocol (SNMP) to communicate with the monitored hosts. Using SNMP, the performance-monitoring system regularly polls the monitored hosts and collects performance-parameter samples. The samples are then stored in a central database for analysis and reporting, such as historical trending. (Deveriya, 2005, p. 314)

The most common parameters for monitoring network performance are throughput (kbps), latency (ms/RTT), jitter, packet loss, CPU and memory utilization of network devices, and hard device space.

• **Intrusion detection systems/intrusion prevention systems (IDS/IPS)** using such tools as Suricata and Snort. Most network intrusion detection systems (NIDS) are packet analyzers that watch for peculiar traffic patterns that are unique to network attacks.

• **Incident response and mitigation (SIEM) and endpoint detection and response (EDR)** using such tools as Wazuh SIEM/XDR.

• **Host and network firewalls** using such tools as ufw, iptables, nftables, pf (packet filter = CLI based macOS built-in Unix firewall), and OPNsense/pfsense.

• **Network security testing** - netadmins perform network security testing to assess and verify the threats and vulnerabilities of their network.&#x20;

### Network security testing

Network security is an ongoing process that can be described by the Cisco security wheel. The security wheel (Figure 7-1) consists of the following four phases: Secure, Monitor, Test, and Improve.

<figure><img src="../.gitbook/assets/image (15).png" alt=""><figcaption><p>Cisco Security Wheel (image courtesy of Deveriya, 2005, p. 362)</p></figcaption></figure>

The third phase, Test, or network security testing, helps netadmins verify the security design and\
discover vulnerabilities within a network.

The process of network security testing is also commonly known as security audit, security assessment, posture assessment, vulnerability assessment, penetration testing, and ethical hacking. All these terms are invoked to refer to "a legitimate process of attacking, discovering, and reporting security holes in a network" (Deveriya, 2005, p. 362).

Tools used for security auditing can be loosely classified into the following two categories:

* Scanners - Active tools that send out probe packets to the target host or network to attack or gather information.
* Packet analyzers - Passive in their operation because they do not send probe packets. Instead, packet analyzers work by capturing and analyzing the data that is flowing across the network.

The following discussion introduces the following tools and methodologies of network security testing:

• Network scanners - Nmap network scanner

• Vulnerability scanners - OpenVAS vulnerability scanner (forked Nessus)

• Packet analyzers (sniffers) - Wireshark, Tcpdump

#### Network Scanners

Network scanners are software tools that probe a network to determine the hosts present on\
the network. Network scanners also probe the discovered hosts to determine the TCP and\
UDP ports that are open. Furthermore, based on the response of the probes, scanners can\
identify the OS, the services that are running, and the associated security vulnerabilities\
present on the discovered hosts. Some scanners can also display the results in the form of\
graphical reports. (Deveriya, 2005, p. 365)

Some of the most popular open source network scanners are Nmap, Nessus, and Netcat.

• **Nmap** (Network Mapper): The Swiss army knife of network scanners; a popular and versatile tool.

• **Nessus** (proprietary since October 5, 2005): A popular **vulnerability scanner** with the ability to regularly update the vulnerability database; comes preinstalled with many Linux live CD-ROMs; and has good reporting capability.&#x20;

Nessus turned commercial in October 2005 but a limited feature version is available (Nessus Essentials provides high-speed, in-depth vulnerability scanning for up to 16 IP addresses per scanner).

Vulnerabilities are the weaknesses in an operating system or software that can potentially be exploited by malicious users with an intent to cause system damage. Network vulnerability scanners such as Nessus provide security vulnerability detection and reporting for networks and host systems. (Deveriya, 2005, p. 377)

• **Netcat**: A port scanner with the additional capability to read and write data across a network through TCP and UDP ports.

#### Technology focus: Nmap

Nmap is highly versatile tool used for port scanning and network enumeration. Nmap also looks for services that are running on hosts by scanning TCP and UDP ports. Nmap is an integral part of every network security professional's tool kit (Deveriya, 2005).

Some of the routine (and cumbersome) netadmin tasks that Nmap can do are as follows:

* Verify unused IP addresses in a network&#x20;
* Verify available hosts in a network&#x20;
* Verify services running on a host in a network&#x20;
* Verify the firewall security configurations&#x20;
* Verify the OS running on a remote host&#x20;

Nmap uses Internet Control Message Protocol (ICMP) ping scans for network discovery as well as other scanning techniques using TCP and UDP packets. These techniques enable network scanning even if ICMP traffic is blocked in a network.

#### Packet Analyzers

Packet analyzers are software or hardware devices that capture and analyze the data flowing through the network. Packet analyzers are also called sniffers, protocol analyzers, and network analyzers … Many packet analyzers provide capabilities to filter, store, and analyze the captured data. In fact, most network intrusion detection systems (NIDS) are packet analyzers that watch for peculiar traffic patterns that are unique to network attacks. Packet analyzers work at Layers 1 and 2 of the OSI model but can also decode data at higher layers. This feature enables networking professionals to have a cross-sectional view of the data flowing through the network in real time. The ability to slice and view the raw data flowing through the wires is important when troubleshooting. Such views also help networking professionals to learn and understand the functioning of various protocols and applications. The views also provide clear proof that the network and its components are operational. (Deveriya, 2005, p. 386)

Wireshark and Tcpdump are powerful tools capable of sniffing and analyzing network traffic.

### References

Network Administrators Survival Guide (Anand Deveriya, 2005)
