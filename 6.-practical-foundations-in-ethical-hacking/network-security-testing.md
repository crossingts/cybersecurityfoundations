---
hidden: true
---

# Network security testing

This section introduces tools and methodologies used in network security testing, including/more specifically, network scanners, vulnerability scanners, and sniffers.

This section introduces the following security testing tools and methodologies:

Linux-based live CD\
Network scanners\
Vulnerability scanners\
Packet analyzers

### Introduction

Network admins perform various monitoring and testing activities to ensure smooth and secure network operation:

• Connectivity testing/troubleshooting (basic netadmin) using such tools/technologies as, ping, traceroute, whois, nslookup, dig, netstat, nbtstat, arp, and syslog.

• Network availability monitoring (part of Network Management System) to determine the availability of network resources to the users using such tools as Big Brother, OpenNMS, and Nagios. Network availability monitoring is "the concept of observing, measuring, and comparing the performance of a computer network using both technology and personnel". The purpose of network availability monitoring is "to detect faults within a network and ensure steady network operations" (Deveriya, 2005, p. 270).

Typically, a network-monitoring system is comprised of Windows- or UNIX-based network-ready computers loaded with network-monitoring software. The network-monitoring system polls the monitored nodes at regular intervals to determine the overall health of the network and its components. Based on the polled results, the network-monitoring system generates alerts. These alerts can be e-mailed, sent through pager messages, or relayed through a web page. The network-monitoring system also stores the historical data for reporting and trending. (Deveriya, 2005, p. 270)

Key concepts related to network availability monitoring include SLAs (Service-Level Agreements), MTTR (mean time to repair), and Five Nines.

• Network performance monitoring (part of NMS), SNMP-based MRTG (monitor +manage devices), CiscoWorks. Focus: Network performance monitoring is the process of collecting, storing, and analyzing network statistics. The most common parameters for monitoring network performance are: Throughput kbps, Latency, Jitter, packet loss, CPU and memory utilization of a network device, hard device space.

• Network security testing - to assess and verify the threats and vulnerabilities of a network.&#x20;

### Network Security Testing Overview

The process of testing network security is also known as any of the following:

Security audit\
Penetration testing\
Posture assessment\
Ethical hacking\
Vulnerability assessment

The tools used for security auditing can be loosely classified into the following two categories:

• Scanners - Active tools that send out probe packets to the target host or network to attack or gather information.\
• Packet analyzers - Passive in their operation because they do not send probe packets. Instead, packet analyzers work by capturing and analyzing the data that is flowing across the network.

Bootable CD-ROM–Based Tool Kits

The Knoppix CD-ROM provides an easy-to-use graphical user interface (GUI) with basic security-testing tools, including Nmap, Nessus, Ethereal, and Tcpdump. Knoppix also includes the following tools and services…

#### Network Scanners

Network scanners are software tools that probe a network to determine the hosts present on\
the network. Network scanners also probe the discovered hosts to determine the TCP and\
UDP ports that are open. Furthermore, based on the response of the probes, scanners can\
identify the OS, the services that are running, and the associated security vulnerabilities\
present on the discovered hosts. Some scanners can also display the results in the form of\
graphical reports. Some of the most popular open source network scanners are as follows:

Nmap (the Swiss army knife of network scanners; a popular and versatile tool), Netcat, Nessus.

#### Packet Analyzers

Packet analyzers are software or hardware devices that capture and analyze the data flowing through the network. Packet analyzers are also called sniffers, protocol analyzers, and network analyzers … Many packet analyzers provide capabilities to filter, store, and analyze the captured data. In fact, most network intrusion detection systems (NIDS) are packet analyzers that watch for peculiar traffic patterns that are unique to network attacks. Packet analyzers work at Layers 1 and 2 of the OSI model but can also decode data at higher layers. This feature enables networking professionals to have a cross-sectional view of the data flowing through the network in real time. The ability to slice and view the raw data flowing through the wires is important when troubleshooting. Such views also help networking professionals to learn and understand the functioning of various protocols and applications. The views also provide clear proof that the network and its components are operational.

Both Tcpdump and Ethereal are powerful tools capable of sniffing and analyzing network traffic. Both packet analyzers are under active development and enjoy community wide support. The following sections cover these tools in more detail.

### References

Network Administrators Survival Guide (Anand Deveriya, 2005)
