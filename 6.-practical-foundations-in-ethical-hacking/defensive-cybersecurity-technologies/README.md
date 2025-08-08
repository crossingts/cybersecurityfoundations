---
description: >-
  This section focuses on popular open source defensive cybersecurity
  technologies such as firewalls, IDS/IPS, SIEM/EDR, and packet analyzers
---

# Defensive cybersecurity technologies

## Learning objectives

* Become familiar with popular open source host- and network-based firewalls
* Understand the difference between Web Application Firewalls (WAFs) and packet-filtering firewalls
* Become familiar with popular open source host- and network-based IDS and their key features
* Become familiar with popular open source security event management technologies and their key features
* Become familiar with popular open source packet analyzers and their common use cases

This section looks at popular open source defensive cybersecurity technologies, exploring their key characteristics and deployment (use cases). Key categories of defensive cybersecurity technologies discussed include host/network firewalls (e.g., UFW, iptables, nftables, PF, OPNsense, and pfSense), IDS/IPS (e.g., Suricata and Snort), network security monitoring/SIEM (e.g., Wazuh and OSSEC), and packet analyzers (e.g., Wireshark and tcpdump).

## Topics covered in this section

* **Firewalls**
* **IDS/IPS**
* **SIEM/EDR**
* **Packet analyzers**

### Firewalls

Popular open source host and network firewalls include UFW (Uncomplicated Firewall), iptables, nftables, PF or pfilter (packet filter), OPNsense, and pfSense (Community Edition).

Technology focus: nftables and OPNsense.

### IDS/IPS

Popular open source NIDS and HIDS include Suricata, Snort, Wazuh, OSSEC, Fail2Ban, Zeek (formerly Bro), Security Onion, and OpenWIPS-NG.

Technology focus: Suricata.

### SIEM/EDR

Popular open source SIEM/EDR (Security Information and Event Management/Endpoint Detection and Response) technologies include Wazuh, TheHive, Zeek, OSSEC, Suricata, and Velociraptor.

Technology focus: Wazuh (SIEM/XDR).

### Packet analyzers

Popular open source packet analyzers include Wireshark, tcpdump, Zeek, Snort, and Arkime.

Technology focus: Wireshark and tcpdump.

### Key takeaways

* Popular open source host-based firewalls include nftables and pf&#x20;
* Popular open source network-based firewalls include OPNsense and pfSense (CE)
* Packet-filtering firewall technologies such as iptables and pfilter (PF) operate at the network level (Layer 3/4)
* WAFs operate at the Application level (L7) and can be host- and network-based
* Popular open source HIDS include Wazuh and OSSEC
* Popular open source NIDS include Suricata and Snort
* Popular open source SIEM include Wazuh and TheHive
* Popular open source packet analyzers include Wireshark and tcpdump
