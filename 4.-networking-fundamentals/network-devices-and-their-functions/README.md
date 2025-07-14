---
description: >-
  This section introduces core networking concepts and devices, including
  clients, servers, switches, routers, and firewalls
---

# Network devices and their functions

## Learning objectives

• Develop a basic understanding of the concepts of host, client, server, IP address, and network\
• Learn how to define network devices\
• Become familiar with major network devices and their role in network operations

This discussion introduces foundational concepts in computer networking and explains the functions of key networking components and devices. Key concepts discussed in this section include hosts, IP addresses, networks, repeaters, hubs, bridges, switches, and routers.

## Topics covered in this section

* **Host, client, server, IP address, network**
* **Network devices definition**
* **Repeaters, hubs, bridges, switches, and routers**
* **Nodes and endpoints**
* **Network devices icons**
* **Cisco devices examples**
* **Firewalls**

### Host, client, server, IP address, network

A host is any device that sends or receives traffic. It can be a client or a server. A client initiates a request for some data or a service. A server responds. A server is any computer which has software installed on it and which can respond to specific requests.

An IP address is the identity of a host. IP stands for [Internet Protocol](https://itnetworkingskills.wordpress.com/2023/01/15/network-protocols-their-functions/). Every host must have an IP address to communicate on the Internet. An IP (specifically, IPv4) address is comprised of 32 bits (4 bytes), represented as four octets. The value of each octet is represented in decimal numbers (e.g., 136.22.17.98). The smallest binary number you can get with 8 bits is zero; the largest is 255.

IP addresses are typically assigned in some sort of hierarchy. The breaking up of IP addresses into their different hierarchies is done through a process known as subnetting.

A network is what transports traffic between hosts. A computer network delivers data from one device to another. Any time you connect two hosts you have a network. A network is a logical grouping of hosts which require similar connectivity. Networks can contain other networks called sub-networks or subnets. The Internet is a bunch of interconnected networks.

Each network has its own IP address space and each host in the network has an IP address in that network’s IP address space (hosts on a network share the same IP address space). For example, a network can own all IP addresses which start with 192.168.1.x.

### Network devices definition

Network devices are components of electronic networks required for communication and interaction between devices on computer networks. Network devices mediate data transmission in a computer network.

Network devices are also known as network equipment or network hardware or networking hardware because traditionally they were physical components. Today, many network devices are virtualized or software-based.

<figure><img src="https://itnetworkingskills.wordpress.com/wp-content/uploads/2024/05/43ea5-network-devices-their-functions-1200x838px.webp?w=968" alt="network-devices-their-functions-1200x838px" height="675" width="968"><figcaption><p>Network devices examples (image courtesy of itrelease.com)</p></figcaption></figure>

There are many types of network devices, such as access points, firewalls, IDS/IPS, routers, and switches.

### Repeaters, hubs, bridges, switches, and routers

Repeaters regenerate signals, allowing devices to communicate across great distances. Connecting hosts directly to each other does not scale. Hubs connect multiple devices together, solving the scaling problem. Hubs are multi-port repeaters. A hub facilitates scaling communication between additional hosts. A hub will duplicate a packet and send it out to all ports on the hub. Everybody receives everybody else’s data.&#x20;

A bridge sits in between hub-connected hosts, connecting two hubs. Bridges only have two ports – each facing a different hub. Bridges learn which hosts are on which side of the bridge, which allows bridges to contain communication/channel packets to their relative networks. Bridges allow packets to traverse to the other side of the bridge when needed.

Switches have multiple ports (like hubs) and learn which hosts are on each port and can channel communication on a per port basis. A switch is a device that facilitates communication within a network.

You may want to separate sets of devices into separate networks because each set has its own connectivity requirements. A network boundary is what is meant to be a logical separation of devices.

A router is a device that facilitates communication between different networks. Routers connect networks to the Internet. Routers provide traffic control points (security, filtering, redirecting) between networks. Routers sit on the boundary between networks, providing a logical location to apply security policies.&#x20;

Routers learn which networks they are attached to. The knowledge of each different network is a route. Routes are stored in a routing table. A routing table is all the networks a router knows about. A router uses the routing table to funnel traffic to the appropriate interface.

Routers learn which networks they are attached to – meaning, routers have an interface assigned an IP address in every network they are attached to, and typically those interfaces act as a gateway for the connected networks. A gateway is a host’s way out of their local network.

If a host in the sales team of a corporation wants to speak to a host in the marketing team, it’s going to use its gateway, which is its closest router IP address, which is then going to send a packet to the next router, to the next router, and finally to the host in the marketing team.

Routers create the hierarchy in networks and IP addresses.

Routing is the process of moving data between networks. A router is a device which performs routing.

Switching is the process of moving data within networks. A switch is a device which performs switching.&#x20;

### Nodes and endpoints

The interconnection between various communication devices through different communication links can be defined as a network. The network is used to exchange, store, send, and retrieve data between network devices, also known as network nodes. (solarwinds.com)

So examples of network nodes would include routers, switches, firewalls, servers, and clients.

Servers and clients are sometimes called end hosts and end points (or endpoints). An endpoint is a computing device that communicates back and forth with the network it is connected to. Examples of endpoints include desktops, laptops, smartphones, tablets, and servers.

### Network devices icons

For illustration, here are icons used in Wendell Odom’s (2020) CCNA 200-301 Official Cert Guide.

<figure><img src="https://itnetworkingskills.wordpress.com/wp-content/uploads/2024/10/network-icons-used-in-odom-2020.webp?w=980" alt="common network devices" height="676" width="980"><figcaption><p>Icons of common network devices/technologies used in network diagrams (Odom, 2020)</p></figcaption></figure>

### Cisco devices examples

Enterprise computer networks typically consist of two types of networks: local area networks (LANs) and wide area networks (WANs). LANs typically connect devices on the same floor of a building. By comparison, WANs connect devices that are typically relatively far apart.&#x20;

Switches provide connectivity to end hosts within the same LAN. Standard (Layer 2) switches do not connect to the Internet. Switches forward data within a LAN. Switches do not provide connectivity over the Internet/between LANs.

Routers provide connectivity between LANs. Routers are used to send data over the Internet.

Typically end devices connect to a switch and the switch connects to a router which connects to the Internet. In network diagrams, usually a cloud is used to represent the Internet.

The following image shows some models of Cisco routers and switches. You can see router models ISR 1841 and ISR 2921, and switch models Catalyst 3560 and Catalyst Express 520.

<figure><img src="https://itnetworkingskills.wordpress.com/wp-content/uploads/2024/10/cisco-routers-switches.webp?w=1201" alt="cisco-routers-switches" height="598" width="1201"><figcaption><p>Cisco routers and switches (image courtesy of allbids.com.au)</p></figcaption></figure>

Notice that switches have many more network interfaces (ports) than routers. This is typical. For example, the Catalyst Express 520 shows 24 network interfaces we can connect end hosts or servers to. Switches typically have many RJ-45 ports because switches give user devices a place to connect to the Ethernet LAN.&#x20;

Other Cisco switch models include Catalyst 9200 and Catalyst 3650. And other Cisco router models include ISR 1000, ISR 900, and ISR 4000.

### Firewalls

Firewalls monitor and control network traffic based on configured rules. You explicitly configure which network traffic should be allowed into your network, and which should not.

Firewalls can be placed inside the network or outside the network. Meaning, the firewall can filter traffic before it reaches the router or after it has passed through the router.&#x20;

The ASA (Adaptive Security Appliance) is Cisco’s classic firewall. The following image shows the Cisco ASA 5500-X series firewall model.

Although the ASA is Cisco’s classic firewall, modern ASAs include modern features of next generation firewalls, including things like IPS (intrusion prevention system).&#x20;

<figure><img src="https://itnetworkingskills.wordpress.com/wp-content/uploads/2024/10/asa5500-x-series-firewall.webp?w=959" alt="ASA5500-X-series-firewall" height="546" width="959"><figcaption><p>ASA 5500-X series firewall (image courtesy of cisco.com)</p></figcaption></figure>

Firewalls are known as next-generation firewalls when they include more modern and advanced filtering capabilities.

Another example of an enterprise grade next-generation firewall is the Cisco Firepower 2100 series.&#x20;

ASA 5500-X and Firepower 2100 are network firewalls, which are hardware devices that filter traffic between networks. However, there are also host-based firewalls.

Host-based firewalls are software applications that filter traffic entering and exiting a host machine, like a PC. Your PC almost certainly has a software firewall installed. Even in a network with a hardware firewall, each PC should include a software firewall as an extra line of defense.

### Key takeways

* A host is any device that sends or receives traffic
  * a client initiates a request for some data or a service, a server responds
* An IP address is the identity of each host
* A network is what transports traffic between hosts
  * a network is a logical grouping of hosts which require similar connectivity
  * networks can contain other networks called sub-networks or subnets
* Network devices&#x20;
  * repeaters regenerate signals
  * hubs are multiport repeaters
  * bridges sit between hub-connected hosts
  * switches facilitate communication within a network
  * routers facilitate communication between networks

### References

[Free CCNA | Network Devices | Day 1 | CCNA 200-301 Complete Course](https://www.youtube.com/watch?v=H8W9oMNSuwo\&list=PLxbwE86jKRgMpuZuLBivzlM8s2Dk5lXBQ\&index=1)

[Hub, Bridge, Switch, Router – Network Devices – Networking Fundamentals – Lesson 1b](https://www.youtube.com/watch?v=H7-NR3Q3BeI\&ab_channel=PracticalNetworking)

[Network devices part 1: Network Devices – Hosts, IP Addresses, Networks – Networking Fundamentals – Lesson 1a](https://www.youtube.com/watch?v=bj-Yfakjllc\&ab_channel=PracticalNetworking)

Odom, W. (2020). CCNA 200-301 Official Cert Guide, Volume 1. Cisco Press.
