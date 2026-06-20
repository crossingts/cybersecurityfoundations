---
description: >-
  This section describes the roles of key Internet protocols and illustrates how
  they work together when you type a web address into a browser
---

# Network protocols in action

## Learning objectives

* Understand what network protocols are
* Understand how the TCP/IP model maps to the OSI model
* List the four parameters every host needs for Internet connectivity and explain how DHCP provides them
* Describe the roles of DNS, ARP, HTTP, SSL/TLS, and HTTPS in executing a web request
* Explain how the MAC address table, the ARP table, and the routing table enable data to move through the Internet
* Trace the journey of a web request (e.g., typing [www.google.com](https://www.google.com/)) using DNS, ARP, DHCP, HTTP/HTTPS, and the MAC address table, ARP table, and routing table

This section explains what network protocols are and how they enable communication across the Internet. You will learn how the TCP/IP model maps to the OSI model, how DHCP automatically configures a host with the four essential parameters for Internet connectivity, and how DNS translates domain names into IP addresses. The roles of ARP, HTTP, and HTTPS are described, and you will see all of these protocols in action by tracing a web request from a browser to a web server and back. Along the way, the MAC address table, ARP table, and routing table are introduced as the three core structures that routers and switches use to forward data hop by hop.

### Topics covered in this section

* What are network protocols?
* Key application layer and support protocols

#### What are network protocols?

First, let's define some key terms - What is a protocol? What are network protocols? And, what is an Internet protocol?

**What is a protocol?**

A protocol is a set of rules that govern communication.

In computing, a protocol is a convention or standard that controls or enables the connection, communication, and data transfer between computing endpoints. In its simplest form, a protocol can be defined as the rules governing the syntax, semantics, and synchronization of communication. Protocols may be implemented by hardware, software, or a combination of the two. At the lowest level, a protocol defines the behavior of a hardware connection. (Common Protocols, 2023, January 10)

While protocols can vary greatly in purpose and sophistication, most specify one or more of the following properties (Common Protocols, 2023, January 10):

* Detection of the underlying physical connection (wired or wireless), or the existence of the other endpoint or node.
* Handshaking (dynamically setting parameters of a communications channel).
* Negotiation of various connection characteristics.
* How to start and end a message.
* How to format a message.
* What to do with corrupted or improperly formatted messages (error correction).
* How to detect unexpected loss of the connection, and what to do next.
* Termination of the session and/or connection.

**What are network protocols?**

Network protocols or networking protocols are rules that dictate how network devices should exchange data across networks – how to format, transmit, and receive data, allowing network devices to communicate regardless of the differences in their underlying infrastructures or designs.

For our present discussion, network protocols refer to Internet protocols within the TCP/IP and OSI models. The rest of this section focuses on the protocols that are essential to every web request: DHCP, DNS, ARP, HTTP, and HTTPS.

**What is an Internet protocol?**

There are thousands of Internet protocols and all of them contribute to some sort of functionality in the Internet ecosystem. For our purposes, an Internet protocol refers to a protocol within the Internet protocol suite.

The Internet protocol suite is the set of communications protocols used for the Internet and other similar networks. It is comprised of a set of layers. Each layer “solves a set of problems involving the transmission of data, and provides a well-defined service to the upper layer protocols based on using services from some lower layers” (Common Protocols, 2023, January 10).

The Internet protocol suite is commonly known as the TCP/IP suite because the foundational protocols in the suite are the Transmission Control Protocol and the Internet Protocol.

The TCP/IP model (like the OSI model) is a formalized way of organizing and representing the various protocols of the Internet protocol suite into logical groupings of layers based on the functions of the protocols in facilitating the movement of data on networks.

**Mapping of the TCP/IP model to the OSI Model**

| TCP/IP               | OSI Model          | Protocols & Standards                                                                             |
| -------------------- | ------------------ | ------------------------------------------------------------------------------------------------- |
| Application Layer    | Application Layer  | DNS, DHCP, FTP, TFTP, HTTP, HTTPS, LDAP, NTP, POP3, RTP, RTSP, SSH, Telnet, SIP, SMTP, SNMP, MIME |
| Application Layer    | Presentation Layer | JPEG, ASCII, EBCDIC, MIDI, MPEG, PICT, TIFF, GIF                                                  |
| Application Layer    | Session Layer      | NetBIOS, NFS, PAP, SCP, RPC, SQL, ZIP                                                             |
| Transport Layer      | Transport Layer    | TCP, UDP, SPX                                                                                     |
| Internet Layer       | Network Layer      | ICMP, IGMP, IPsec, IPv4, IPv6, IPX, RIP, OSPF                                                     |
| Network Access Layer | Data Link Layer    | ARP, RARP, ATM, CDP, FDDI, Frame Relay, HDLC, MPLS, PPP, SLIP, STP, Token Ring                    |
| Network Access Layer | Physical Layer     | Bluetooth, DSL, Ethernet II, IEEE 802.3, IEEE 802.11 (WiFi), ISDN                                 |

**What is the Internet Protocol?**

The Internet Protocol (IP) is the principal protocol at the Internet layer (TCP/IP) or network layer (OSI). It relays datagrams across network boundaries, and its routing function essentially establishes the Internet.

There are two main versions of IP:

* IPv4 uses 32 bit addresses which limits the address space to 2 to the power of 32 unique IP addresses. This is equal to 4,294,967,296 IP addresses. The addressing architecture of IPv4 is defined in IETF publication RFC 791 (September 1981).
* IPv6 uses 128 bit addresses allowing for 2 to the power of 128 (about 3.4 x 10 to the power of 38) unique IP addresses. This is equal to 340 trillion trillion trillion IP addresses. The IPv6 addressing architecture is defined in RFC 4291 (February 2006). IPv4 remains widely deployed, but IPv6 adoption continues to grow rapidly.

#### Key application layer and support protocols

Now that we have defined network protocols and seen how they fit into the TCP/IP and OSI models, we turn to the specific protocols that make everyday Internet use possible. The following subsections describe DHCP, which automatically configures a host; DNS, which translates domain names to IP addresses; HTTP and HTTPS, which deliver web pages; and ARP, which resolves MAC addresses for local delivery.

**The DHCP protocol**

Every host needs four items for Internet connectivity. Anytime a host connects to a network there are four parameters that need to be configured on this host to achieve Internet connectivity.

**First**, an IP address. This serves as the host identity on the Internet.

**Second**, a subnet mask. This will tell the host the size of its local network. It will allow the host to determine if it’s trying to speak to something on its own network or to something on a foreign network. A subnet mask can look like this: /24. Or it can look like this: 255.255.255.0. Both of those are simply different ways of representing an identical subnet mask.

If a host only has an IP address and a subnet mask this will be sufficient to allow this host to speak to any other host on the same local network.

**Third**, a default gateway (default router). If a host needs to speak to something on a foreign network, for instance the Internet, that host is going to need a router. Specifically, that host is going to need the router’s IP address configured as that host’s default gateway.

With these three elements configured on a host, a host can speak through the router to the Internet to any server using its IP address. But most of the time, an Internet user is browsing websites and trying to send emails. In order for a host to speak to domains, it has to convert domain names into IP addresses first.

**Fourth**, a default DNS server. The fourth item that every host needs in order to achieve Internet connectivity is the IP address of a DNS server so that it can translate domain names to IP addresses, so that it can then communicate with other hosts using their domain names.

These four IP parameters must be configured on every host anytime it connects to a network.

Recall, a host is anything that sends or receives traffic on the Internet, which means a host could be your laptop or your printer or your mobile phone. In all cases every time any of these devices connects to a new network these devices must be configured with these four items.

Every time you connect to a new network your host will send a DHCP Discover message to discover the DHCP server and then the DHCP server will provide these four things in response back to the client. The client then has everything it needs in order to speak to the Internet. That is how every time you connect to a new Wi-Fi network, your phone or laptop automatically acquires the information it needs in order to speak to the Internet.

These four parameters must be configured on every host each time it joins a network – whether the device is a laptop, smartphone, or printer. Yet when you connect to a new Wi‑Fi network, you do not have to manually enter them. That is because the Dynamic Host Configuration Protocol (DHCP) works behind the scenes.

When a host connects to a network, it sends a DHCP Discover message. The DHCP server responds with an offer containing an IP address, subnet mask, default gateway, and DNS server address. The host automatically applies these settings and can then reach the Internet.

**Domain Name System (DNS)**

The DNS protocol is an application layer protocol that translates human‑readable domain names (e.g., [www.google.com](https://www.google.com/)) into IP addresses. Nearly every user interaction with the Internet begins with DNS.

To see DNS – and the other key protocols DHCP, ARP, HTTP, and HTTPS – in action, we will trace the classic interview question: "What happens when you type [www.google.com](https://www.google.com/) into a web browser?" The process relies on three tables that are fundamental to all network communication:

* MAC address table – on a switch, maps switch ports to MAC addresses.
* ARP table – on a host or router, maps IP addresses to MAC addresses.
* Routing table – on a host or router, maps destination networks to next‑hop IP addresses (or directly connected interfaces).

These tables are populated either in advance (routing table) or dynamically as traffic flows (ARP and MAC tables). The following walkthrough shows how they work together.

**HTTP and HTTPS**

HTTP (Hypertext Transfer Protocol) is the application layer protocol for communicating with web servers. A web browser (client) sends a GET request for a specific resource, and the server responds with a status code (often 200 OK) and the requested content. Web pages, written in HTML, are exchanged using HTTP over TCP.

<figure><img src="https://itnetworkingskills.wordpress.com/wp-content/uploads/2024/05/9640f-ssl-tls-protocols.webp" alt="HTTP request and response diagram" height="257" width="1144"><figcaption><p>HTTP governs the structure and language of the requests and responses that take place between clients and servers (source: Ed Harmoush, PracNet: Network Protocols)</p></figcaption></figure>

SSL (Secure Sockets Layer) and TLS (Transport Layer Security) are cryptographic protocols that create a secure, encrypted tunnel between client and server. When HTTP runs inside an SSL/TLS tunnel, the result is HTTPS (HTTP Secure). HTTPS protects data confidentiality and integrity, and it is what allows you to browse the web, enter passwords, and send payment information securely.

**ARP (Address Resolution Protocol)**

ARP is a Layer 2 protocol that maps an IP address to the corresponding MAC address, enabling a device to build the correct frame for the next hop. The rules for ARP requests and replies are defined in RFC 826. Because it is an open standard, any vendor can implement ARP, allowing devices from different manufacturers to communicate seamlessly.

The walkthrough that follows will show how hosts and routers use ARP to resolve MAC addresses at each hop.

* Host A uses ARP to find R1’s MAC address.
* R2 uses ARP to find Host B’s MAC address.
* The switch automatically learns MAC to port mappings by watching the source MAC addresses in frames, building its MAC address table without any separate protocol.

#### Typing [www.google.com](http://www.google.com) into a web browser

#### The topology for our example

To understand exactly how the protocols work together, we will trace the steps involved in sending and receiving a web request across the sample network shown in Figure 1.

<figure><img src="https://itnetworkingskills.wordpress.com/wp-content/uploads/2024/05/ed09f-type-google-into-web-browser-1.webp?w=1201" alt="Network topology with three hosts, three routers, and a switch" height="636" width="1201"><figcaption><p>Figure 1: Sample topology for tracing a web request. Host A is the client, Host B is a DNS server, and Host C is the web server for www.google.com. (Source: Ed Harmoush, PracNet)</p></figcaption></figure>

The topology contains three hosts (A, B, C), three routers (R1, R2, R3), and one switch. All devices have IP addresses in their respective subnets. The switch only needs its port numbers (port 4 and port 5); its MAC and IP addresses are irrelevant because traffic is passing through it, not to it. The routing tables are pre‑configured with directly connected routes and default routes (0.0.0.0/0), while the ARP and MAC tables are initially empty and will be filled as frames traverse the network.

#### Phase 1 & 2 – DNS query and response

When you type [www.google.com](http://www.google.com) into a browser, the browser needs the web server’s IP address. It asks the operating system to perform a DNS lookup. The operating system constructs a DNS query and hands it to the network stack for delivery.

**Transport layer encapsulation**\
Before any data is placed into an IP packet, it is wrapped in a Transport layer segment. The DNS query is carried inside a UDP datagram with destination port 53 (the standard DNS port). Later, after learning the web server’s IP address, the client will use TCP (ports 80 for HTTP or 443 for HTTPS), beginning with a three‑way handshake (SYN, SYN‑ACK, ACK) to establish a reliable connection.

**Phase 1 – DNS query (Host A → Host B)**

1. Host A builds an IP packet: source IP = 11.8.8.11, destination IP = 22.7.7.22 (DNS server).
2. Host A checks that the destination is on a foreign network, so it must send the packet to its default gateway (R1, 11.8.8.1).
3. Host A’s ARP table is empty. To learn R1’s MAC address, Host A sends an ARP request: a broadcast frame (destination MAC FFFF.FFFF.FFFF) asking “Who has 11.8.8.1? Tell 11.8.8.11.”
4. The switch receives the frame on port 4, learns that MAC address a1a1 is out port 4 (updating its MAC address table), and floods the broadcast out all other ports (port 5 to R1).
5. R1 receives the ARP request, learns that 11.8.8.11 maps to MAC a1a1, and sends a unicast ARP reply with its own MAC address eee1.
6. The switch sees this frame on port 5, learns that eee1 is out port 5, and forwards the unicast reply out port 4 to Host A.
7. Host A now has the ARP mapping (11.8.8.1 → eee1) and can build the Ethernet frame: source MAC a1a1, destination MAC eee1. The IP packet containing the DNS query is placed inside this frame.
8. The switch forwards the frame out port 5 to R1.
9. R1 strips the frame header, consults its routing table, and forwards the packet toward the Internet via its default route. The packet traverses multiple routers until it reaches R2.
10. R2 sees that the destination IP (22.7.7.22) matches a directly connected network. It must resolve Host B’s MAC address, so it broadcasts an ARP request for 22.7.7.22.
11. Host B responds with a unicast ARP reply, allowing R2 to learn the MAC address b2b2.
12. R2 encapsulates the packet in a frame with destination MAC b2b2 and delivers it directly to Host B.
13. Host B removes the L2 and L3 headers, processes the DNS query, and prepares a DNS response.

**Phase 2 – DNS response (Host B → Host A)**

Host B (DNS server) responds to host A (client/web browser).

Now we will go through all the steps required to get this data payload back through the network from host B to host A. This phase will go much quicker than before because most of our tables have already been populated.

<figure><img src="https://itnetworkingskills.wordpress.com/wp-content/uploads/2024/05/32577-type-google-into-web-browser-2.webp?w=1201" alt="type-google-into-web-browser-2" height="631" width="1201"><figcaption><p>Figure 2: What happens when you type http://www.google.com into a browser? (source: Ed Harmoush, PracNet: How Data moves)</p></figcaption></figure>

Most tables are now populated, so the return path is straightforward. Host B builds a packet (source 22.7.7.22, destination 11.8.8.11), sees that the destination is foreign, and uses its pre‑existing ARP entry for R2 to deliver the frame to the default gateway. R2 forwards the packet across the Internet to R1. R1 finds a directly connected route for 11.8.8.11, already has the ARP entry for a1a1, and delivers the frame via the switch to Host A. Host A extracts the DNS response and learns that [www.google.com](https://www.google.com/) resolves to the IP address of Host C (33.6.6.33).

#### Completing the web request: Phase 3 – HTTP GET

After receiving the DNS reply, Host A now knows the web server’s IP address (33.6.6.33) and can fetch the web page.

1. Transport layer – Host A’s browser initiates a TCP three‑way handshake with Host C on port 80 (HTTP) or 443 (HTTPS). Once the connection is established, the HTTP GET request is placed inside a TCP segment.
2. Sending the packet – Host A constructs an IP packet (source 11.8.8.11, destination 33.6.6.33). It determines the destination is foreign and uses its existing ARP entry for R1 to deliver the frame to the default gateway.
3. The frame reaches R1. R1 strips the L2 header, sees the destination matches its default route, and forwards the packet across the Internet.
4. The packet arrives at R3, which has a directly connected route for 33.6.6.0/24. Because R3’s ARP table is initially empty, it broadcasts an ARP request for 33.6.6.33.
5. Host C replies with its MAC address (c3c3). R3 updates its ARP table and encapsulates the packet in a frame destined to c3c3.
6. Host C receives the frame, strips L2 and L3 headers, and processes the HTTP GET request.
7. Response – Host C prepares the web page data, places it in an IP packet (source 33.6.6.33, destination 11.8.8.11), and sends it to its default gateway R3 (whose MAC it already knows). The packet travels back through the Internet, arrives at R1, and R1 forwards it directly to Host A using its existing ARP entry.
8. Host A receives the response, strips the headers, and the browser renders [www.google.com](https://www.google.com/).

The entire process—from typing the URL to seeing the page—happens in a fraction of a second, reusing the same ARP, MAC, and routing table entries many times.

#### Key takeaways

* DHCP supplies the four essential parameters (IP address, subnet mask, default gateway, DNS server) automatically when a host joins a network.
* DNS translates domain names into IP addresses. Every web visit begins with a DNS query, typically sent inside a UDP datagram.
* ARP maps IP addresses to MAC addresses; the ARP table is built dynamically. ARP allows a device to construct the correct Layer‑2 header for the next hop.
* The MAC address table on a switch maps ports to MAC addresses, learned automatically from incoming frames.
* The routing table on routers and hosts maps destination networks to next‑hop IP addresses. It must be pre‑populated with at least directly connected and default routes.
* HTTP (and its secure version HTTPS, which uses SSL/TLS) is the protocol for fetching web pages. The request/response conversation is governed by HTTP rules.
* Layered communication means that IP provides end‑to‑end addressing, Ethernet and ARP handle hop‑by‑hop delivery, and TCP/UDP provide process‑to‑process delivery with ports.
* Once you understand how the MAC address table, ARP table, and routing table interact in a small topology, you can trace packet delivery through networks of any size using the same logical steps.

#### References

[Common Protocols. (2023, January 10). Wikibooks, The Free Textbook Project. Retrieved 15:39, January 15, 2023 from https://en.wikibooks.org/wiki/Network\_Plus\_Certification/Technologies/Common\_Protocols](https://en.wikibooks.org/wiki/Network_Plus_Certification/Technologies/Common_Protocols)

[How Data moves through the Internet – Networking Fundamentals (PracNet)](https://www.youtube.com/watch?v=YJGGYKAV4pA\&ab_channel=PracticalNetworking)

[Internet Protocol. (2022, December 29). Wikipedia, The Free Encyclopedia. Retrieved 15:47, January 15, 2023, from https://en.wikipedia.org/wiki/Internet\_Protocol](https://en.wikipedia.org/wiki/Internet_Protocol)

[Network Protocols – ARP, FTP, SMTP, HTTP, SSL, TLS, HTTPS, DNS, DHCP – Networking Fundamentals – L6 (PracNet)](https://www.youtube.com/watch?v=E5bSumTAHZE\&ab_channel=PracticalNetworking)

Odom, W. (2020). CCNA 200-301 Official Cert Guide, Volume 1. Cisco Press.
