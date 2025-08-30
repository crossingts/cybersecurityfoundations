---
description: >-
  This section describes the roles of the network protocols ARP, FTP, SMTP,
  HTTP, SSL, TLS, and HTTPS  in data transmission over the Internet
---

# Network protocols and their functions

## Learning objectives

• Understand what are network protocols\
• Understand how the TCP/IP model maps to the OSI model\
• List and describe the four parameters every host needs to achieve Internet connectivity\
• Understand the roles of the DHCP protocol and the DNS protocol in Internet communication\
• Describe the functions of the network protocols ARP, FTP, SMTP, HTTP, SSL, TLS, and HTTPS

This section discusses several important [network protocols and their functions](https://www.comptia.org/content/guides/what-is-a-network-protocol). Key concepts discussed in this section include the TCP/IP model, and the functions of the network protocols ARP, FTP, SMTP, HTTP, SSL, TLS, HTTPS, DHCP, and DNS.

## Topics covered in this section

* **What are network protocols?**
* **The DHCP protocol**
* **Network protocols ARP, FTP, SMTP, HTTP, SSL, TLS, and HTTPS**
* **The DNS protocol**

### What are network protocols?

First let’s differentiate between some key networking terms pertaining to protocols.

**What are network protocols?**

Network protocols or networking protocols are rules that dictate how network devices should exchange data across networks – how to format, transmit, and receive data, allowing network devices to communicate regardless of the differences in their underlying infrastructures or designs.

For our present discussion, network protocols refer to Internet protocols within the TCP/IP and OSI models. Here we will only discuss the following important network protocols relevant to the overall goal of this chapter of understanding how data flow through the Internet: ARP, FTP, SMTP, HTTP, SSL, TLS, HTTPS, DHCP, and DNS.

But let’s roll back our definition of network protocols to further clarify its intended meaning and offer a broader view of the topic of Internet protocols.

**What is a protocol?**

A protocol is a set of rules and messages that form an Internet standard.

In computing, a protocol is a convention or standard that controls or enables the connection, communication, and data transfer between computing endpoints. In its simplest form, a protocol can be defined as the rules governing the syntax, semantics, and synchronization of communication. Protocols may be implemented by hardware, software, or a combination of the two. At the lowest level, a protocol defines the behavior of a hardware connection. (Common Protocols, 2023, January 10)

While protocols can vary greatly in purpose and sophistication, most specify one or more of the following properties (Common Protocols, 2023, January 10):

* Detection of the underlying physical connection (wired or wireless), or the existence of the other endpoint or node
* Handshaking (dynamically setting parameters of a communications channel)
* Negotiation of various connection characteristics
* How to start and end a message
* How to format a message
* What to do with corrupted or improperly formatted messages (error correction)
* How to detect unexpected loss of the connection, and what to do next
* Termination of the session and or connection.

**What is an Internet protocol?**

There are thousands of Internet protocols and all of them contribute to some sort of functionality in the Internet ecosystem. For our purposes, an Internet protocol refers to a protocol within the Internet protocol suite.

The Internet protocol suite is the set of communications protocols used for the Internet and other similar networks. It is comprised of a set of layers. Each layer “solves a set of problems involving the transmission of data, and provides a well-defined service to the upper layer protocols based on using services from some lower layers” (Common Protocols, 2023, January 10).

The Internet protocol suite is commonly known as the TCP/IP suite because the foundational protocols in the suite are the Transmission Control Protocol and the Internet Protocol.

The TCP/IP model (like the OSI model) is a formalized way of organizing and representing the various protocols of the Internet protocol suite into logical groupings of layers based on the functions of the protocols in facilitating the movement of data on networks.

#### Mapping of the TCP/IP model to the OSI Model

| TCP/IP            | OSI Model          | Protocols & Standards                                                                             |
| ----------------- | ------------------ | ------------------------------------------------------------------------------------------------- |
| Application Layer | Application Layer  | DNS, DHCP, FTP, TFTP, HTTP, HTTPS, LDAP, NTP, POP3, RTP, RTSP, SSH, Telnet, SIP, SMTP, SNMP, MIME |
|                   | Presentation Layer | JPEG, ASCII, EBDIC, MIDI, MPEG, PICT, TIFF. GIF                                                   |
|                   | Session Layer      | NetBIOS, NFS, PAP, SCP, RPC, SQL, ZIP                                                             |
| Transport Layer   | Transport Layer    | TCP, UDP, SPX                                                                                     |
| Internet Layer    | Network Layer      | ICMP, IGMP, IPsec, IPv4, IPv6, IPX, RIP, OSPF                                                     |
| Link Layer        | Data Link Layer    | ARP, RARP, ATM, CDP, FDDI, Frame Relay, HDLC, MPLS, PPP, SLIP, STP, Token Ring                    |
|                   | Physical Layer     | Bluetooth, DSL, Hub, Ethernet II, IEEE 802.3, IEEE 802.11 (WiFi), ISDN                            |

**What is the Internet Protocol?**

The Internet Protocol (IP) is the Internet layer (TCP/IP model) or network layer (OSI model) communications protocol in the Internet protocol suite for relaying datagrams across network boundaries. “Its routing function enables internetworking, and essentially establishes the Internet” (Internet Protocol, 2022, December 29).

There are two main versions of IP: IPv4 and IPv6 (v equals version). IPv4 uses 32 bit addresses which limits the address space to 2 to the power of 32 unique IP addresses. This is equal to 4,294,967,296 IP addresses. IPv6 uses 128 bit addresses allowing for 2 to the power of 128 (about 3.4 x 10 to the power of 38) unique IP addresses. This is equal to 340 trillion trillion trillion IP addresses. The addressing architecture of IPv4 is defined in IETF publication RFC 791 (September 1981). IPv6 is defined in IETF publication RFC 4291 (July 2017). IPv4 is used by 99% of the networks, while IPv6 is used by less than 1% of the networks.

We elaborated the OSI model in section 2 The Open Systems Interconnection (OSI) model, and there we discussed the functions of network protocols not discussed in this section such as TCP and UDP. So feel free to review section 2 of this chapter.

### The DHCP protocol

Every host needs four items for Internet connectivity. Anytime a host connects to a network there are four items that need to be configured on this host to achieve Internet connectivity.

**First**, an IP address. This serves as the the host identity on the Internet.

**Second**, a subnet mask. This will tell the host the size of its network. It will allow the host to determine if it’s trying to speak to something on its own network or to something on a foreign network. A subnet mask can look like this: /24. Or it can look like this: 255.255.255.0. Both of those are simply different ways of representing an identical subnet mask.

If a host only has an IP address and a subnet mask this will be sufficient to allow this host to speak to any other host on the same local network.

**Third**, a default gateway (default router). If a host needs to speak to something on a foreign network, for instance the Internet, that host is going to need a router. Specifically, that host is going to need the router’s IP address configured as that host’s default gateway.

With these three elements configured on a host, a host can speak through the router to the Internet to any server using its IP address. But most the time, an Internet user is browsing websites and trying to send emails. In order for a host to speak to domains, it has to convert domain names into IP addresses first.

**Fourth**, a default DNS server. The fourth item that every host needs in order to achieve Internet connectivity is the IP address of a DNS server so that it can translate domain names to IP addresses, so that it can then communicate with other hosts using their domain names.

These four things must be configured on every host anytime it connects to a network.

Recall, a host is anything that sends or receives traffic on the Internet, which means a host could be your laptop or your printer or your mobile phone. In all cases every time any of these devices connects to a new network these devices must be configured with these four items.

But hold on! Every time you connect to a new Wi-Fi network at the local coffee shop or an airport or your school, you do not have to go into the settings of your phone and configure these things manually, yet you can still reach the Internet. How come?

Well, an important Internet protocol is working its magic behind the scenes, the **Dynamic Host Configuration Protocol (DHCP)**. DHCP allows a DHCP server to provide an IP address, a mask, a default gateway, and a DNS server for any client.

Every time you connect to a new network your host will send a DHCP discover message to discover the DHCP server and then the DHCP server will provide these four things in response back to the client. The client then has everything it needs in order to speak to the Internet. That is how every time you connect to a new Wi-Fi network, your phone or laptop automatically acquires the information it needs in order to speak to the internet.

### Network protocols ARP, FTP, SMTP, HTTP, SSL, TLS, and HTTPS

We’ve discussed the **Address Resolution Protocol or ARP** earlier in this chapter, especially in section 3 [Host to host communication in networking](https://itnetworkingskills.wordpress.com/2023/01/01/host-host-communication-networking/) and section 5 [How routers facilitate communication between networks](https://itnetworkingskills.wordpress.com/2023/01/09/how-routers-facilitate-communication/).

Recall, ARP is a L2 protocol used to map MAC addresses to IP addresses which allows two hosts to discover each other’s MAC address if all they know is their IP address. A client sends out an ARP request and a server, the receiving host, sends an ARP response.&#x20;

But what is the structure of an ARP request? Someone had to determine what constitutes an ARP request – what question to ask in an ARP request or what information to include in an ARP request or what to add as the destination MAC address in an ARP request. And what constitutes an ARP response? In short, what are the rules for writing ARP requests and ARP responses?

RFC 826 is what defines what makes an ARP conversation.

<figure><img src="https://itnetworkingskills.wordpress.com/wp-content/uploads/2024/05/35f13-network-protocols-arp-ftp-smtp-http-ssl-tls-https-dns-dhcp.webp" alt="Network-Protocols-ARP-FTP-SMTP-HTTP-SSL-TLS-HTTPS-DNS-DHCP" height="507" width="1479"><figcaption><p>RFC 826 sets the rules of an ARP conversation (source: Ed Harmoush, PracNet: Network Protocols)</p></figcaption></figure>

The RFC 826 are the engineering implementation rules for how to do ARP. Since these rules are published as an Internet standard, ARP can be implemented by many different vendors. Thus an HP server can speak to an Apple MacBook, and a Dell laptop can speak to a Samsung phone. The different vendors would simply follow the public open Internet standard for ARP.

**FTP (File Transfer Protocol)** is an application layer protocol. It allows a client and a server to send and receive files from each other. The FTP conversation is made up of messages that look like this:

<figure><img src="https://itnetworkingskills.wordpress.com/wp-content/uploads/2024/05/a96a7-network-protocols-ftp.webp" alt="Network-Protocols-FTP" height="480" width="1079"><figcaption><p>An RETR command stands for retrieve and ask (source: Ed Harmoush, PracNet: Network Protocols)</p></figcaption></figure>

The client would send the RETR command for a particular file and this would prompt the server to respond with that file.

The **SMTP (Simple Mail Transfer Protocol)** is the protocol that email servers will use to exchange emails. That conversation looks like this:

<figure><img src="https://itnetworkingskills.wordpress.com/wp-content/uploads/2024/05/cbc60-smtp-protocol.webp" alt="smtp-protocol" height="352" width="1186"><figcaption><p>The HELO command initiates the SMTP session conversation (source: Ed Harmoush, PracNet: Network Protocols)</p></figcaption></figure>

HELO is a SMTP command sent by a client to an SMTP server. The command tells the server that the client wishes to initiate an e-mail transaction and is followed by the client’s domain name.

The SMTP server will respond with a response code of 250, and now the client and the server can exchange emails with one another. HELO and 250 are simply some of the messages in the SMTP standard.&#x20;

**HTTP** (**Hyper Text Transfer Protocol**) is the protocol you’re using anytime you’re communicating with a web server.

Web servers host many web sites written in HTML, which stands for Hypertext Markup Language, and those HTML pages are exchanged using HTTP. When you browse to site.com your client, your web browser, sends a GET request to the web server and the web server will respond with a 200 OK message and then provide the website you are asking for. The clients are usually web browsers, but they can come in many forms, such as search engine robots.

<figure><img src="https://itnetworkingskills.wordpress.com/wp-content/uploads/2024/05/9640f-ssl-tls-protocols.webp" alt="SSL-TLS-protocols" height="257" width="1144"><figcaption><p>HTTP governs the structure and language of the requests and responses that take place between clients and servers (source: Ed Harmoush, PracNet: Network Protocols)</p></figcaption></figure>

**SSL (Secure Sockets Layer**) **and TLS (Transport Layer Security**) **protocols** allow a client and a server to build a secure tunnel between themselves and then they can do that HTTP conversation within that tunnel.

That process is known as **HTTPS (Hypertext Transfer Protocol Secure)**. That is in fact what HTTPS stands for: an HTTP conversation secured within an SSL or TLS tunnel. That’s what allows you to browse the web securely.

### The DNS protocol

Recall in section 1 we said a server is essentially a computer that knows how to respond to specific requests – meaning, each of the servers we discussed earlier (FTP, SMTP, and Web) are really just computers that have FTP software installed or SMTP software installed or HTTP or SSL software installed, which means these clients and servers all follow the same rules of [host to host communication](https://itnetworkingskills.wordpress.com/2023/01/01/host-host-communication-networking/) that we covered in section 3. And one of the key elements of that is for a host to speak to another host it must know the other host’s IP address.&#x20;

Client 9.1.1.11 in our previous illustration of the FTP conversation can speak to the FTP server because we have the IP address of the FTP Server. But how would our client speak to each of the other two servers (SMTP and Web)?

If asked for your favorite websites you would probably give the domain names of these websites. And if asked for your email address you would give something that looks like john@email.com. You would not give an IP address.&#x20;

The **DNS (Domain Name System)** is an application layer protocol that will use a DNS server to convert a domain name into an IP address. When you type a website into a browser it will first make a request to a DNS server asking for the IP address of the website you just typed into the browser. Then the DNS server will provide an IP address and this will allow your host to make a request to the actual web server IP address. Even though you never provided the website IP address your computer was able to figure it out automatically by using the DNS protocol.

DNS is also what makes email possible. If asked for your email address, you would probably give something that looked like john@email.com and not the actual IP address of your email server. DNS would resolve email.com into your actual mail service IP address and now your client can actually send mail to the mail server.

### Key takeaways

* DHCP and DNS play crucial roles in facilitating Internet communication
  * DHCP allows a DHCP server to provide an IP address, a mask, a default gateway, and a DNS server for any client
  * DNS resolves domain names to IP addresses
* A protocol is a set of rules and messages that form an Internet standard
* Network protocols are Internet protocols that operate at specific layers of the TCP/IP and OSI models
  * ARP, FTP, SMTP, HTTP, SSL, TLS, HTTPS, DHCP, DNS

### References

[Common Protocols. (2023, January 10). Wikibooks, The Free Textbook Project. Retrieved 15:39, January 15, 2023 from https://en.wikibooks.org/wiki/Network\_Plus\_Certification/Technologies/Common\_Protocols](https://en.wikibooks.org/wiki/Network_Plus_Certification/Technologies/Common_Protocols)

[Internet Protocol. (2022, December 29). Wikipedia, The Free Encyclopedia. Retrieved 15:47, January 15, 2023, from https://en.wikipedia.org/wiki/Internet\_Protocol](https://en.wikipedia.org/wiki/Internet_Protocol)

[Network Protocols – ARP, FTP, SMTP, HTTP, SSL, TLS, HTTPS, DNS, DHCP – Networking Fundamentals – L6 (PracNet)](https://www.youtube.com/watch?v=E5bSumTAHZE\&ab_channel=PracticalNetworking)

Odom, W. (2020). CCNA 200-301 Official Cert Guide, Volume 1. Cisco Press.

Odom, W. (2020). CCNA 200-301 Official Cert Guide, Volume 2. Cisco Press.
