# Chapter 4 review questions

### Network devices and their functions

* What is the fundamental difference between the function of a switch and the function of a router?
  * Answer: A switch facilitates communication within a single network. A router facilitates communication between different networks.
* Explain the primary limitation of using a hub in a network.
  * Answer: Hubs do not scale well because they create a single collision domain, duplicating and flooding all traffic out every port. This leads to collisions and wasted bandwidth as every device receives everyone else's data.
* What are the two main categories of firewalls covered in the section, and how do they differ in their physical form and placement?
  * Answer: The two categories are network firewalls (hardware devices that filter traffic between networks) and host-based firewalls (software applications installed on a host machine to filter its incoming and outgoing traffic).
* A host needs to communicate with another host on a different network. What is the role of its "gateway" in this process?
  * Answer: The gateway is the host's way out of its local network. It is the IP address of its closest router, which will receive the packet and route it towards the destination network.
* What is the key functional difference between a bridge and a hub, and why are bridges considered an improvement?
  * Answer: A hub blindly floods all traffic to all ports, while a bridge learns which MAC addresses are on each of its two sides and can filter traffic, only forwarding frames if the destination is on the other segment. This reduces unnecessary broadcasts and improves network performance.

***

### The Open Systems Interconnection (OSI) model

* Briefly describe the primary function of the Physical Layer (Layer 1) in the OSI model.
  * Answer: The primary function of the Physical Layer is transporting bits between hosts. It defines the physical characteristics of the medium (like cables and radio waves) and converts digital bits into electrical, light, or radio signals for transmission.
* Briefly describe the primary function of the Data Link Layer (Layer 2) in the OSI model.
  * Answer: The primary function of the Data Link Layer is hop-to-hop delivery. It uses MAC addresses to move data from one Network Interface Card (NIC) to the next immediate device on the same network segment, such as from a computer to a switch or from a switch to a router.
* Briefly describe the primary function of the Network Layer (Layer 3) in the OSI model.
  * Answer: The primary function of the Network Layer is end-to-end delivery. It uses IP addresses for logical addressing and routing to get data from a source host to a destination host across different networks.
* List three key protocols that operate at the Application Layer (Layer 7) and state their purpose.
  * Answer: DNS: Translates human-readable domain names (e.g., example.com) into machine-readable IP addresses. HTTP: Defines how web browsers and web servers communicate and transfer web pages. DHCP: Automatically assigns IP addresses and other network configuration parameters to devices on a network.
* Identify three addressing schemes used at Layers 2, 3, and 4 of the OSI model and state the purpose of each.
  * Answer:&#x20;
    * Layer 2 (Data Link): MAC Address - Used for hop-to-hop delivery to physically identify the next immediate device on the local network segment.
    * Layer 3 (Network): IP Address - Used for end-to-end delivery to logically identify the source and destination hosts across an entire network path.
    * Layer 4 (Transport): Port Number - Used for service-to-service delivery to ensure data is delivered to the correct application or service on the destination host.

***

### Host to host communication in networking

* Briefly explain the difference in the ARP process when a host communicates with another host on its local network versus one on a foreign network.
  * Answer: For a host on the local network, the host sends an ARP request to resolve the destination host's IP address to the destination host's MAC address. For a host on a foreign network, the host sends an ARP request to resolve the default gateway's IP address to the default gateway's MAC address.
* What are the three key pieces of information a host must be configured with to communicate on an IP network?
  * Answer: 1) An IP address, 2) A subnet mask, and 3) A default gateway.
* After a packet arrives at its final destination host, what happens to the Layer 2 and Layer 3 headers?
  * Answer: The destination host discards the Layer 2 header (as its job for NIC-to-NIC delivery is done) and then retires the Layer 3 header (as its job for end-to-end delivery is done), leaving only the data for the application to process.
* Once a host has resolved the MAC address of its default gateway via ARP, how does this benefit future communications?
  * Answer: The MAC-to-IP mapping is stored in the host's ARP cache. This resolved MAC address can be reused for any subsequent packet destined for any foreign network, as the first hop for all such traffic is the same router. The host does not need to ARP for the gateway again until the cache entry expires.
* Where does a host store the IP-to-MAC address mappings it learns from ARP responses?
  * Answer: The host stores them in its ARP cache (also called an ARP table).

***

### Network protocols and their functions

* What is the fundamental purpose of a network protocol?
  * Answer: A network protocol is a set of rules that dictates how network devices should format, transmit, and receive data, enabling them to communicate effectively across networks regardless of their underlying infrastructure.
* List the four parameters a host must have configured to achieve full Internet connectivity.
  * Answer: An IP address, a subnet mask, a default gateway (router) IP address, and the IP address of a DNS server.
* Explain the role of the DHCP protocol in the context of a user connecting to a new Wi-Fi network.
  * Answer: When a user connects to a new Wi-Fi network, their device (the DHCP client) automatically sends a DHCP discover message. A DHCP server on that network responds by providing the four necessary parameters (IP address, subnet mask, default gateway, DNS server), automatically configuring the host for Internet access without any manual input from the user.
* Differentiate between the functions of DNS and ARP.
  * Answer: DNS is an application-layer protocol that resolves a _domain name_ (e.g., `example.com`) to an _IP address_. ARP is a link-layer protocol that resolves a known _IP address_ on the local network to a _MAC address_.
* What is the relationship between HTTP, SSL/TLS, and HTTPS?
  * Answer: HTTP is the protocol for transferring web content. SSL and TLS are cryptographic protocols that create a secure, encrypted tunnel between a client and server. HTTPS is not a separate protocol but is the term for conducting an HTTP communication within that secure SSL/TLS tunnel.

***

### Typing www.google.com into a web browser

* What are the three fundamental tables used for data flow in a network, and what does each one map?
  * Answer:
    * MAC Address Table: Maps a switch port to a MAC address.
    * ARP Table: Maps an IP address to a MAC address.
    * Routing Table: Maps an IP network to a next-hop IP address.
* Why must a host send its packet to its default gateway when communicating with a device on a foreign network?
  * Answer: The host determines the destination IP is on a different network using its own IP and subnet mask. The host itself cannot deliver packets outside its local network, so it must forward the packet to the router (its default gateway), which is designed to route traffic between networks.
* Describe the two main phases that occur when you type a URL into a web browser, according to the text.
  * Answer: 1) DNS Resolution: The browser makes a request to a DNS server to resolve the domain name (e.g., `www.google.com`) into its corresponding IP address. 2) HTTP Request: The browser uses the returned IP address to send an HTTP request (e.g., a GET request) directly to the web server at that address.
* What is the purpose of a broadcast MAC address (all F's), and what action does a switch take when it receives a frame with this destination address?
  * Answer: The broadcast MAC address (FF:FF:FF:FF:FF:FF) is used to send a frame to every device on the local network segment. When a switch receives a frame with this destination address, it performs flooding—it sends the frame out all of its ports except the one it was received on.
* Once a packet arrives at the final router (e.g., R3 for host C), what two things must the router check to deliver the packet to the final destination host on its directly connected network?
  * Answer: 1) Its routing table to confirm the destination IP address is on a directly connected network. 2) Its ARP table to find the MAC address associated with the destination host's IP address so it can build a new Layer 2 header for the final hop.

***

### Cisco IOS CLI and basic device security

* What is the primary functional difference between User EXEC mode and Privileged EXEC mode?
  * Answer: User EXEC mode is for basic, read-only monitoring commands. Privileged EXEC mode provides full administrative access to all viewing, debugging, and device control commands (e.g., reload, copy).
* What is the single, most important CLI shortcut for getting help and how is it used?
  * Answer: The question mark `?`. It is used for context-sensitive help. Typing it at a prompt lists all available commands. Typing it after a partial command shows possible completions and arguments.
* Which command should always be used over `enable password` to secure access to privileged EXEC mode and why?
  * Answer: The `enable secret` command. It should always be used because it encrypts the password using a strong, irreversible MD5 hash, whereas the `enable password` stores it in plain text, which is a security risk.
* A colleague can see a password in plain text when they use the `show running-config` command. What single global configuration command can you use to prevent this for all such passwords?
  * Answer: `service password-encryption`
* What is the specific purpose of the `show startup-config` command?
  * Answer: To display the configuration file (`startup-config`) that is stored in NVRAM. This is the configuration that the device will load and use when it boots up or is reloaded.

***

### Connected and local routes

* What is the fundamental purpose of a router's routing table, and how does a router use it when it receives a packet?
  * Answer: The routing table is a router's map of known networks. Its purpose is to store the best paths to those networks. When a router receives a packet, it examines the packet's destination IP address and looks for a matching route in its routing table to determine where to send the packet next (the "next-hop") or if it should accept the packet itself.
* After successfully configuring the command `ip address 10.0.5.1 255.255.255.128` on an interface and issuing `no shutdown`, which two specific routes will appear in the `show ip route` output? List them with their correct prefix lengths.
  * Answer: A Connected route to `10.0.5.0/25` (since 255.255.255.128 is a /25 mask). A Local route to `10.0.5.1/32`.
* A new network technician sees a Local route (L) to 192.168.55.1/32 and a Connected route (C) to 192.168.55.0/24 in the routing table. They ask, "Why do I need the Local route if the Connected route already includes that IP address?" How would you explain the critical functional difference between these two routes to them?
  * Answer: I would explain that the Connected route (`192.168.55.0/24`) is an instruction for forwarding traffic to other hosts on that network (e.g., `192.168.55.100`). The Local route (`192.168.55.1/32`) is an instruction for the router to accept and process traffic destined to its own interface IP.&#x20;
* A router's routing table contains the following two routes:\
  \* `C 172.16.0.0/16 is directly connected, GigabitEthernet0/1`\
  \* `L 172.16.5.1/32 is directly connected, GigabitEthernet0/1`\
  For a packet destined to `172.16.5.1`, which route will the router use and why?
  * Answer: The router will use the `L 172.16.5.1/32` route. Why: Because of the longest prefix match rule. Both routes match the destination, but the /32 mask (255.255.255.255) is longer (more specific) than the /16 mask (255.255.0.0). The router always chooses the most specific match.
* What is the single, most important rule a Cisco router uses to choose between multiple routes that all match a packet's destination IP address? What is the specific term for this rule?
  * Answer: The most important rule is to select the matching route with the longest subnet mask (highest prefix value, e.g., /32 is longer than /24). The specific term for this rule is Longest Prefix Match.

***

### How to configure static routes on Cisco routers

* What is the fundamental difference between how a connected route and a static route are added to a router's routing table?
  * Answer: A connected route is added automatically when a router interface is configured with an IP address and enabled. A static route must be manually configured by an administrator using the `ip route` command.
* A Linux host's Ethernet interface (`eth0`) needs a static IP address of `10.0.1.5/24` and a default gateway of `10.0.1.1`. What lines would you add to the `/etc/network/interfaces` file to achieve this?
  * Answer: `iface eth0 inet static address 10.0.1.5 netmask 255.255.255.0 gateway 10.0.1.1`
* What does the code "S\*" indicate in a Cisco router's `show ip route` output?
  * Answer: The "S" indicates a static route. The asterisk "\*" indicates that this static route is a candidate default route (a gateway of last resort).
* What is the key functional difference between a host's default gateway and a router's default route?
  * Answer: A default gateway is an IP address configured on an end host (like a PC), telling it where to send traffic for any network not on its local subnet. A default route is configured on a router itself (0.0.0.0/0), telling it where to forward packets that do not match any other, more specific route in its routing table.
* What is a significant operational drawback of configuring a static route using only an exit interface (e.g., `ip route 192.168.1.0 255.255.255.0 GigabitEthernet0/1`) instead of a next-hop IP address?
  * Answer: The router will treat the destination network as if it is directly connected to that interface. This can cause problems because the router may rely on Proxy ARP for every destination in that network, which is inefficient and can fail if Proxy ARP is disabled on the neighboring router. It is generally considered less reliable and specific than using a next-hop IP address.

***

### Comparing TCP to UDP

* During the TCP connection termination process, explain why a four-way handshake is used instead of a three-way handshake.
  * Answer: Because a TCP connection is full-duplex, meaning data can flow independently in each direction. Each side must independently signal that it has finished sending data (FIN) and acknowledge the other side's FIN signal. This independent termination for each direction requires four segments.
* A host receives three TCP segments with sequence numbers 1500, 500, and 1000. Based on TCP's design, how does the host handle these segments to ensure correct data order?
  * Answer: The host uses the sequence numbers to identify the correct order of the data. It will hold the segments with sequence numbers 500 and 1000 in a buffer until the segment with sequence number 1500 arrives and is acknowledged. It then reassembles them in the order 500, 1000, 1500 before passing the data to the application.
* What is the fundamental purpose of an ephemeral port number, and from which IANA-defined range is it selected?
  * Answer: Its purpose is to uniquely identify a specific communication session on the source host. The source host randomly selects an ephemeral port number from the IANA range 49152 to 65535 to use for the duration of that session.
* Describe a specific scenario where an application would be better suited to use UDP instead of TCP, and explain the reason for this choice.
  * Answer: Scenario: A live voice-over-IP (VoIP) phone call. Reason: Speed and low latency are more critical than 100% reliability. Dropping a few audio packets is preferable to the delay caused by TCP's retransmission, acknowledgments, and congestion control, which would result in choppy, delayed audio.
* A packet capture shows a segment with a destination port of 443. Based on the IANA port ranges, what type of port is this, and what application-layer protocol is it almost certainly associated with?
  * Answer: Port 443 is a well-known port (0-1023 range). It is associated with the HTTPS protocol, used for secure web browsing.

***

### How to configure standard ACLs on Cisco routers

* What is the key characteristic that differentiates a standard ACL from an extended ACL in terms of what it can filter?
  * Answer: A standard ACL filters traffic based only on the source IP address. An extended ACL can filter based on source and destination IP address, as well as source and destination port numbers and protocol.
* A colleague has configured an ACL but it is not working. You check the configuration and see the ACL has been created but is not applied to any interface. What is the single, necessary step they have missed?
  * Answer: They must apply the ACL to a router interface in either the inbound or outbound direction using the `ip access-group` command (e.g., `ip access-group 1 out`).
* Write the global configuration command to create an ACE in ACL number 15 that permits traffic from the single host with IP address 192.168.55.1. Use the most efficient method.
  * Answer: `R1(config)# access-list 15 permit host 192.168.55.1`\
    (Alternatively, `R1(config)# access-list 15 permit 192.168.55.1` is also acceptable as the router interprets a lone IP address as a host address).
* Explain why the order of ACEs (Access Control Entries) within an ACL is critically important.
  * Answer: ACLs are processed from the top down. The router takes the action (permit/deny) for the first matching entry and stops processing further entries. A more general statement placed above a more specific one will cause the specific one to be ignored.
* You need to create a standard ACL to prevent the entire 172.16.0.0/16 network from passing through a router, but allow all other traffic. Besides the 'deny' statement for that network, what other explicit statement must you add to the ACL and why?
  * Answer: You must add an explicit `permit any` statement. If you do not, the implicit deny at the end of the ACL will block all traffic that isn't from 172.16.0.0/16, which is the opposite of the intended goal. The explicit `permit any` overrides the implicit deny for all other traffic.

***

### The role of DNS within the network

* What is the primary function of the Domain Name System (DNS), and why is it essential for human users?
  * Answer: The primary function of DNS is to translate human-readable domain names (e.g., www.google.com) into machine-readable IP addresses (e.g., 172.217.0.142).&#x20;
* A Windows user can successfully ping `8.8.8.8` but cannot ping `google.com`. What is the most likely cause, and which command would you use on the Windows PC to investigate the configured resolver?
  * Answer: The most likely cause is a DNS resolution failure. The user's device cannot translate `google.com` into an IP address. To investigate, you would use the `ipconfig /all` command on the Windows PC to verify which DNS server it is configured to use.
* What are the two primary purposes of the `ip host` and `ip name-server` commands when configuring a Cisco router to act as a DNS server for local clients?
  * Answer: The `ip host` command is used to build a local host table on the router by statically mapping hostnames to IP addresses (e.g., `ip host PC1 192.168.0.101`). The `ip name-server` command configures an external DNS server (e.g., `8.8.8.8`) that the router will query if a client requests a name not found in its local host table.
* In a Wireshark capture of a DNS query for `youtube.com`, you see one query for an "A" record and another for a "AAAA" record. What is the difference between these two record types?
  * Answer: An "A" record maps a domain name to an IPv4 address. A "AAAA" (quad-A) record maps a domain name to an IPv6 address. The two queries are made to get both the IPv4 and IPv6 addresses for the same domain name.
* What is the key functional difference between a router acting as a DNS client versus a DNS server? What is the main command to enable each role?
  * Answer: DNS Client: The router sends DNS queries to an external server to resolve names for its own use (e.g., when using the `ping` command). The main command is `ip name-server <address>`. DNS Server: The router answers DNS queries from other devices on the network. The main command to enable this is `ip dns server`.

***

### Configuring and verifying DHCP client and relay

* What is the primary purpose of the DHCP protocol on a network, and what are two key benefits it provides?
  * Answer: The primary purpose of DHCP is to automatically assign IP addresses and other network configuration parameters (like subnet mask, default gateway, and DNS servers) to client devices. Two key benefits are reducing administrative overhead by eliminating manual configuration and minimizing human error.
* List the four steps of the DORA process and briefly state the purpose of each.
  * Answer: Discover: The client broadcasts a message to find available DHCP servers. Offer: A DHCP server unicasts or broadcasts a message offering an IP address lease to the client. Request: The client broadcasts a message formally requesting the offered IP address and informing other servers of its choice. Acknowledgement (Ack): The chosen server sends a final confirmation, allowing the client to use the IP address.
* Identify the key IP parameters displayed by ipconfig /all and the primary reasons for using this essential command.
  * Answer: Key parameters include IPv4 Address, Subnet Mask, Default Gateway, DHCP Server, and DNS Servers. The primary reasons for using ipconfig /all are to verify network configuration and to diagnose connectivity issues (e.g., missing IP address or gateway).
* Which Cisco IOS command is used to configure a router's interface to obtain its IP address from a DHCP server? Provide the exact command syntax.
  * Answer: The command is `ip address dhcp`. It is entered in interface configuration mode for the specific interface (e.g., `R1(config-if)# ip address dhcp`).
* A network administrator needs to see all active IP address leases assigned by the router's DHCP server. What is the exact command to display this information?
  * Answer: The command is `show ip dhcp binding`. This command displays the IP address, MAC address, lease expiration, and type of binding for each client.

***

### Static NAT configuration

* Describe the need for private IPv4 addressing.
  * Answer: The need for private IPv4 addressing arose from the imminent exhaustion of public IPv4 addresses. It allows organizations to use non-unique, reusable addresses (defined in RFC 1918) for their internal networks, while requiring only a limited number of public IPs for external communication via NAT. This conserves the global IPv4 address space and extends its usability.
* List the three RFC 1918 private IP address ranges and their corresponding CIDR notations.
  * Answer:
    * 10.0.0.0/8 (10.0.0.0 to 10.255.255.255)
    * 172.16.0.0/12 (172.16.0.0 to 172.31.255.255)
    * 192.168.0.0/16 (192.168.0.0 to 192.168.255.255)
* What is the primary functional difference between Static NAT and PAT (Overload) regarding IP address usage?
  * Answer: Static NAT creates a one-to-one, permanent mapping between a single private IP and a single public IP. PAT (Overload) allows many private IP addresses to share a single public IP address by using unique source port numbers to distinguish between connections.
* What are two main reasons for implementing NAT?
  * Answer: 1) IP Address Conservation: To solve IPv4 exhaustion by allowing many devices to share few public IPs. 2) Enhanced Security: To hide the internal network topology and provide a basic firewall by dropping unsolicited inbound traffic.
* Provide the complete sequence of Cisco IOS commands to configure a basic static NAT mapping for a server. Assume the server's private IP is 192.168.1.10 and its public IP is 203.0.113.10. The inside interface is GigabitEthernet0/1 and the outside interface is GigabitEthernet0/0.
  * Answer:

```
Router(config)# interface GigabitEthernet0/1
Router(config-if)# ip nat inside
Router(config-if)# interface GigabitEthernet0/0
Router(config-if)# ip nat outside
Router(config-if)# exit
Router(config)# ip nat inside source static 192.168.1.10 203.0.113.10
```

***

### OSI model layers and security threats

* Identify two common network attack types associated with each OSI layer.
* Briefly describe how each identified attack type can compromise a network.
* Identify two key mitigation methods for each identified attack type.
* Sort the identified network attack types by their potential level of risk (consider attack likelihood and potential impact).
