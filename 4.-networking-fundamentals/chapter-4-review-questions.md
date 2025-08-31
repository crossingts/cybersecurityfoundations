---
hidden: true
---

# Chapter 4 review questions

### Network devices and their functions

* Point 1

***

### The Open Systems Interconnection (OSI) model

* Point 1

***

### Host to host communication in networking

* Point 1

***

### Network protocols and their functions

* Point 1

***

### Typing www.google.com into a web browser

* Point 1

***

### Cisco IOS CLI and basic device security

* Quiz questions

**Quiz question 1**

Which command provides the most secure method for setting a password to access privileged EXEC mode?

a) `login password`

b) `enable password`

**c) `enable secret`**

d) `secret password`

**Quiz question 2**

You have just configured a console password and an enable secret on a new router. After reloading the router, the console password is required, but the enable secret is not. What is the most likely cause?

a) The `enable secret` command was entered in User EXEC mode

**b) The configuration was not saved to startup-config before reloading**

c) The `service password-encryption` command was not used

d) The terminal emulator software is incompatible

**Quiz question 3**

Which CLI mode is indicated by the `Router(config)#` prompt and is required to make changes that affect the entire device?

a) User EXEC Mode

b) Privileged EXEC Mode

c) Interface Configuration Mode

**d) Global Configuration Mode**

***

### Connected and local routes

* Quiz questions

**Quiz question 1**&#x20;

The IP address configured on a router interface will appear in the routing table as what kind of route?&#x20;

a) Static

b) Connected

**c) Local**

d) Dynamic

**Quiz question 2**

After configuring the IP address 192.168.1.1/24 on a router's GigabitEthernet0/1 interface, which two routes are automatically added to the routing table?

a) A static route and a default route

**b) A connected route to 192.168.1.0/24 and a local route to 192.168.1.1/32**

c) A local route to 192.168.1.0/24 and a connected route to 192.168.1.1/32

d) Two equal-cost static routes

**Quiz question 3**

In a Cisco routing table, what code letter signifies a Local route?

a) C

b) S

**c) L**

d) D

**Quiz question 4**

When a router receives a packet destined for the IP address 10.0.0.1, and its routing table contains both a route to 10.0.0.0/24 and 10.0.0.1/32, which route will it select?

a) The 10.0.0.0/24 route because it represents a larger network

**b) The 10.0.0.1/32 route because it is a longer, more specific prefix match**

c) The router will load-balance traffic across both routes

d) The router will drop the packet due to a routing conflict

***

### How to configure static routes on Cisco routers

* Quiz questions

**Quiz question 1**

Which of the following commands configures a default route on a Cisco router?

**a) R1(config)#ip route 0.0.0.0 0.0.0.0 10.1.1.255**

b) R1(config)#ip route 0.0.0.0/0 10.1.1.255

c) R1(config)#ip route 0.0.0.0 255.255.255.255 10.1.1.255

d) R1(config)#ip route 0.0.0.0/32 10.1.1.255

**Quiz question 2**

What is the primary purpose of configuring a static route on a router?

a) To automatically learn all possible network paths

**b) To manually define a path to a remote network that is not directly connected**

c) To assign an IP address to a router's physical interface

d) To encrypt traffic between two remote hosts

**Quiz question 3**

Which command is the correct syntax for configuring a default static route on a Cisco router?

**a) `ip route 0.0.0.0 0.0.0.0 192.168.1.1`**

b) `ip default-route 192.168.1.1`

c) `ip route 192.168.1.0 255.255.255.0 GigabitEthernet0/1`

d) `default-information originate`

**Quiz question 4**

For a host on a network to communicate with a host on a different network, it must be configured with which of the following?

a) A Dynamic Host Configuration Protocol (DHCP) server address

b) A DNS server address

**c) A default gateway address**

d) A subnet mask for the remote network

***

### Comparing TCP to UDP

* Quiz questions

**Quiz question 1**&#x20;

Which characteristic best describes why TCP is considered a stateful protocol?

a) It uses a checksum to detect errors in the data

**b) It tracks the state of the communication session through handshakes and sequence numbers**

c) It can operate over both IPv4 and IPv6 networks

d) It uses port numbers to direct data to the correct application

**Quiz question 2**

A cybersecurity analyst notices network traffic using destination port 53. Which protocol and service are most likely being used?

a) TCP and HTTPS

**b) UDP and DNS**

c) TCP and SSH

d) UDP and SMTP

**Quiz question 3**

What is the primary advantage UDP has over TCP?

a) Stronger error correction and data recovery features

b) Guaranteed, in-order delivery of all data packets

**c) Lower latency and reduced protocol overhead**

d) Built-in encryption for securing data in transit

***

### How to configure standard ACLs on Cisco routers

* Quiz questions

**Quiz question 1**&#x20;

<figure><img src="https://itnetworkingskills.wordpress.com/wp-content/uploads/2024/05/2f1ca-acls-practice-quiz-questions-22.webp?w=1201" alt="acls-Practice-quiz-questions" height="608" width="1201"><figcaption><p>Image courtesy of Jeremy’s IT Lab (Free CCNA | Standard ACLs | Day 34)</p></figcaption></figure>

The answer is ACL 1. Entry 10 permits PC1 and entry 20 permits PC4. The implicit deny will deny all other traffic. ACL 1 fulfills the requirements. The other ACLs do not.

**Quiz question 2**

What is the final implicit statement at the end of every standard ACL?

a) permit any

**b) deny any**

c) log all

d) permit host

**Quiz question 3**

Standard ACLs are best applied close to the destination because they filter based on:

a) Destination IP address and port number

**b) Source IP address only**

c) Protocol type

d) Destination IP address only

**Quiz question 4**

Which of the following is an advantage of using a named ACL over a numbered ACL?

a) Named ACLs can filter on a wider range of criteria

b) Named ACLs have a higher performance efficiency

**c) Named ACLs allow for easier editing and more descriptive entries**

d) Named ACLs are applied differently to router interfaces

***

### The role of DNS within the network

* Quiz questions

**Quiz question 1**&#x20;

Which of the following Windows command prompt commands will display the PC’s DNS server? Select two.

a) ipconfig

**b) ipconfig /all**

c) ipcofig /displaydns

**d) nslookup**

The correct answers are b and d. a, IPCONFIG, displays the PC’s IP address, subnet mask, and default gateway, but not details like the DNS server. c, IPCONFIG /DISPLAYDNS, shows the PC’s DNS cache, but not the DNS server address.

**Quiz question 2**

A user can successfully ping a web server's IP address but cannot load its website by typing the URL into a browser. Which of the following is the most likely cause of this problem?

a) The default gateway is misconfigured

**b) The DNS service is unavailable**

c) The network cable is unplugged&#x20;

d) The web server is down

Correct Answer: b) The DNS service is unavailable. Explanation: The fact that the IP address ping works proves that the network path is functional (ruling out a, c, and d). The browser uses the domain name (URL), which must be translated into an IP address by DNS. If DNS is unavailable, this translation fails, and the browser cannot connect.

**Quiz question 3**

Which command on a Windows PC would you use to determine which DNS server the computer is configured to use?

a) `ping`

b) `nslookup`

**c) `ipconfig /all`**

d) `tracert`

Correct Answer: c) `ipconfig /all.` Explanation: The `ipconfig /all` command displays the complete IP configuration for all network adapters, including the IP addresses of the configured DNS servers. While `nslookup` _uses_ the DNS server, it doesn't explicitly show you which one is configured in the adapter's settings.

***

### Configuring and verifying DHCP client and relay

* Identify the key IP parameters displayed by ipconfig /all and the primary reasons for using this essential command.
* Quiz questions

**Quiz question 1**

During the DORA process, which message is a broadcast from the client indicating its acceptance of the offered IP address?

Answer: DHCP Request message. The Request message is broadcast by the client to formally accept the offer from the server and to inform all other potential servers that it has chosen an address.

**Quiz question 2**

What Cisco IOS command is essential to configure an interface to forward incoming DHCP broadcasts to a specific DHCP server on another network?

Answer: ip helper-address. This interface configuration command tells the router to forward certain broadcast packets, including DHCP Discover messages, to the specified IP address of the DHCP server.

***

### Static NAT configuration

* Describe the need for private IPv4 addressing.
* Quiz questions

**Quiz question 1**&#x20;

**Scenario:** You are configuring a network where an internal web server with the IP address `192.168.50.100` must be accessible from the internet. The router's public IP address on its outside interface is `203.0.113.50`. You have been assigned the public IP `203.0.113.100` to statically map to the web server.

**Task:** Write the necessary Cisco IOS commands to configure static NAT for this server. Assume the inside interface is `GigabitEthernet0/1` and the outside interface is `GigabitEthernet0/0`. You do not need to configure the interface IP addresses, only the NAT-specific commands.

**Answer:**

ios

```
interface GigabitEthernet0/1
 ip nat inside
!
interface GigabitEthernet0/0
 ip nat outside
!
ip nat inside source static 192.168.50.100 203.0.113.100
```

**Explanation for Grading:**

* Correctly identifies and sets the `ip nat inside` command on the appropriate interface.
* Correctly identifies and sets the `ip nat outside` command on the appropriate interface.
* Uses the correct `ip nat inside source static` command with the proper order of arguments: `local-inside-ip` first, then `global-outside-ip`.

**Quiz question 2**&#x20;

**Scenario:** After configuring static NAT for a server, you run the `show ip nat translations` command on your router and get the following output:

text

```
Pro Inside global      Inside local       Outside local      Outside global
--- 203.0.113.100     192.168.50.100     ---                ---
```

**Questions:**\
A. What is the purpose of the Inside Global IP address `203.0.113.100`?\
B. If a user on the internet wants to connect to the internal server, which IP address will they use?\
C. The output shows no entries under "Outside local" and "Outside global". Why is that?

**Answer:**\
A. The Inside Global IP (`203.0.113.100`) is the public IP address that represents the internal server to the outside network (internet).\
B. The user on the internet must use the Inside Global IP address: `203.0.113.100`.\
C. The "Outside" fields are empty because there are currently no active translations or connections involving outside hosts. The static NAT entry is pre-programmed and always in the table, but it only shows outside addresses when a connection is actively using the translation.

**Grading:**

* **(A)** Answer correctly identifies the Inside Global IP as the public representation of the internal host.
* **(B)** Answer correctly identifies that external users target the global (public) IP.
* **(C)** Answer demonstrates understanding that the static entry is always present, but the "outside" fields are populated by the state of active connections.

***

### OSI model layers and security threats

* Identify two common network attack types associated with each OSI layer.
* Briefly describe how each identified attack type can compromise a network.
* Identify two key mitigation methods for each identified attack type.
* Sort the identified network attack types by their potential level of risk (consider attack likelihood and potential impact).
