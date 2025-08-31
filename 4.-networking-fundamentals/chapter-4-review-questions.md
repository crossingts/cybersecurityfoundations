---
hidden: true
---

# Chapter 4 review questions

### Network devices and their functions

* Point 1

***

### The Open Systems Interconnection (OSI) model

* Map networking protocols to their OSI model layers.

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

* Point 1

***

### Connected and local routes

* Quiz questions

**Quiz question 1**&#x20;

The IP address configured on a router interface will appear in the routing table as what kind of route?&#x20;

a) Static

b) Connected

**c) Local**

d) Dynamic

***

### How to configure static routes on Cisco routers

* Quiz questions

**Quiz question 1**&#x20;

Which of the following commands configures a default route on a Cisco router?

**a) R1(config)#ip route 0.0.0.0 0.0.0.0 10.1.1.255**

b) R1(config)#ip route 0.0.0.0/0 10.1.1.255

c) R1(config)#ip route 0.0.0.0 255.255.255.255 10.1.1.255

d) R1(config)#ip route 0.0.0.0/32 10.1.1.255

***

### Comparing TCP to UDP

* Point 1

***

### How to configure standard ACLs on Cisco routers

* Quiz questions

**Quiz question 1**&#x20;

<figure><img src="https://itnetworkingskills.wordpress.com/wp-content/uploads/2024/05/2f1ca-acls-practice-quiz-questions-22.webp?w=1201" alt="acls-Practice-quiz-questions" height="608" width="1201"><figcaption><p>Image courtesy of Jeremy’s IT Lab (Free CCNA | Standard ACLs | Day 34)</p></figcaption></figure>

The answer is ACL 1. Entry 10 permits PC1 and entry 20 permits PC4. The implicit deny will deny all other traffic. ACL 1 fulfills the requirements. The other ACLs do not.

**Quiz question 2**

What is the final implicit statement at the end of every standard ACL?\
a) permit any\
**b) deny any**\
c) log all\
d) permit host

**Quiz question 3**

Standard ACLs are best applied close to the destination because they filter based on:\
a) Destination IP address and port number\
**b) Source IP address only**\
c) Protocol type\
d) Destination IP address only

**Quiz question 4**

Which of the following is an advantage of using a named ACL over a numbered ACL?\
a) Named ACLs can filter on a wider range of criteria\
b) Named ACLs have a higher performance efficiency\
**c) Named ACLs allow for easier editing and more descriptive entries**\
d) Named ACLs are applied differently to router interfaces

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
