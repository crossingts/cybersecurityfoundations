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

* Point 1

***

### Connected and local routes

* Point 1

***

### How to configure static routes on Cisco routers

* Point 1

***

### Comparing TCP to UDP

* Point 1

***

### How to configure standard ACLs on Cisco routers

* Point 1

***

### The role of DNS within the network

* Point 1

***

### Configuring and verifying DHCP client and relay

* Identify the key IP parameters displayed by ipconfig /all and the primary reasons for using this essential command.
* During the DORA process, which message is a broadcast from the client indicating its acceptance of the offered IP address?
* What Cisco IOS command is essential to configure an interface to forward incoming DHCP broadcasts to a specific DHCP server on another network?

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
