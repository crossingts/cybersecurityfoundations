---
description: >-
  This section introduces various types of NAT, and explains the role of NAT in
  networks and how to configure and verify static source NAT on Cisco routers
---

# Static NAT configuration

## Learning objectives

* Understand the need for private IPv4 addressing
* Understand the role of NAT in networks
* Understand the difference between static NAT and dynamic NAT
* Understand how static source NAT works
* Configuring and verifying inside source NAT using static NAT

This section focuses on static NAT configuration on Cisco IOS devices. NAT (Network Address Translation) is an important networking topic. NAT is used to translate the source and/or destination IP address of a packet to a different IP address. There are different types of NAT, such as static NAT, dynamic NAT, and Port Address Translation (PAT). Static NAT maps a private IP address to a fixed public IP address. Dynamic NAT assigns a public IP address from a pool of available addresses to a private IP address on demand. PAT uses a single public IP address and different port numbers to distinguish between multiple private IP addresses. This section covers on the following four topic areas: 1) the need for private IPv4 addressing, 2) NAT purpose in networks, 3) how NAT works, and 4) configuring and verifying inside source NAT using static NAT.

## Topics covered in this section

* **Private IPv4 addresses (RFC 1918)**
* **NAT (Network Address Translation) introduction**
* **Static NAT configuration – introduction**
* **Static NAT configuration**
* **Cisco NAT terminology**
* **clear ip nat translation**
* **show ip nat statistics**
* **Command review**
* **Key learnings**
* **Practice quiz questions**

### Private IPv4 addresses (RFC 1918)

IPv4 does not provide enough addresses for all devices that need an IP address in the world. The long-term solution to this problem is to switch to IPv6. But changing networks all over the world from IPv4 to IPv6 is a tremendous undertaking. There are three main short-term solutions which have extended the lifespan of IPv4:

1\) [CIDR (Classless Inter-Domain Routing)](https://itnetworkingskills.wordpress.com/2023/03/12/classless-ipv4-addressing-subnetting/). CIDR allows us to forget about the rigid IPv4 addressing convention and freely use any prefix length with any address.

2\) Private IPv4 addresses – these are IP addresses you can freely use in your internal networks. These IP addresses do not have to be globally unique.

3\) NAT (network address translation). NAT translates private IP addresses to the public IP for outbound traffic and back to the corresponding private IP for inbound traffic. Static NAT offers dedicated public IP assignment for specific devices. [Dynamic PAT (Port Address Translation)](https://itnetworkingskills.wordpress.com/2023/04/13/dynamic-pat-configuration/) allows multiple devices on a private network to share a single public IP address.

Private IPs were originally meant for security because they are not routable over the Internet, but they also proved valuable in saving public IP address space. Without private IP addressing we would not have any more public IP addresses to assign to new devices.

RFC 1918 specifies the following IPv4 address ranges as private:

10.0.0.0/8 (10.0.0.0 to 10.255.255.255) → Class A

172.16.0.0/12 (172.16.0.0 to 172.31.255.255) → Class B

192.168.0.0/16 (192.168.0.0 to 192.168.255.255) → Class C

You will notice, RFC 1918 has moved past the classic IP addressing convention, where Class A range is /8, Class B range is /16, and Class C range is /24.

You can freely use these private IPv4 addresses in your network. If you are watching a YouTube video from a PC in your home, very likely you are using a private IP address. For example, our home PC here has the IP address 192.168.0.167, and its default gateway, our router, is 192.168.0.1. &#x20;

<figure><img src="https://itnetworkingskills.wordpress.com/wp-content/uploads/2024/05/895d5-rfc-1918-private-ipv4-addresses-1.webp?w=1201" alt="RFC-1918-private-ipv4-addresses" height="243" width="1201"><figcaption><p>Image courtesy of Jeremy’s IT Lab (Free CCNA | NAT (Part 1) | Day 44)</p></figcaption></figure>

A different PC might have the exact same IP address as this PC, or it might be in the same subnet, 192.168.0.0/24.&#x20;

Private IP addresses are not routable on the public Internet, so they cannot be used to directly connect to websites or other devices on the Internet. Your ISP will drop traffic to or from private IP addresses. NAT allows you to use private IP addresses on your network to access the Internet by translating private IP addresses to public IP addresses when traffic leaves your network.

Let’s demonstrate. On the left is our demo PC, 192.168.0.167, connected to our router, 192.168.0.1. Somewhere across the Internet there is another PC connected to a router, and they have the same IP addresses. &#x20;

<figure><img src="https://itnetworkingskills.wordpress.com/wp-content/uploads/2024/05/8d8aa-static-nat-demo-network-2.webp?w=1201" alt="static-nat-demo-network" height="152" width="1201"><figcaption><p>Image courtesy of Jeremy’s IT Lab (Free CCNA | NAT (Part 1) | Day 44)</p></figcaption></figure>

There are two problems here. The first problem is that there are duplicate addresses. If there is a packet traveling over the Internet with the destination address 192.168.0.167, which PC will it go to? The second problem is that private IP addresses cannot even be used over the Internet, so the PCs can’t access the Internet. &#x20;

NAT solves both of these problems.&#x20;

Private IP addresses do not have to be unique, but public IP addresses must be unique. When our PC needs to reach destinations over the Internet, NAT will allow it to borrow the unique public IP address of our router or to use another public IP address configured for NAT. In [dynamic PAT (port address translation)](https://itnetworkingskills.wordpress.com/2023/04/13/dynamic-pat-configuration/), a variation of NAT, the PC and all other home devices can use the same public IP address to access the Internet, all at the same time. For example, our PC can borrow our router’s public IP address and communicate over the Internet using 203.0.113.1, and the other PC can communicate over the Internet using 203.0.113.5.

### NAT (Network Address Translation) introduction

NAT is used to modify the source and/or destination IP addresses of packets. Source NAT translates the source IP address of a packet. Destination NAT translates the destination IP address of a packet. NAT allows hosts with private IP addresses to communicate with other hosts over the Internet. Further, dynamic NAT (i.e., PAT) allows multiple internal hosts to share a single public IP address.&#x20;

#### Three Major Reasons to Use NAT/PAT

1. **IP Address Conservation (Solving IPv4 Exhaustion)**
   * A single public IPv4 address (or a small pool) can be shared by hundreds or thousands of internal hosts using PAT (NAT Overload).
   * This is the fundamental reason the Internet continued to grow after the available IPv4 addresses were depleted.
   * It allows organizations to use the free, reusable RFC 1918 private address space internally without needing a unique public IP for every device.
2. **Enhanced Security (Basic Firewalling and Obfuscation)**
   * **Hides Internal Network Topology:** NAT acts as a natural firewall for inbound connections. Because the internal IP addresses are private and translated, an external attacker cannot directly see the structure or specific hosts on the internal network.
   * **Breaks Unsolicited Connections:** Since dynamic NAT/PAT mappings are created by outbound traffic, unsolicited incoming connections from the Internet are dropped by the router as there is no translation entry in the NAT table for them. This provides a basic level of security by default.
3. **Network Flexibility and Simplified Management**
   * **Decouples Internal and External Addressing:** You can change your internal network scheme (e.g., re-subnetting, changing ISP) without affecting the outside world. Only the NAT translations on the border router need to be updated.
   * **Easier ISP Migration:** If you change your Internet Service Provider, you are assigned a new block of public IP addresses. With NAT, you only need to reconfigure the outside global pool on your router, rather than re-addressing every single device on your internal network.

There are several types of NAT. For the CCNA you have to understand **source NAT** and how to configure it on Cisco routers. Source NAT is used to allow hosts with private IP addresses to access a public network.

Let’s see an illustration of how **source NAT** works. &#x20;

PC1’s IP address is 192.168.0.167. PC1 wants to communicate with the server at 8.8.8.8. &#x20;

<figure><img src="https://itnetworkingskills.wordpress.com/wp-content/uploads/2024/05/4a5b4-source-nat-demo-3.webp?w=1201" alt="source-nat-demo" height="362" width="1201"><figcaption><p>Image courtesy of Jeremy’s IT Lab (Free CCNA | NAT (Part 1) | Day 44)</p></figcaption></figure>

PC1 creates a packet with source IP 192.168.0.167 and destination 8.8.8.8. PC1 sends the packet to its default gateway, R1. This is where NAT happens. R1 translates the source IP address of the packet from 192.168.0.167 to 203.0.113.1, the IP address of its external interface. R1 then sends the packet out to the Internet and it arrives at its destination, 8.8.8.8.&#x20;

Now the server will send a reply. The source is 8.8.8.8, and the destination is 203.0.113.1. The server sends the packet to R1, which then reverses the translation. 203.0.113.1 is translated back to 192.168.0.167. Although in this case the destination IP is being changed, this is not a destination NAT process. R1 is just reverting the previously translated address back to PC1’s actual IP address. Finally the server’s response reaches PC1. Destination NAT is beyond the scope of the CCNA exam.

In this case R1 translated PC1’s IP to the IP address of its own external interface, 203.0.113.1. In this type of source NAT, the router’s interface IP address is used to route packets. This type of NAT is a specific type of Dynamic NAT with Overload (PAT). But this is not the only option.&#x20;

Source NAT translates the source IP address of a packet. It could be inside source NAT or outside source NAT. Inside source NAT is what we usually configure. It translates the source IP address of a packet as it travels from the inside network to the outside network. Outside Source NAT translates the source IP of a packet coming from the outside network into your inside network).

#### Types of Inside Source NAT&#x20;

For the CCNA, you need to know three core methods for configuring **inside source NAT**. They are defined by what you use as the "translation target":

1. **Static NAT**
   * **Command:** `ip nat inside source static <local-ip> <global-ip>`
   * **Mapping:** Permanent, one-to-one.
   * **Use Case:** Making an internal server (e.g., a web server) accessible from the Internet.
2. **Dynamic NAT (with a Pool)**
   *   **Command:**

       ios

       ```
       ip nat pool MY-POOL <start-ip> <end-ip> netmask <subnet-mask>
       ip nat inside source list <acl> pool MY-POOL
       ```
   * **Mapping:** Dynamic, one-to-one, from a defined pool of public IPs. **Does not use overloading** by default.
   * **Use Case:** (Less common) Providing a group of hosts with their own public IPs without needing permanent static mappings.
3. **Dynamic NAT with Overload (PAT)**
   * This is the most common type and has **two sub-types** based on the translation target:
     * **a) Using a Pool of IPs for PAT:**\
       `ip nat inside source list <acl> pool MY-POOL overload`
     * **b) Using a Router Interface IP for PAT (This is your question):**\
       `ip nat inside source list <acl> interface <interface> overload`

#### Summary Table: Types of Inside Source NAT

| Type                | Command                                                 | Key Characteristic                               |
| ------------------- | ------------------------------------------------------- | ------------------------------------------------ |
| **Static NAT**      | `ip nat inside source static 192.168.1.10 203.0.113.10` | Fixed, 1-to-1 mapping.                           |
| **Dynamic NAT**     | `ip nat inside source list 1 pool MY-POOL`              | Dynamic, 1-to-1, no port translation.            |
| **PAT (Overload)**  | `ip nat inside source list 1 pool MY-POOL overload`     | Many-to-Many/Few, uses ports.                    |
| **PAT (Interface)** | `ip nat inside source list 1 interface Gi0/1 overload`  | Many-to-**One**, uses the router's interface IP. |

Up next, we will cover a specific kind of NAT called **static source NAT,** a type of source NAT which involves manually configuring one-to-one mappings of private IP addresses to global IP addresses. &#x20;

### Static NAT configuration – introduction

Static source NAT uses an **inside global** IP address. The inside global IP address is a public IP address that is statically assigned to a specific device on the internal network. When the device sends a packet to the Internet, the router will translate the device’s private IP address to the inside global IP address as the source IP address of the packet.

Static NAT involves statically configuring one-to-one mappings of IP addresses. You can NAT any address to any other address, but to keep things simple let’s think of it as mapping one private IP to one public IP.&#x20;

For example, an **inside local** IP address is mapped to an inside global IP address. &#x20;

“Inside” refers to the router’s internal network, as opposed to “outside” networks such as the Internet.&#x20;

<figure><img src="https://itnetworkingskills.wordpress.com/wp-content/uploads/2024/05/29c9f-inside-local-nat-demo-4.webp?w=1201" alt="source-nat-demo" height="183" width="1201"><figcaption><p>Image courtesy of Jeremy’s IT Lab (Free CCNA | NAT (Part 1) | Day 44)</p></figcaption></figure>

An **inside local** address is the IP address of the inside host, from the perspective of the local network. It is the IP address actually configured on the inside host, which is usually a private IP address.&#x20;

That inside local address is translated to an **inside global** address, which is the IP address of the inside host from the perspective of outside hosts, hosts outside of the local network. It is the IP address of the inside host after NAT, and is usually a public IP address.&#x20;

Let’s demonstrate.&#x20;

<figure><img src="https://itnetworkingskills.wordpress.com/wp-content/uploads/2024/05/459ab-inside-global-nat-5.webp?w=1201" alt="inside-global-nat" height="516" width="1201"><figcaption><p>Image courtesy of Jeremy’s IT Lab (Free CCNA | NAT (Part 1) | Day 44)</p></figcaption></figure>

PC1 wants to communicate with the server at 8.8.8.8. PC1 constructs a packet with destination IP address 8.8.8.8 and source IP address 192.168.0.167. This is the inside local address, the IP address actually configured on PC1, and it is a private IP address.&#x20;

PC1 sends the packet to its default gateway R1, which performs source NAT to change the source IP address to 100.0.0.1.&#x20;

100.0.0.1 is a public IP address reserved just for PC1 (we are not using R1’s interface IP). 100.0.0.1 is the inside global IP of PC1. 100.0.0.1 is PC1’s IP address after NAT is performed.

R1 then sends the packet over the Internet to 8.8.8.8, which then sends the reply. Note that from the server’s perspective it’s communicating with IP address 100.0.0.1, even though PC1’s actual IP address is 192.168.0.167. That’s why we say the inside global address is the IP address of the inside host, PC1 in this example, from the perspective of outside hosts, the server in this example. R1 reverses the translation back to PC1’s inside local address, and sends it to PC1.

We defined static NAT as being one-to-one mapping of IP addresses. On R1 we mapped PC1’s private IP address 192.168.0.167 to the public IP address 100.0.0.1. That’s a one-to-one mapping. If PC2 also wants to reach 8.8.8.8, PC2 will need its own IP address. The router would not allow us to map both PC1’s and PC2’s actual/inside local IP addresses to 100.0.0.1 using static NAT. &#x20;

<figure><img src="https://itnetworkingskills.wordpress.com/wp-content/uploads/2024/05/52fa6-static-source-nat-example-6.webp?w=1201" alt="static-source-nat-example" height="297" width="1201"><figcaption><p>Image courtesy of Jeremy’s IT Lab (Free CCNA | NAT (Part 1) | Day 44)</p></figcaption></figure>

So we configured R1 to translate PC2’s IP address, 192.168.0.168, to 100.0.0.2. The server sends the reply to 100.0.0.2, and R1 translates it back to 192.168.0.168 and sends the reply back to PC2.&#x20;

192.168.0.168 is the inside local address, the actual IP address configured on PC2. And 100.0.0.2 is the inside global address, PC2’s IP address after NAT. &#x20;

Note that this one-to-one mapping of IP addresses does not only allow the internal host to access external resources, it also allows external hosts to access the internal host via the inside global address. So without PC1 initiating communication with the server, the server could send a packet to destination IP 100.0.0.1, and because of that one-to-one IP address mapping R1 would translate it to 192.168.0.167 and forward it to PC1, and then PC1 would reply. So, it works two-ways, not just from inside to outside, but also  from outside to inside.&#x20;

Static NAT allows devices with private IP addresses to communicate over the Internet. However, because it requires a one-to-one IP address mapping, it does not really help preserve IP addresses. If each internal device needs its own public IP address anyway, we might as well just configure a public IP address on the device itself.&#x20;

### Static NAT configuration

First, define the inside interface or interfaces by using the IP NAT INSIDE command from interface configuration mode. In the sample network below, R1’s inside interface is G0/1, connected to the internal network.&#x20;

<figure><img src="https://itnetworkingskills.wordpress.com/wp-content/uploads/2024/05/d9775-static-nat-configuration-7.webp?w=1201" alt="Static-NAT-configuration" height="600" width="1201"><figcaption><p>Image courtesy of Jeremy’s IT Lab (Free CCNA | NAT (Part 1) | Day 44)</p></figcaption></figure>

Then we used the IP NAT OUTSIDE command on G0/0 to define it as the outside interface. R1 will perform NAT on traffic traveling from the inside interface, G0/1, to the outside interface, G0/0. &#x20;

Then we configured the one-to-one IP address mappings using the command IP NAT INSIDE SOURCE STATIC, followed by the inside local IP address and then the inside global IP address. We mapped 192.168.0.167 to 100.0.0.1, and 192.168.0.168 to 100.0.0.2. So PC1’s IP address will be translated to 100.0.0.1, and PC2’s will be translated to 100.0.0.2.&#x20;

Finally we used the command SHOW IP NAT TRANSLATIONS. When static NAT is used you will see the entries permanently displayed in the translations table. You can see entries for traffic sent from PC1 and PC2 to 8.8.8.8. &#x20;

Let’s look at each column, from left to right. On the left is the Pro, protocol column, indicating that UDP was used. Next is the inside global address column. Notice, next to each IP address there is a colon followed by a number, the port number. In the context of static NAT, port numbers are not important. Next is the inside local address column. Notice that R1 does not translate the port numbers when using static NAT. The last two columns introduce two new terms, **outside local** and **outside global**. Let’s discuss.

### Cisco NAT terminology

Look at the following diagram. The **outside local** address is the IP address of the outside host from the perspective of the local network. For example, from PC1’s perspective, the server’s IP address 8.8.8.8 is an outside local IP address. The **outside global** address is the IP address of the outside host from the perspective of the outside network, the outside hosts. In this case, the server’s actual IP address is 8.8.8.8. So both the outside local address and the outside global address are the same. Unless destination NAT is used, these two addresses will always be the same.  &#x20;

<figure><img src="https://itnetworkingskills.wordpress.com/wp-content/uploads/2024/05/86907-cisco-nat-terminology-8.webp?w=1201" alt="Cisco-NAT-terminology" height="604" width="1201"><figcaption><p>Image courtesy of Jeremy’s IT Lab (Free CCNA | NAT (Part 1) | Day 44)</p></figcaption></figure>

Notice that the port number is also indicated for these services. In this case, PC1 and PC2 used DNS to access the server, as indicated by the port number. DNS uses UDP port 53, and sometimes TCP port 53.&#x20;

The four terms – inside local, inside global, outside local, and outside global – can be a little confusing.&#x20;

“Inside” and “outside” indicate the location of the host, on the inside network or the outside network. PC1 and PC2 are inside, and the server at 8.8.8.8 is outside.&#x20;

“Local” and “global” indicate the perspective. Local means from the perspective of the local, inside network. Global means from the perspective of the global, outside network. For example, 192.168.0.167 is PC1’s IP address from the perspective of the local network, and 100.0.0.1 is PC1’s IP address from the perspective of the global network. &#x20;

### clear ip nat translation

Each time the static NAT entries are used, dynamic entries are added to the NAT translation table for those translations, as you can see in the following CLI output, as an example. These dynamic entries will eventually time out and be removed from the NAT translation table after PC1 and PC2 stop communicating with 8.8.8.8.

You can clear all of the dynamic translations in the NAT translation table with CLEAR IP NAT TRANSLATION, and then an asterisk. &#x20;

<figure><img src="https://itnetworkingskills.wordpress.com/wp-content/uploads/2024/05/3c51c-clear-ip-nat-translation-9.webp?w=1201" alt="CLEAR-IP-NAT-TRANSLATION" height="316" width="1201"><figcaption><p>Image courtesy of Jeremy’s IT Lab (Free CCNA | NAT (Part 1) | Day 44)</p></figcaption></figure>

After using that command the two dynamic entries disappeared, but the static entries remained. These static NAT entries will not time out and cannot be deleted.&#x20;

### show ip nat statistics

The **show ip nat statistics** command displays the statistics for NAT on a router. This command is a useful tool for troubleshooting NAT problems and for monitoring the performance of NAT. The output of this command includes information such as the number of active translations, the number of expired translations, the number of translations using a pool, the number of translations using a static mapping, the interfaces that are marked as inside and outside, and the access lists that are used for NAT.

Let’s walk through the first few lines of a CLI output.&#x20;

<figure><img src="https://itnetworkingskills.wordpress.com/wp-content/uploads/2024/05/bd10f-show-ip-nat-statistics-10.webp?w=1201" alt="show-ip-nat-statistics" height="373" width="1201"><figcaption><p>Image courtesy of Jeremy’s IT Lab (Free CCNA | NAT (Part 1) | Day 44)</p></figcaption></figure>

Total active translations: 2, and both of them are static. There are 0 dynamic entries, since we just cleared the dynamic entries. Extended entries are touched on in [NAT Part 2](https://itnetworkingskills.wordpress.com/2023/04/13/dynamic-pat-configuration/). Peak translations is 4, that’s the highest number of translations that has been in R1’s NAT table. Note, the outside interface is g0/0, and the inside interface is g0/1.

### Command review

\>Define the inside and outside interfaces:

First, define the inside interface or interfaces connected to the internal network.

R(config)#**interface** _interface_

R(config-if)#**ip nat inside**

Second, define the outside interface or interfaces connected to the external network.

R(config)#**interface** _interface_

R(config-if)#**ip nat outside**

R will perform NAT on traffic traveling from the inside interface to the outside interface.

\>Configure the one-to-one IP address mappings:

R(config)#**ip nat inside source static** _inside-local-ip inside-global-ip_

**Example:**

R1(config)#ip nat inside source static 192.168.0.167 100.0.0.1

This command maps 192.168.0.167 (PC1) to 100.0.0.1. R1 (PC1’s default gateway) performs source NAT to change the source IP address to 100.0.0.1.

\>Show translations table:

R#**show ip nat translations**

When static NAT is used you will see the entries permanently displayed in the translations table. You can see entries for traffic sent from hosts inside the network to servers outside the network.

The translations table displays information about used protocols (e.g., UDP), inside global addresses and inside local addresses (and associated port numbers), and outside local addresses and outside global addresses (and associated port numbers, e.g., 53 to indicate DNS services).

\>clear ip nat translation:

R#**clear ip nat translation \***\
→to clear all the dynamic translations in the NAT translation table (the asterisk is part of the command)

\>show ip nat statistics:

R#**show ip nat statistics**\
→to display information about the number of active translations, the number of expired translations, and the outside and inside interfaces within the NAT configuration

[Free CCNA | Static NAT | Day 44 Lab – Notes](https://docs.google.com/document/d/e/2PACX-1vTpZTH2_RAy_A0nOJrEUbMJZdTHkcD2vVrPZk-SzJRccqGmdt7YB14gKBPjnSLyBKYYVkZgstJ3Ap-D/pub)

### Key takeaways

* Private IPv4 addresses (RFC 1918)
  * Defined by RFC 1918 to conserve public IPv4 address space.
  * Not routable on the public Internet.
  * Three main ranges:
    * Class A: `10.0.0.0` to `10.255.255.255` (10.0.0.0/8)
    * Class B: `172.16.0.0` to `172.31.255.255` (172.16.0.0/12)
    * Class C: `192.168.0.0` to `192.168.255.255` (192.168.0.0/16)
  * NAT is required for hosts using these addresses to communicate with the Internet.
* **Three Major Reasons to Use NAT/PAT**
  * **IP Address Conservation:** PAT (Overload) allows thousands of internal hosts to share a single public IP address, directly combating IPv4 exhaustion.
  * **Enhanced Security:** Hides internal network topology and acts as a basic firewall by dropping unsolicited inbound connections that lack a NAT table entry.
  * **Network Flexibility:** Allows an organization to change its internal addressing scheme without impacting its public presence, making ISP migrations easier.
* **Types of Inside Source NAT**
  * **Static NAT:** A permanent, one-to-one mapping between an inside local and inside global address. Used for servers that need to be accessible from the Internet.
  * **Dynamic NAT:** A temporary, one-to-one mapping from a pool of public addresses. Does not use port translation. Less common.
  * **PAT (NAT Overload):** A many-to-one (or many-to-few) mapping that uses port numbers to distinguish between connections. This is the most common type.
    * Can be configured to use a **pool of public IPs**.
    * Or, more commonly, to use a **router's interface IP** (e.g., `interface GigabitEthernet0/1 overload`).
* **How Source NAT Works**
  * The process is triggered when an **inside host initiates** traffic to an outside network.
  * The router checks the packet against its NAT rules.
  * It translates the **source IP address** (and for PAT, the source port) in the packet header.
  * It creates an entry in its **NAT translation table** to remember the mapping.
  * Return traffic is matched against this table and translated back to the original inside IP/port before being forwarded into the local network.
* **Cisco NAT Terminology**
  * **Inside Local:** The real, private IP address of the host as seen on the inside network (e.g., `192.168.1.10`).
  * **Inside Global:** The public IP address representing the inside host as seen on the outside network (e.g., `203.0.113.5`).
  * **Outside Global:** The real, public IP address of the external destination host.
  * **Outside Local:** Rarely used; the IP address of the outside host as seen from the inside network (usually the same as the Outside Global).

**Using the `ip nat inside source static` Command**

* Command: `ip nat inside source static <inside-local-ip> <inside-global-ip>`
* This command creates a permanent, bidirectional entry in the NAT table.
* Must be paired with configuring `ip nat inside` and `ip nat outside` on the appropriate interfaces.

**`show ip nat translations`**

* The primary command for **verifying** NAT operation.
* Displays the current content of the router's NAT table.
* For static NAT, entries are always present.
* For dynamic NAT/PAT, entries appear only when active connections exist and will timeout.

**`show ip nat statistics`**

* Provides a **summary and counters** for NAT operations.
* Shows:
  * The total number of active translations.
  * NAT configuration parameters (e.g., ACLs, pools, interfaces).
  * Counters for hits and misses, indicating how many translations have occurred.
* Essential for **troubleshooting** (e.g., confirming if a pool is exhausted).

### References

[Free CCNA | NAT (Part 1) | Day 44 | CCNA 200-301 Complete Course](https://www.youtube.com/watch?v=2TZCfTgopeg\&list=PLxbwE86jKRgMpuZuLBivzlM8s2Dk5lXBQ\&index=85)

[Free CCNA | Static NAT | Day 44 Lab | CCNA 200-301 Complete Course](https://www.youtube.com/watch?v=vir6n_NVZFw\&list=PLxbwE86jKRgMpuZuLBivzlM8s2Dk5lXBQ\&index=86)

[NAT – Practical Networking — CCNA Topics](https://www.practicalnetworking.net/index/ccna/)

Odom, W. (2020). CCNA 200-301 Official Cert Guide, Volume 2. Cisco Press.
