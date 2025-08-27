# The role of DNS within the network

The [DNS (Domain Name System) protocol ](https://study-ccna.com/domain-name-system-dns/)makes it easy for humans to use the Internet by translating domain names into IP addresses. This means that we can type in a human-readable address like [http://www.google.com](http://www.google.com/) instead of a complex IP address like 172.217.0.142. DNS is mentioned in the CCNA exam topics list in Section 4, IP Services, subsection 4.3, which states that you must be able to “[Explain the role of DHCP and DNS within the network](https://study-ccna.com/dhcp-dns/)”. This lesson explains the [role of DNS within the network](https://its.umich.edu/enterprise/wifi-networks/dns-dhcp) and how to configure DNS in Cisco IOS.&#x20;

* **The role of DNS within the network**
* **ip config /all (Windows)**
* **nslookup (Windows)**
* **The ping**
* **Wireshark capture (nslookup)**
* **DNS cache**
* **Host file**
* **DNS in Cisco IOS**
* **Configuring a router as a DNS server**
* **DNS demo 1**
* **DNS demo 2**
* **Configuring a router as a DNS client**
* **Command review**
* **Key learnings**
* **Practice quiz questions**

### [The role of DNS within the network](https://www.fortinet.com/resources/cyberglossary/what-is-dns)

DNS is used to resolve (i.e., convert) human-readable names such as google.com to IP addresses. When you type youtube.com into a web browser, your device will ask a DNS server for the IP address of youtube.com.

The DNS server or servers your device uses can be manually configured or automatically learned via [DHCP (dynamic host configuration protocol)](https://itnetworkingskills.wordpress.com/2023/04/11/configure-verify-dhcp-client-relay/).

We will use this network to demonstrate how DNS works.

<figure><img src="https://itnetworkingskills.wordpress.com/wp-content/uploads/2024/05/09e39-dns-network-1.webp?w=1201" alt="dns-network" height="300" width="1201"><figcaption><p>Image courtesy of Jeremy’s IT Lab (Free CCNA | DNS | Day 38)</p></figcaption></figure>

Three PCs are connected to R1 via SW1. R1 is connected to the Internet, and somewhere across the Internet is Google’s DNS server with the IP address 8.8.8.8.&#x20;

Let’s go on to PC1, a Windows PC, and check out some IP parameters in the OS.

### ip config /all (Windows)

Here’s the CLI of PC1, the Windows command prompt. The command IPCONFIG /ALL was used to display various information for PC1.&#x20;

Remember this command. Topic 1.10 of the CCNA exam blueprint says you must be able to “Verify IP parameters for Client OS (Windows, Mac OS, Linux)”.

<figure><img src="https://itnetworkingskills.wordpress.com/wp-content/uploads/2024/05/8f922-dns-ipconfig-all-2.webp?w=1201" alt="dns-ipconfig-all" height="450" width="1201"><figcaption><p>Image courtesy of Jeremy’s IT Lab (Free CCNA | DNS | Day 38)</p></figcaption></figure>

Normally, end hosts can automatically determine which DNS server to use through the DHCP protocol. However, the DNS server can be manually configured. In our demo here, PC1 was manually configured to use Google’s DNS server 8.8.8.8.

### nslookup (Windows)

Let’s see how DNS works.

We used the command NSLOOKUP youtube.com. NSLOOKUP stands for Name Server Lookup. This command tells the device to ask its DNS server for the IP address of the specified name.

As we saw, PC1 is using Google’s DNS server at 8.8.8.8. Here’s the answer from Google’s DNS server. Youtube.com’s IPv4 address is 172.217.25.110, and its IPv6 address is displayed also.

<figure><img src="https://itnetworkingskills.wordpress.com/wp-content/uploads/2024/05/c84fc-nslookup-dns-3.webp?w=1201" alt="nslookup-dns" height="541" width="1201"><figcaption><p>Image courtesy of Jeremy’s IT Lab (Free CCNA | DNS | Day 38)</p></figcaption></figure>

PC1 pinged youtube.com by specifying the name. The OS automatically converted the domain name to an IP address. We do not need to use the NSLOOKUP command before sending the ping.&#x20;

Let’s look back at our example network and visualize how the NSLOOKUP command works. Again, the NSLOOKUP command tells the device to ask its DNS server for the IP address of the specified name.

<figure><img src="https://itnetworkingskills.wordpress.com/wp-content/uploads/2024/05/09e39-dns-network-1.webp?w=1201" alt="dns-network" height="300" width="1201"><figcaption><p>Image courtesy of Jeremy’s IT Lab (Free CCNA | DNS | Day 38)</p></figcaption></figure>

PC1 sends a DNS query message to its configured DNS server 8.8.8.8 asking for the IP address of youtube.com. And the DNS server replies, telling PC1 that the IP address is 172.217.25.110. In this case, R1 is not acting as a DNS server or client. It is just forwarding packets. So no DNS configuration is required on R1.&#x20;

It is often not necessary to do any DNS configuration on routers. However, a Cisco router can act as a DNS server and client at the same time, as we will see shortly.&#x20;

### The ping

When one host pings another, a series of steps occur behind the scenes, establishing a basic connection and measuring its responsiveness. Here’s a breakdown:

Steps:

* Initiation: The sending host creates an Internet Control Message Protocol (ICMP) Echo Request packet, containing its own IP address.
* Transmission: The packet is sent to the target host’s IP address through the network route determined by routing protocols.
* Receiving: If the target host is reachable and operational, it receives the Echo Request packet, extracts the sender’s IP address, and creates an ICMP Echo Reply packet containing its own IP address.
* Response: The Echo Reply packet travels back through the network to the sending host.
* Analysis: The sending host receives the Echo Reply packet, analyzes the time it took for the entire round trip (from sending the Echo Request to receiving the Echo Reply), and calculates the round-trip time (RTT).

Pinging serves several purposes:

* Reachability check: It’s a simple way to verify if the target host is online and accessible. If you get a reply, the host is reachable. No reply indicates unreachable, but could also be due to network issues.
* Latency measurement: The RTT provides an estimate of the time it takes data to travel between two hosts, giving an idea of network speed and potential delays.
* Basic troubleshooting: Pinging can help pinpoint where communication issues might lie. If pings to a gateway router fail but pings to an external host succeed, the problem is likely within your local network.

Ping is often used alongside other network diagnostic tools like traceroute for more in-depth troubleshooting. Different ping tools offer advanced options like sending multiple packets, varying packet size, and specifying timeout values.

### Wireshark capture (nslookup)

Here is a Wireshark capture of the traffic from the **nslookup** youtube.com command. There are four messages. Here’s the first message, from source 192.168.0.101, PC1, to destination 8.8.8.8, Google’s DNS server.

<figure><img src="https://itnetworkingskills.wordpress.com/wp-content/uploads/2024/05/a6d84-wireshark-capture-nslookup-5.webp?w=1201" alt="Wireshark-capture-nslookup" height="593" width="1201"><figcaption><p>Image courtesy of Jeremy’s IT Lab (Free CCNA | DNS | Day 38)</p></figcaption></figure>

Under “Info” it says standard query, so this is a standard DNS query message, a request to the server. A DNS standard query is a request for information sent from a DNS client to a DNS server. Notice the part that says “A youtube.com’”. Notice the letter “A” before youtube.com. We will clarify this in a minute.

The next message (second row) is from Google’s DNS server 8.8.8.8 to PC1, 192.168.0.101. Under Info it says standard query response. This is a response to PC1’s query. Notice the part that says “A youtube.com A 172.217.25.110”. Note, 172.217.25.110 is youtube.com’s IPv4 address.&#x20;

The third message (third row) is again a standard query from 192.168.0.101 to 8.8.8.8. This time at the end of the Info field it says “AAAA youtube.com”. AAAA is called quadruple A.

The fourth message (fourth row) is a standard query response. Notice this time at the end of the Info field it displays, AAAA youtube.com AAAA, followed by an IPv6 address, youtube.com’s IPv6 address.

What is meant by A and quadruple A? DNS ‘A’ records are used to map names to IPv4 addresses. DNS ‘AAAA’ records are used to map names to IPv6 addresses.

In the first query message, PC1 asked the DNS server for the A record of youtube.com, so the DNS server responded with an IPv4 address. In the second query message, PC1 asked the DNS server for the quadruple A record of youtube.com, so the server responded with an IPv6 address.&#x20;

Now let’s briefly look inside the first query.

<figure><img src="https://itnetworkingskills.wordpress.com/wp-content/uploads/2024/05/c9abf-wireshark-capture-nslookup-6.webp?w=1201" alt="Wireshark-capture-nslookup" height="586" width="1201"><figcaption><p>Image courtesy of Jeremy’s IT Lab (Free CCNA | DNS | Day 38)</p></figcaption></figure>

Note the L4 field. The DNS query is using UDP. DNS uses TCP and UDP. Standard DNS queries and responses typically use UDP. TCP is used for DNS messages larger than 512 bytes. In either case, UDP or TCP, the port number is 53.&#x20;

Finally, in the smaller box in the following diagram is the UDP query itself, asking for the A record of youtube.com.

<figure><img src="https://itnetworkingskills.wordpress.com/wp-content/uploads/2024/05/aeaa0-wireshark-capture-nslookup-7.webp?w=1201" alt="Wireshark-capture-nslookup" height="598" width="1201"><figcaption><p>Image courtesy of Jeremy’s IT Lab (Free CCNA | DNS | Day 38)</p></figcaption></figure>

### DNS cache

Devices store DNS server responses in a local DNS cache to avoid having to query the server every time they want to access a particular destination. This saves network traffic.

To view the DNS cache on a Windows PC use the command IPCONFIG /DISPLAYDNS.

Here’s the record for youtube.com. Notice the record type.

<figure><img src="https://itnetworkingskills.wordpress.com/wp-content/uploads/2024/05/981c1-dns-cache-displaydns-8.webp?w=982" alt="DNS-cache-displaydns" height="675" width="982"><figcaption><p>Image courtesy of Jeremy’s IT Lab (Free CCNA | DNS | Day 38)</p></figcaption></figure>

We discussed A and quadruple A. A CNAME (pronounced “C name”) record, or Canonical Name record, is a type of DNS record that maps a domain name to another domain name.&#x20;

Notice, the A record for the domain name youtube-ui.l.google.com matches the A record for the domain name youtube.com (the IPv4 address is 172.217.25.110).

<figure><img src="https://itnetworkingskills.wordpress.com/wp-content/uploads/2024/05/baadf-dns-cache-displaydns-9.webp?w=978" alt="DNS-cache-displaydns" height="675" width="978"><figcaption><p>Image courtesy of Jeremy’s IT Lab (Free CCNA | DNS | Day 38)</p></figcaption></figure>

You can clear the DNS cache with the command IPCONFIG /FLUSHDNS.&#x20;

<figure><img src="https://itnetworkingskills.wordpress.com/wp-content/uploads/2024/05/d54f3-ipconfig-flushdns-10.webp?w=1201" alt="ipconfig-flushdns" height="406" width="1201"><figcaption><p>Image courtesy of Jeremy’s IT Lab (Free CCNA | DNS | Day 38)</p></figcaption></figure>

It says the DNS resolver cache successfully was flushed. Now when we use IPCONFIG /DISPLAYDNS, nothing is displayed. Now if we try to access youtube.com again PC1 will have to send another DNS query to the DNS server to learn the IP address again.

### Host file

In addition to a DNS cache, most devices have a “hosts” file which is a list of hosts and IP addresses.&#x20;

In Windows PCs it is called hosts and it is in the C:\Windows\System32\drivers\etc folder.

<figure><img src="https://itnetworkingskills.wordpress.com/wp-content/uploads/2024/05/65fb5-host-file-11.webp?w=1201" alt="Host-file" height="453" width="1201"><figcaption><p>Image courtesy of Jeremy’s IT Lab (Free CCNA | DNS | Day 38)</p></figcaption></figure>

In Windows the hosts file looks like this:

<figure><img src="https://itnetworkingskills.wordpress.com/wp-content/uploads/2024/05/abace-windows-host-file-12.webp" alt="windows-Host file" height="677" width="951"><figcaption><p>Image courtesy of Jeremy’s IT Lab (Free CCNA | DNS | Day 38)</p></figcaption></figure>

By default there are no hosts listed. However, we added an entry on PC1 for R1 by typing the IP address, a space, and then the host name, R1.&#x20;

We then returned to the command prompt and entered PING R1, and PC1 was able to ping R1 because it had an entry in its hosts file.&#x20;

<figure><img src="https://itnetworkingskills.wordpress.com/wp-content/uploads/2024/05/f577a-host-file-ping-13.webp?w=1144" alt="Host-file-ping" height="507" width="1144"><figcaption><p>Image courtesy of Jeremy’s IT Lab (Free CCNA | DNS | Day 38)</p></figcaption></figure>

Hosts files are an alternative to DNS. Before DNS was invented, host files like this were used. In modern times a hosts file might be used in a small network to list some hosts on the local network if necessary.

### DNS in Cisco IOS

Now let’s look at how to configure DNS in Cisco IOS, using R1 as an example.

<figure><img src="https://itnetworkingskills.wordpress.com/wp-content/uploads/2024/05/09e39-dns-network-1.webp?w=1201" alt="dns-network" height="300" width="1201"><figcaption><p>Image courtesy of Jeremy’s IT Lab (Free CCNA | DNS | Day 38)</p></figcaption></figure>

Routers can forward DNS messages without being explicitly configured to do so. Routers will forward the DNS messages like they forward other packets.

Although not a common practice, a Cisco router can be configured **as a DNS server**. If an internal DNS server is used, it is typically a Windows or Linux server. “Internal” in this context refers to a DNS server that is located on the local network, rather than a public DNS server like Google’s.

A Cisco router can also be configured **as a DNS client**. This allows you to use hostnames instead of IP addresses when executing commands such as PING.

A Cisco router can be configured **as a DNS server and DNS client at the same time**.

### Configuring a router as a DNS server

Here’s how to configure a Cisco router as a DNS server.

<figure><img src="https://itnetworkingskills.wordpress.com/wp-content/uploads/2024/05/ce55f-configuring-router-dns-server-15.webp?w=1201" alt="Configuring-router-DNS-server" height="358" width="1201"><figcaption><p>Image courtesy of Jeremy’s IT Lab (Free CCNA | DNS | Day 38)</p></figcaption></figure>

First, use the command IP DNS SERVER from global config mode. This configures the router to act as a DNS server. If a client sends a DNS query to R1, R1 will respond if it has the requested record. For that to work, R1 must have some host records. To build a host table on R1, use the IP HOST command, followed by the host name and the IP address. We configured entries for R1, PC1, PC2, and PC3.

Next we configured an external DNS server for R1 to use, to query if R1 does not have a requested record in its own table. We configured R1 to use Google’s DNS server at 8.8.8.8. We will see how this works in a minute.

Next we used the command IP DOMAIN LOOKUP to enable R1 to perform DNS queries. This command is enabled by default. Usually you do not need to configure it. Note, the old version of this command is IP DOMAIN-LOOKUP.

### DNS demo 1

Let’s say PC1 wants to ping PC2. We configured PC1 to use R1 as its DNS server instead of Google.

<figure><img src="https://itnetworkingskills.wordpress.com/wp-content/uploads/2024/05/c6e06-configuring-router-dns-server-16.webp?w=1201" alt="Configuring-router-DNS-server" height="610" width="1201"><figcaption><p>Image courtesy of Jeremy’s IT Lab (Free CCNA | DNS | Day 38)</p></figcaption></figure>

We issue the PING PC2 command on PC1. Note that we used “hyphen n 1” (-n 1) to specify a single ping. PC1 does not have an entry for PC2 in its own host table, so PC1 uses DNS to learn the IP address of PC2. PC1 sends a query to its DNS server R1 asking for the IP address of PC2.

R1 has an entry for PC2, we just configured it using the IP HOST command. So R1 replies to PC1’s query. Finally PC1 sends the ping to PC2, and PC2 sends a reply. Now PC1 has an entry for PC2 in its DNS cache. If PC1 wants to ping PC2 again, PC1 does not need to perform a DNS query.

### DNS demo 2

We added the YouTube server to the diagram. This time, we issued the command PING YOUTUBE.COM -N 1.

Let’s walk through that process again.&#x20;

<figure><img src="https://itnetworkingskills.wordpress.com/wp-content/uploads/2024/05/76446-configuring-router-dns-server-17.webp?w=1201" alt="Configuring-router-DNS-server" height="626" width="1201"><figcaption><p>Image courtesy of Jeremy’s IT Lab (Free CCNA | DNS | Day 38)</p></figcaption></figure>

Before PC1 can send the ping, it has to know the IP address of youtube.com, so it sends a query to its DNS server, R1. However, R1 does not have an entry for youtube.com. What will R1 do? Remember we used the IP NAME-SERVER 8.8.8.8 command on R1, so R1 can send queries to Google’s DNS server. Google’s server replies, telling R1 the IP address of youtube.com. Now R1 is able to reply to PC1’s query, telling it the IP address of youtube.com. Finally PC1 is able to send the ping to YouTube, and YouTube sends the reply.&#x20;

R1 acts as a DNS server for PC1. But if R1 does not have an entry for a record that PC1 requests, R1 acts as a DNS client and asks Google’s DNS server for the record.

Use the command SHOW HOSTS to view the configured hosts, as well as the hosts learned and cached via DNS. The following output shows the cached entry for youtube.com that R1 learned from Google’s DNS server.&#x20;

<figure><img src="https://itnetworkingskills.wordpress.com/wp-content/uploads/2024/05/5bef7-show-hosts-dns-18.webp?w=1201" alt="show-hosts-dns" height="475" width="1201"><figcaption><p>Image courtesy of Jeremy’s IT Lab (Free CCNA | DNS | Day 38)</p></figcaption></figure>

Notice in the flags column it says “temp”, for temporary. This entry is not permanent because it was learned via DNS. When it expires it must be re-learned. The manually configured entries for R1, PC1, PC2, and PC3 are permanent, as shown in the flags column.

### Configuring a router as a DNS client

Here’s how to configure a Cisco router as a DNS client. To demonstrate, all DNS settings from R1 were deleted. Then we tried to ping youtube.com, but the ping failed. R1 was not able to translate youtube.com to an IP address.

<figure><img src="https://itnetworkingskills.wordpress.com/wp-content/uploads/2024/05/e9665-configuring-router-dns-client-19.webp?w=1201" alt="Configuring-router-DNS-client" height="461" width="1201"><figcaption><p>Image courtesy of Jeremy’s IT Lab (Free CCNA | DNS | Day 38)</p></figcaption></figure>

After the ping failed, we used the IP NAME-SERVER 8.8.8.8 command on R1 to configure R1 to send queries to Google’s DNS server. And we used the IP DOMAIN LOOKUP command on R1 to enable R1 to perform DNS queries. Recall, this command is enabled by default, you do not actually have to enter it.

Then we tried to ping youtube.com again and it worked. We have configured R1 as a DNS client. However, in this case R1 is not a DNS server, so if PC1 tries to use R1 as a DNS server, R1 will not reply to PC1’s queries.

The IP DOMAIN NAME command is an optional command you can use to configure the default domain name. In our example, jeremysitlab.com was specified as R1’s domain name. When applied, this command will be a default domain name for all hostnames without a specified domain name. For example, the command PING PC1 will become PING PC1.JEREMYSITLAB.COM.

There is an older version of the IP DOMAIN NAME command, with a hyphen between DOMAIN and NAME.&#x20;

### Command review

**1. Windows command prompt**&#x20;

C:\Users\user>**ipconfig /all**

C:\Users\user>**nslookup** _domain-name_

C:\Users\user>**ipconfig /displaydns**

C:\Users\user>**ipconfig /flushdns**

C:\Users\user>**ping** _ip-address_ **-n** _pings-number_

**2. Cisco IOS commands**

\>Configuring a router as a DNS server (**with examples**):

R(config)#**ip dns server**\
→to configure the router to act as a DNS server

R(config)#**ip host** _hostname_ _ip-address_\
→to configure a list of hostname and IP address mappings (to build a host table on the router)

R1(config)#ip host R1 192.168.0.1

R1(config)#ip host PC1 191.168.0.101

R1(config)#ip host PC1 191.168.0.102

R(config)#**ip name-server** _ip-address_\
→to configure an external DNS server that the router will query if the requested record is not in its host table

R1(config)#ip name-server 8.8.8.8

R(config)#**ip domain lookup**\
→to enable the router to perform DNS queries (enabled by default)

R#**show hosts** \
→to view the configured hosts (name and IP address mappings), as well as the hosts learned and cached via DNS

\>Configuring a router as a DNS client (**with examples**):

R1(config)#ip name-server 8.8.8.8\
→to configure R1 to use the specified DNS server (Google’s DNS server in this case)

R1(config)#ip domain lookup\
→enable R1 to perform DNS queries (enabled by default)

R(config)#**ip domain name** _domain-name_\
→(optional) to configure the default domain name&#x20;

R1(config)#ip domain name jeremysitlab.com

[Free CCNA | DNS | Day 38 Lab – Notes](https://docs.google.com/document/d/e/2PACX-1vS79akeguiFLpMKYg0BgdioGPEi1iLx88PQPS39SxXs_9bX5uDZG3iIdN4FUivXDYidrb-STxcFKxX7/pub)

### Key learnings

\*The role of DNS within the network.

\*The basic functions of DNS – an overview of how DNS works using a Windows PC. For example, how a Windows PC uses Google’s DNS server to learn the IP address of youtube.com, and then adds that IP address to its DNS cache.&#x20;

\*How to configure DNS in Cisco IOS – how to configure a Cisco router to be a DNS server and a DNS client.

### Practice quiz questions

**Quiz question 1**

Which of the following Windows command prompt commands will display the PC’s DNS server? Select two.

a) ipconfig

b) ipconfig /all

c) ipcofig /displaydns

d) nslookup

The correct answers are b and d. a, IPCONFIG, displays the PC’s IP address, subnet mask, and default gateway, but not details like the DNS server. c, IPCONFIG /DISPLAYDNS, shows the PC’s DNS cache, but not the DNS server address.

You can find four more practice questions for this lesson (plus a bonus one) in Jeremy’s video lesson DNS, cited below.

### Key references

Note: The resources cited below (in the “Key references” section of this document) are the main source of knowledge for these study notes/this lesson, unless stated otherwise.

[Free CCNA | DNS | Day 38 | CCNA 200-301 Complete Course](https://www.youtube.com/watch?v=4C6eeQes4cs\&list=PLxbwE86jKRgMpuZuLBivzlM8s2Dk5lXBQ\&index=73)

[Free CCNA | DNS | Day 38 Lab | CCNA 200-301 Complete Course](https://www.youtube.com/watch?v=7D_FapNrRUM\&list=PLxbwE86jKRgMpuZuLBivzlM8s2Dk5lXBQ\&index=74)
