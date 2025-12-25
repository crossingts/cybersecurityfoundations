---
description: >-
  This section covers DHCP and its basic function (DORA), configuration as a
  server and relay agent, and verification commands on clients
---

# Configuring and verifying DHCP client and relay

## Learning objectives

* Explain the purpose and benefits of DHCP in modern IP networks
* Describe the four-step DORA process used by a client to obtain an IP address lease
* Configure a Cisco IOS router to act as a DHCP server for a local network
* Configure a Cisco IOS router to act as a DHCP relay agent to forward requests to a central server
* Configure a Cisco router as a DHCP client
* Use common client utilities (ipconfig /release, /renew, /all) to verify and manage DHCP-obtained addressing

This section explains the role of DHCP within the network, the basic function of DHCP, specifically the four-message exchange that clients use to get an IP address from a DHCP server (Discover, Offer, Request, and Acknowledgment), and how to configure a Cisco router as a DHCP server, a DHCP relay agent, and a DHCP client.

## Topics covered in this section

* **The role of DHCP within the network**
* **ipconfig /all (Windows)**
* **ipconfig /release (Windows)**
* **ipconfig /renew (Windows)**
* **The basic function of DHCP**
  * **DHCP Discover message**
  * **DHCP Offer message**
  * **DHCP Request message**
  * **DHCP Ack message**
* **DORA (Discover, Offer, Request, Acknowledge)**
* **How to configure DHCP**
  * **DHCP server configuration in IOS**
  * **DHCP relay agent configuration in IOS**
  * **DHCP client configuration in IOS**
* **Command review**

### The role of DHCP within the network

DHCP is a network protocol that is used to configure network devices to communicate on an IP network. DHCP automatically assigns IP addresses and other network configuration settings to devices on a network. This eliminates the need for network administrators to manually configure each device, which can save time and reduce errors. DHCP servers play a vital role in networks. Almost every user endpoint uses DHCP to learn its IP address, mask, default gateway, and DNS server IP addresses.

When a DHCP client device boots up, it sends a broadcast message to the network asking for a DHCP server. The DHCP server responds with an offer, which includes configuration information such as an IP address, subnet mask, default gateway, and one or more DNS server addresses. The DHCP client then accepts the offer and begins using the assigned IP parameters.

DHCP is a very important protocol for large networks, as it allows for efficient and automated management of IP addresses. It is also commonly used on home networks, as it makes it easy to add new devices to the network without having to manually configure them. In small networks such as home networks the router typically acts as the DHCP server for hosts in the LAN. In large networks, such as a large enterprise network, the DHCP server is usually a Windows or Linux server.

Devices such as routers and servers are usually manually configured. This is because they need to have a fixed IP address to perform their function. If the default gateway of the network kept changing it would slow down networking.

### ipconfig /all (Windows)

The ipconfig /all command provides a detailed configuration report for every network adapter on the machine. The most critical IP parameters are:

| Parameter                  | Description                                                                                 | What It Tells You                                                                                                             |
| -------------------------- | ------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| **IPv4 Address**           | The unique address assigned to your computer on the local network (e.g., `192.168.1.101`).  | Your computer's identity on the LAN. An address starting with `169.254.x.x` means it failed to get a valid address.           |
| **Subnet Mask**            | Defines the size and boundaries of your local network (e.g., `255.255.255.0`).              | Which other addresses are on your local network vs. a remote one.                                                             |
| **Default Gateway**        | The IP address of your router, the "door" to the internet.                                  | The path your computer uses to access the internet. If this is missing, you have no internet access.                          |
| **DHCP Enabled**           | States whether the IP address was obtained automatically from a server.                     | "Yes" is standard for most networks. "No" means the address is set manually (static IP).                                      |
| **DHCP Server**            | Identifies the device that leased the IP address to your computer.                          | On most home networks, this is the same as your **Default Gateway** (your router).                                            |
| **DNS Servers**            | The "phone book" servers that translate domain names (e.g., google.com) to IP addresses.    | Who is responsible for your domain name lookups. Could be your router, your ISP, or a public service like Google (`8.8.8.8`). |
| **Lease Obtained/Expires** | The timestamp showing when the current IP address was assigned and when it will be renewed. | Helps diagnose connectivity issues related to DHCP lease expiration.                                                          |
| **Physical Address (MAC)** | The unique, burned-in hardware address of the network adapter.                              | A permanent identifier used for device recognition on the network.                                                            |

Here is the raw ipconfig /all command output on a Windows 10 machine.

<figure><img src="../../.gitbook/assets/image (1).png" alt="ipconfig-all-1"><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (2).png" alt="ipconfig-all-2"><figcaption></figcaption></figure>

**When and Why to Use `ipconfig /all`**

This command is the first and most important tool for **network troubleshooting**. You would use it to:

1. **Diagnose "No Internet Access" or Connection Problems:**
   * **Why:** To find the exact point of failure. Is the problem with getting an IP address, finding the router, or resolving domain names?
   * **What to look for:**
     * **No IP Address or `169.254.x.x` address:** The computer cannot contact the DHCP server (router). Indicates a cable, Wi-Fi, or router issue.
     * **Missing Default Gateway:** You have an IP but no path to the internet.
     * **Can ping Gateway but not websites:** A **DNS server** issue.
2. **Verify Network Configuration:**
   * **Why:** To confirm your computer has received the correct settings from the network or that manual (static) settings are entered properly.
   * **What to look for:** Check if the `IPv4 Address`, `Subnet Mask`, `Default Gateway`, and `DNS Servers` match what is expected for your network.
3. **Release and Renew a DHCP IP Address:**
   * **Why:** To request a fresh IP configuration from the router, which can solve many common connectivity issues.
   * **How:** Use the commands `ipconfig /release` followed by `ipconfig /renew`. Then, run `ipconfig /all` again to verify the new parameters.
4. **Find Physical Hardware Addresses (MAC Address):**
   * **Why:** To register a device on a network that uses **MAC address filtering** for security, or to identify a specific device on the network.

In short, `ipconfig /all` is used to get a complete view of your computer's network identity and connectivity status, making it the fundamental first step in solving any network problem.

### ipconfig /release (Windows)

Let’s do a short demo of the process that a DHCP client goes through to get an IP address from a DHCP server. To release the DHCP-learned IP address on our PC, we need to use the IPCONFIG /RELEASE command in the Windows command prompt. This command will tell our PC to give up its current IP address.

Now no information is displayed for the Ethernet0 interface, which is typically the first interface on a PC and it is used to connect the PC to the Internet or to a local area network (LAN). Ethernet adapter is the default Ethernet adapter on a PC.

<figure><img src="https://itnetworkingskills.wordpress.com/wp-content/uploads/2024/05/15d9b-ipconfig-release-1.webp?w=1201" alt="ipconfig-release" height="574" width="1201"><figcaption><p>Image courtesy of Jeremy’s IT Lab (Free CCNA | DHCP | Day 39)</p></figcaption></figure>

Our PC (192.168.0.167) sent a DHCP Release message to the DHCP server, our router, telling it that the IP address 192.168.0.167 is no longer needed.

Let’s look at that DHCP release message using Wireshark.

The DHCP release message is an [Ethernet frame](https://itnetworkingskills.wordpress.com/2023/04/16/how-traffic-flows-within-lan/). Here’s the Ethernet header:

<figure><img src="https://itnetworkingskills.wordpress.com/wp-content/uploads/2024/05/1cb28-dhcp-release-message-2.webp?w=1201" alt="DHCP-release-message" height="598" width="1201"><figcaption><p>Image courtesy of Jeremy’s IT Lab (Free CCNA | DHCP | Day 39)</p></figcaption></figure>

\>An IPv4 header is inside the Ethernet header, from source IP address 192.168.0.167, the PC, to destination IP 192.168.0.1, the router.

\>Inside is a UDP header. Notice the ports. Source port 68, destination port 67. DHCP clients use UDP port 68, and DHCP servers use UDP port 67. So the source port is the DHCP client, and the destination port is the DHCP server.

\>Inside of the UDP segment there is the DHCP release message. The client IP address is indicated, 192.168.0.167.

Notice the four option fields. For example, the first option, option (53), indicates what kind of DHCP message it is.

Notice the field above the four option fields. The DHCP magic cookie is used to prevent DHCP servers from responding to BOOTP messages. BOOTP is a predecessor to DHCP, and it does not use the magic cookie. If a DHCP server receives a BOOTP message that does not contain the magic cookie, it will ignore the message.

### ipconfig /renew (Windows)

Let’s look at how our PC can get an IP address from the DHCP server.

From the Windows command prompt we used the command IPCONFIG /RENEW. Our PC contacts the DHCP server, and now our PC has the same configuration as before it released the IP address.

<figure><img src="https://itnetworkingskills.wordpress.com/wp-content/uploads/2024/05/4cc17-ipconfig-renew-3.webp?w=1201" alt="ipconfig-renew" height="506" width="1201"><figcaption><p>Image courtesy of Jeremy’s IT Lab (Free CCNA | DHCP | Day 39)</p></figcaption></figure>

### The basic function of DHCP

Here is a brief outline of the four-message process that a DHCP client goes through to lease an IP address from a DHCP server.

* DHCP Discover: The client sends a DHCP Discover message to the network. This message is a broadcast message, so it can be heard by all DHCP servers on the network. The DHCP Discover message tells the DHCP servers that the client is looking for an IP address.
* DHCP Offer: One or more DHCP servers respond to the DHCP Discover message with a DHCP Offer message. The DHCP Offer message contains an offer of an IP address to the client. The DHCP Offer message also contains other information, such as the subnet mask, default gateway, and DNS server addresses.

<figure><img src="https://itnetworkingskills.wordpress.com/wp-content/uploads/2024/05/cf33c-dhcp-dora-4.webp?w=1201" alt="dhcp-dora" height="601" width="1201"><figcaption><p>Image courtesy of Jeremy’s IT Lab (Free CCNA | DHCP | Day 39)</p></figcaption></figure>

* DHCP Request: The client selects one of the DHCP offers and sends a DHCP Request message to the selected DHCP server. The DHCP Request message tells the DHCP server that the client accepts the offered IP address.
* DHCP Acknowledgement: The DHCP server sends a DHCP Acknowledgement message to the client. The DHCP Acknowledgement message confirms that the client has been assigned the offered IP address.

Once the DHCP Acknowledgement message has been received, the client can start using the assigned IP address.

#### DHCP Discover message

The **first** message is the DHCP Discover message. The DHCP Discover message is a broadcast message sent from the client (our PC) asking if there are any DHCP servers in the local network, telling them it needs an IP address. The Discover message contains information such as the client identifier (e.g., the MAC address and hostname of the client), and the client’s preferred lease time (of the assigned IP address) and requested options (like subnet mask, default gateway, and DNS servers).

The DHCP Discover message is sent to the broadcast address 255.255.255.255. This ensures that all DHCP servers on the network will receive the message. If there are multiple DHCP servers on the network, the server that responds to the DHCP Discover message with the best offer will be the one that the client will lease an IP address from.

The following factors are considered when a DHCP client chooses the best offer:

* The IP address: The client will prefer an IP address in the same subnet as its default gateway. This will ensure that the client can communicate with other devices on the network.
* The lease time: The client will prefer a long lease time. This will mean that the client does not have to renew its IP address as often.
* The DHCP server: The client will prefer a DHCP server that is reliable and has a good reputation. This will reduce the risk of the client not being able to obtain an IP address or having its IP address lease expire unexpectedly.

If there are multiple DHCP servers that offer the same IP address with the same lease time, then the client will choose the DHCP server with the highest priority. The priority of a DHCP server is configured by the network administrator.

Let’s look at a Wireshark packet capture of the DHCP Discover message sent by our PC.

Here’s the Ethernet header:

<figure><img src="https://itnetworkingskills.wordpress.com/wp-content/uploads/2024/05/313df-dhcp-discover-ethernet-header-5.webp?w=1201" alt="DHCP-Discover-ethernet-header" height="616" width="1201"><figcaption><p>Image courtesy of Jeremy’s IT Lab (Free CCNA | DHCP | Day 39)</p></figcaption></figure>

\>Notice the destination broadcast MAC address of all Fs. Our PC does not know the IP address or MAC address of the DHCP server. The PC does not even know if there is a DHCP server on the network, that’s why the PC has to broadcast the message.

\>Next is the IPv4 header. Notice the source IP address of 0.0.0.0. This means our PC does not have an IP address yet. The destination is 255.255.255.255, so it’s a broadcast message.

\>Next, the UDP header. Since this is a message from the DHCP client to the server, the source port is UDP 68 and the destination is UDP 67.

\>Next is the actual DHCP Discover message. Here are a few of the fields.

First off, the Bootp flags field. Note the value of Bootp flags 0x0000 unicast. Notice, the message (destination) is broadcast but this field says unicast. Hold that thought.

Then we can see that the client IP address is 0.0.0.0, since our PC does not have an IP address yet.

The client MAC address is also displayed.

The options are also displayed. Notice, they are different than the options used in the DHCP Release message.

Note option (50), Requested IP Address. Because our PC previously had the IP address 192.168.0.167, it requested that address again. If the address is available, the server might grant it again. Otherwise our PC will be assigned a different IP address.

#### DHCP Offer message

The **second** message is the DHCP Offer message. It is sent from the DHCP server to the client, offering an IP address for the client to use, as well as other information such as:

* The IP address of the DHCP server.
* The subnet mask for the network.
* The default gateway for the network.
* The DNS server addresses for the network.
* The lease time for the IP address.
* The DHCP options that the client should use.

The DHCP options are a set of additional parameters that can be configured by the DHCP server. These options can be used to configure the client with a variety of settings, such as the proxy server address and the time zone.

Let’s look at a Wireshark capture of the DHCP Offer message our router sent to our PC.

\>First off, notice the Offer is sent as a unicast frame to the client’s MAC address, since the server learned the client’s MAC address from the Discover message.

<figure><img src="https://itnetworkingskills.wordpress.com/wp-content/uploads/2024/05/73a10-dhcp-offer-ethernet-header-6.webp?w=1201" alt="DHCP-offer-ethernet-header" height="650" width="1201"><figcaption><p>Image courtesy of Jeremy’s IT Lab (Free CCNA | DHCP | Day 39)</p></figcaption></figure>

\>It’s also unicast at Layer 3, the destination is the IP address being offered to the client.

\>Now the source and destination port number are reversed, since it’s a message from the server to the client. The source is UDP 67 and the destination is UDP 68.

\>The Offer message: look again at the field Bootp flags. Again, it says unicast. When our PC sent the DHCP Discover message this field was also set to 0000, unicast. The DHCP Offer message can be sent to the client using either broadcast or unicast. It depends on the client. In this case our PC told the router to send the Offer using unicast, so it did. Sometimes broadcast must be used because some clients will not accept unicast messages before their IP address is configured.

Finally, the options. Option 51 indicates the lease time. Option 6 is the DNS server. And option 3 is router, which tells the client the default gateway.

#### DHCP Request message

The **third** message of the four-message process used to lease an IP address from a DHCP server is the DHCP Request message. The DHCP Request message is sent from the DHCP client to the server. The Request message informs the server that the client wants to use the offered IP address.

There may be multiple DHCP servers on the local network, and they will all reply to the client’s Discover message with an Offer. The client has to tell which server it is accepting the offer from.

Let’s look at that Request message in Wireshark.

\>The destination MAC is all Fs, again a broadcast message.

<figure><img src="https://itnetworkingskills.wordpress.com/wp-content/uploads/2024/05/a7625-dhcp-request-ethernet-header-7.webp?w=1201" alt="DHCP-request-ethernet-header" height="631" width="1201"><figcaption><p>Image courtesy of Jeremy’s IT Lab (Free CCNA | DHCP | Day 39)</p></figcaption></figure>

If there are multiple DHCP servers in the network, they will all receive the Request message. The DHCP server identifier field (option 54) indicates which server the PC accepted the offer from.

\>The source IP is still 0.0.0.0, since the offered IP address has not been configured yet. The destination is broadcast, 255.255.255.255.

\>Since it’s a message from the client to the server, the source port is UDP 68 and the destination is UDP 67.

\>The request message – note the Bootp flags field again, telling the server to send its messages using unicast.

Finally, the options for this Request message. Notice that the server’s IP address is indicated using option 54. If there are multiple DHCP servers on the local network, this is how the client says which server it selected.

#### DHCP Ack message

The **fourth** and final message in the process of leasing an IP address is the DHCP Ack, acknowledgement. This is sent from the server to the client, confirming that the client may use the requested IP address.

Once the client receives the Ack message, the client finally configures the IP address on its network interface.

Here’s that Ack message in Wireshark.

Notice that these messages from the server to the client are again sent unicast.

<figure><img src="https://itnetworkingskills.wordpress.com/wp-content/uploads/2024/05/23200-dhcp-ack-ethernet-header-8.webp?w=1201" alt="DHCP-ack-ethernet-header" height="644" width="1201"><figcaption><p>Image courtesy of Jeremy’s IT Lab (Free CCNA | DHCP | Day 39)</p></figcaption></figure>

The server uses UDP port 67, so that’s the source port. And the client uses UDP port 68, so that’s the destination port.

Looking at the Ack message fields, the Bootp flags field again indicates unicast, because the client requested unicast messages. Just like the DHCP Offer message, the DHCP Ack message can be either broadcast or unicast, depending on what the client requests.

### DORA (Discover, Offer, Request, Acknowledge)

Here’s a summary of the IP lease process. A common way to remember the messages is DORA, for Discover, Offer, Request, and Ack.

| Discover | Client → Server | Broadcast            |
| -------- | --------------- | -------------------- |
| Offer    | Server → Client | Broadcast or unicast |
| Request  | Client → Server | Broadcast            |
| Ack      | Server → Client | Broadcast or unicast |
| Release  | Client → Server | Unicast              |

### How to configure DHCP

Next we will learn how to configure DHCP. **First**, we will see how to configure a Cisco router as a DHCP server. **Second**, we look at how to configure a Cisco router as a DHCP relay agent. **Third**, we look at how to configure a Cisco router as a DHCP client.

### DHCP server configuration in IOS

First, let’s see how to configure a Cisco router to function as a DHCP server.

Let’s use R1 and PC1 to demonstrate. Here are the commands.

<figure><img src="https://itnetworkingskills.wordpress.com/wp-content/uploads/2024/05/cfd1f-how-configure-dhcp-10.webp?w=1201" alt="How-configure-DHCP" height="607" width="1201"><figcaption><p>Image courtesy of Jeremy’s IT Lab (Free CCNA | DHCP | Day 39)</p></figcaption></figure>

\>First, you can use the IP DHCP EXCLUDED-ADDRESS command to specify a range of addresses that you want to exclude from the pool of available IP addresses to assign to clients. Perhaps you want to reserve these addresses for network devices or servers in the local subnet. This configuration reserves all addresses from 192.168.1.1 through 192.168.1.10. Note, you can configure a Cisco router to function as a DHCP server without using this command.

\>Next, use the command IP DHCP POOL, followed by the pool name, to create a DHCP pool. The DHCP pool contains a subnet of addresses that can be assigned to DHCP clients, as well as other information such as DNS server and default gateway. For each network that the router is acting as a DHCP server for, create a separate DHCP pool. In this case R1 is only acting as the DHCP server for 192.168.1.0/24, so we only need to create one pool.

\>Next, configure the range of addresses to be assigned to clients. Use the command NETWORK, followed by the network address and then either the prefix length or network mask (/24 or 255.255.255.0). We configured R1 to assign addresses from 192.168.1.0/24 to clients, the addresses reserved earlier notwithstanding.

\>Next, configure the DNS server that clients in the network should use. In this case R1 would tell PC1 to use Google’s DNS server at 8.8.8.8 for its DNS queries.

You can also configure the domain name of the network. In this case R1 will tell PC1 that it is part of the domain jeremysitlab.com.

Then there’s the DEFAULT-ROUTER command, the default gateway. We configured R1 to tell clients to use its address, 192.168.1.1, as their default gateway.

You can also configure the lease time. We specified 0 5 30, which is 0 days, 5 hours, and 30 minutes.

When PC1 comes online and sends its DHCP Discover message, PC1 may be assigned 192.168.1.11, the first available address (since .1 through .10 are reserved/excluded).

Let’s confirm. SHOW IP DHCP BINDING shows all of the DHCP clients that are currently assigned IP addresses.

Here’s PC1, with an IP address of 192.168.1.11.

<figure><img src="https://itnetworkingskills.wordpress.com/wp-content/uploads/2024/05/38bcf-show-ip-dhcp-binding-11.webp?w=1201" alt="show-ip-dhcp-binding" height="167" width="1201"><figcaption><p>Image courtesy of Jeremy’s IT Lab (Free CCNA | DHCP | Day 39)</p></figcaption></figure>

PC1’s MAC address, the lease expiration date and time, and the binding type are displayed. DHCP bindings can be manually configured, though we did not do that in this case.

Let’s check the configuration on PC1.

<figure><img src="https://itnetworkingskills.wordpress.com/wp-content/uploads/2024/05/72f73-ipconfig-all-12.webp?w=1201" alt="ipconfig-all" height="460" width="1201"><figcaption><p>Image courtesy of Jeremy’s IT Lab (Free CCNA | DHCP | Day 39)</p></figcaption></figure>

Notice the domain name is jeremysitlab.com. The IP address is 192.168.1.11. And the subnet mask is 255.255.255.0. All as configured.

Notice that the lease period is 5 hours and 30 minutes, as configured. The lease expiration times on PC1 and R1 are different because we did not configure the time zone.

Finally, we can see the default gateway, DHCP server, and DNS server.

The configuration was successful.

### DHCP relay agent configuration in IOS

What is DHCP relay and how does a DHCP relay agent work? Some network engineers might choose to configure each router to act as the DHCP server for its connected LANs. However, large enterprises often choose to use a centralized DHCP server, which will assign IP addresses to DHCP clients in all subnets in the enterprise.

If the server is centralized, the server will not receive the clients’ broadcast DHCP messages. Recall, broadcast messages do not leave the local subnet. Routers do not forward broadcast messages.

A router can be configured as a DHCP relay agent. Then the router will forward the clients’ broadcast DHCP messages to the remote DHCP server as unicast messages.

PC1 is a DHCP client, so it will broadcast a DHCP Discover message to ask DHCP servers on the local network for an IP address. R1 is not a DHCP server. SRV1 is the central DHCP server for this network, so R1 will need to forward any DHCP messages from PC1 to SRV1.

<figure><img src="https://itnetworkingskills.wordpress.com/wp-content/uploads/2024/05/6b43b-dhcp-relay-9.webp?w=1201" alt="DHCP-relay" height="622" width="1201"><figcaption><p>Image courtesy of Jeremy’s IT Lab (Free CCNA | DHCP | Day 39)</p></figcaption></figure>

SRV1 is a DHCP server, and R1 is a DHCP relay agent.

PC1 broadcasts a DHCP Discover message to get an IP address. R1, a DHCP relay agent, relays the message to SRV1. Notice that the source IP address changes to the address of R1’s G0/1 interface, and the destination is SRV1’s IP address (it is a unicast message).

Then SRV1 replies with the DHCP Offer, sending it to R1’s G0/1, 192.168.1.1. R1 then forwards the Offer message to PC1. The message source is R1’s IP address, and the message is sent either unicast to PC1 or broadcast.

Then PC1 broadcasts a Request message, and R1 relays it to SRV1. Finally SRV1 replies with a DHCP Ack, and R1 forwards that to PC1, which configures the IP address it was assigned, for example, 192.168.1.100.

**Next let’s see how to configure a router as a DHCP relay agent.**

Here’s that same network as before, SRV1 is a DHCP server and R1 will be a DHCP relay agent after we configure it.

<figure><img src="https://itnetworkingskills.wordpress.com/wp-content/uploads/2024/05/85a87-dhcp-relay-agent-configuration-ios-13.webp?w=1201" alt="DHCP-relay-agent-configuration-IOS" height="601" width="1201"><figcaption><p>Image courtesy of Jeremy’s IT Lab (Free CCNA | DHCP | Day 39)</p></figcaption></figure>

To configure R1 as a relay agent, first enter interface config mode for the interface connected to the client devices, the interface you want to configure. In this case it’s R1’s g0/1.

Then use the command IP HELPER-ADDRESS, followed by the IP address of the DHCP server. Make sure R1 has a route to the DHCP server. If not, configure a static route or use a dynamic routing protocol like OSPF.

Then we checked the interface with SHOW IP INTERFACE G0/1. Notice that the helper address is 192.168.10.10, which is SRV1.

### DHCP client configuration in IOS

A Cisco router can be a DHCP client, meaning it can use DHCP to configure the IP address of its interfaces.

Here’s how to configure a Cisco router as a DHCP client.

Let’s make R2 a DHCP client on its G0/1 interface.

<figure><img src="https://itnetworkingskills.wordpress.com/wp-content/uploads/2024/05/1d95c-dhcp-relay-agent-configuration-ios-14.webp?w=1201" alt="DHCP-relay-agent-configuration-IOS" height="588" width="1201"><figcaption><p>Image courtesy of Jeremy’s IT Lab (Free CCNA | DHCP | Day 39)</p></figcaption></figure>

From interface config mode for G0/1, use the command IP ADDRESS DHCP. That’s it, now R2 will broadcast a DHCP Discover message and get an IP address from SRV1.

We checked with SHOW IP INTERFACE G0/1, and you can see the entry, “address determined by DHCP”.

### Command review

**1. Windows command prompt**

C:\Users\user>**ipconfig /all**\
→to check the network configuration on the PC (all available information for each adapter)

C:\Users\user>**ipconfig /release**\
→to tell the PC to give up its current DHCP-learned IP address

C:\Users\user>**ipconfig /renew**\
→to renew the IP address configuration of the PC’s network adapter

**2. Cisco IOS commands (DHCP configuration)**

_2.1. Configure a Cisco router as a DHCP server (**with examples**)_

R(config)#**ip dhcp excluded-address** _low-address high-address_\
→to specify a range of addresses to exclude from the pool of available IP addresses to assign to clients. You can configure a Cisco router to function as a DHCP server without using this command

R1(config)#ip dhcp excluded-address 192.168.1.1 192.168.1.10

R(config)#i**p dhcp pool** _pool-name_\
→to create a DHCP pool. Create a separate DHCP pool for each network that the router is acting as a DHCP server for

R1(config)#ip dhcp pool LAB\_POOL

In this case R1 is acting as the DHCP server for only 192.168.1.0/24, so we only need to create one pool.

R(dhcp-config)#**network** _ip-address_ {_/prefix-length_ | _subnet mask_}\
→to configure the subnet (range of addresses) to be assigned to clients (except the excluded addresses)

R1(dhcp-config)#network 192.168.1.0 /24\
→to configure R1 to assign addresses from 192.168.1.0/24 to clients, the addresses reserved earlier notwithstanding

R#**show running-config** | **section dhcp**\
→to check the dhcp pool/settings of R

R(dhcp-config)#**dns-server** _ip-address_\
→to specify the DNS server that DHCP clients in the network should use

R1(dhcp-config)#dns-server 8.8.8.8

In this case R1 tells PC1 to use Google’s DNS server at 8.8.8.8 for its DNS queries.

R(dhcp-config)#**domain-name** _domain-name_\
→to configure the domain name of the network

R1(dhcp-config)#domain-name jeremysitlab.com

In this case R1 will tell PC1 that it is part of the domain jeremysitlab.com (i.e., PC1 = PC1.jeremysitlab.com).

R(dhcp-config)#**default-router** _ip-address_\
→to specify the default gateway

R1(dhcp-config)#default-router 192.168.1.1

We configured R1 to tell clients to use its address, 192.168.1.1, as their default gateway.

R(dhcp-config)#**lease** {_days hours minutes | infinite_}\
→to specify the lease time

R1(dhcp-config)#lease 0 5 30

We specified 0 5 30, which is 0 days, 5 hours, and 30 minutes.

R#**show ip dhcp binding**\
→to see all of the DHCP clients that are currently assigned IP addresses

R#**clear ip dhcp binding \***\
→to clear dhcp bindings

_2.2. Configure a Cisco router as a DHCP relay agent (**with examples**)_

R(config-if)#**ip helper-address** _ip-address_\
→to configure the IP address of the DHCP server (to which broadcast requests should be forwarded) as the “helper address” (ip helper-address = the command to enable DHCP relay functionality)

R1(config)#interface g0/1\
→configure the interface connected to the subnet of the client devices

R1(config-if)#ip helper-address 192.168.10.10

R#**show ip interface** _interface_\
→to display detailed information about the interface. Includes IP address, subnet mask, status, encapsulation type, and other relevant parameters

_2.3. Configure a Cisco router as a DHCP client (**example**)_

To make R2 a DHCP client on its G0/1 interface:

R2(config)#interface g0/1

R2(config-if)#**ip address dhcp**\
→to tell the router to use DHCP to learn its IP address

[Free CCNA | DHCP | Day 39 Lab – Notes](https://docs.google.com/document/d/e/2PACX-1vT5Ec0vkK81awEL8mLOTPR20Rro8g3AUyvN-wNsxFWaZiUq8_7CZOhIYZ78wsE_MFRirI9OXIdS6iui/pub)

### Key takeaways

* DHCP automates IP address, subnet mask, gateway, and DNS server assignment, reducing administrative overhead.
* The client-server exchange follows the DORA process: Discover, Offer, Request, Acknowledgement.
* A DHCP server is configured with a pool of addresses and critical network information (default gateway, DNS servers).
* A DHCP relay agent (using the `ip helper-address` command) is required to forward broadcast DHCP messages across router boundaries to a central server.
* Client-side commands like `ipconfig /all`, `/release`, and `/renew` are crucial for verifying connectivity and troubleshooting DHCP issues.

### References

[Free CCNA | DHCP | Day 39 | CCNA 200-301 Complete Course](https://www.youtube.com/watch?v=hzkleGAC2_Y\&list=PLxbwE86jKRgMpuZuLBivzlM8s2Dk5lXBQ\&index=75)

[Free CCNA | DHCP | Day 39 Lab | CCNA 200-301 Complete Course](https://www.youtube.com/watch?v=cgMsoIQB9Wk\&list=PLxbwE86jKRgMpuZuLBivzlM8s2Dk5lXBQ\&index=76)

Odom, W. (2020). CCNA 200-301 Official Cert Guide, Volume 1. Cisco Press.
