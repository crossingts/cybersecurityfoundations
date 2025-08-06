# Scanning and enumeration

### Scanning for Targets

Scanning is "the process of discovering systems on the network and taking a look at what open ports and applications may be running" (Walker, 2012, p. 86).&#x20;

The steps for a scanning methodology according to EC-Council's CEH curriculum are (Walker, 2012, pp. 86-87):

1. Identify live systems (finding out which IP addresses are actually alive). Something as simple as a ping can provide this. This gives you a list of what’s actually alive on your network subnet.
2. Discover open ports. Once you know which IP addresses are active, find what ports they’re listening on.
3. Identify the OS and services. Banner grabbing and OS fingerprinting will tell you what operating system is on the machines and which services they are running.
4. Scan for vulnerabilities. Perform a more focused look at the vulnerabilities these machines haven’t been patched for yet.&#x20;

#### Identifying Active Machines

The simplest and easiest way to check for live systems on a network is to take advantage of ICMP (Internet Control Message Protocol), i.e., pinging target hosts. ICMP is built into every TCP/IP device. ICMP presents information back to the sender in one of several ICMP types. The most common of these are Type 8 (Echo Request) and Type 0 (Echo Reply). Table 4-1 lists some of the more relevant message type codes.

<figure><img src="../../../.gitbook/assets/image (2).png" alt="ICMP message types"><figcaption><p>Source: Walker (2012, p. 88)</p></figcaption></figure>

An ICMP Type 8 packet received by a host tells the recipient, “Hey! I’m sending you a few packets. When you get them, reply back with the same number so I know you’re there.” The recipient will respond with an ICMP Type 0, stating, “Sure, I’m alive. Here are the data packets you just sent me as proof!” (Walker, 2012, p. 87)

The associated responses provide detailed information about the recipient host. Consider, for example, an Echo Request (Type 8) sent to a host returning a Type 3. Code 7 would tell us whether the host is down. Code 0 would tell us whether the network route is missing or corrupt in our local route tables. Code 13 would tell us whether a filtering device, such as a firewall, is preventing ICMP messages altogether.

Combining pings to each and every address within a subnet range is known as a ping sweep. A ping sweep is the easiest method to identify active machines on the network, though it may not necessarily be the only or best option. Sometimes it's convenient to combine the search for active machines with a port scan.

Another option for identifying machines (not necessarily live ones, but ones that were live at some time) is called a list scan, performed by running a reverse DNS lookup on all IPs in the subnet.

In addition to the ping command on its own, several tools can be used for a ping sweep. Examples include Angry IP Scanner, Pinger, WS\_Ping, SuperScan, and Friendly Pinger.

#### Port Scanning: Identifying Open Ports and Running Services

Port scanning is "the method by which systems on a network are queried to see which ports they are listening to" (Walker, 2012, p. 92). Since well-known port numbers are associated with specific upper-layer protocols, we can tell a lot about what services a system is running by performing port scanning. A system is said to be "listening for a port" when it has that port open (Walker, 2012, p. 92).

All port scanners work by manipulating Transport Layer (TCP/UDP) flags and analyzing responses to identify active hosts and scan their ports remotely.

#### TCP and UDP Communication

So what is a TCP flag and how does TCP and UDP communication work?

Two TCP/IP-enabled hosts can use two data transfer methods to communicate with each other: connectionless and connection-oriented.

In connectionless communication the sender does not care whether the recipient currently has the bandwidth to accept the message or whether the recipient gets the message at all. The sender relies on other upper-layer protocols to handle any problems. At the transport layer, connectionless communication is accomplished with UDP. Examples of application protocols that make use of UDP are TFTP, DNS, and DHCP.&#x20;

In connection-oriented communication, which uses TCP, a sender first reaches out to a recipient to make sure the recipient is available before attempting to exchange any data. TCP establishes a connection through the use of header flags and the three-way handshake. The method involves three messages being sent between any two hosts. Six flags can be set in the TCP header. Depending on what a segment is intended to do, some or all of these flags would be set.

The TCP header flags are (Walker, 2012, p. 96):

• URG (Urgent) When this flag is set, it indicates the data inside is being sent out of band.\
• ACK (Acknowledgment) This flag is set as an acknowledgment to SYN flags. This flag is set on all segments after the initial SYN flag.\
• PSH (Push) This flag forces delivery of data without concern for any buffering.\
• RST (Reset) This flag forces a termination of communications (in both directions).\
• SYN (Synchronize) This flag is set during initial communication establishment. It indicates negotiation of parameters and sequence numbers.\
• FIN (Finish) This flag signifies an ordered close to communications.

**Nmap** &#x20;

nmap can perform many different types of scans (from simply identifying active machines to port scanning and enumeration) and can also be configured to control the speed at which a scan operates—in general, the slower the scan, the less likely you are to be discovered. It comes in both a command-line version and a GUI version (now known as Zenmap), works on multiple OS platforms, and can even scan over TCP and UDP. (Walker, 2012, p. 98)

Nmap syntax is fairly straightforward:&#x20;

nmap \<scan options> \<target>

The target for nmap can be a single IP address, multiple individual IPs separated by spaces, or an entire subnet range (using CIDR notation). For example, to scan a single IP, the command might look like&#x20;

nmap 192.168.1.100

whereas scanning multiple IPs would look like&#x20;

nmap 192.168.1.100 192.168.1.101

and scanning an entire subnet would appear as&#x20;

nmap 192.168.1.0/24

Starting nmap without any of the options runs a “regular” scan and provides all sorts of information for you. But to get really sneaky and act like a true ethical hacker, you’ll need to learn the option switches—and there are a bunch of them. Table 4-3 nmap Switches lists some of the more relevant nmap switches. (Walker, 2012, p. 98)

<figure><img src="../../../.gitbook/assets/image (14).png" alt="Nmap switches"><figcaption><p>Source: Walker (2012, p. 99)</p></figcaption></figure>

Generally speaking, there are seven generic scan types for port scanning (Walker, 2012, pp. 99-100):

• TCP Connect Runs through a full connection (three-way handshake) on all ports. Easiest to detect, but possibly the most reliable. Open ports will respond with a SYN/ACK, closed ports with a RST/ACK.\
• SYN Known as a “half-open scan.” Only SYN packets are sent to ports (no completion of the three-way handshake ever takes place). Responses from ports are the same as they are for a TCP Connect scan.\
• FIN Almost the reverse of the SYN scan. FIN scans run the communications setup in reverse, sending a packet with the FIN flag set. Closed ports will respond with RST, whereas open ports won’t respond at all.\
• XMAS A Christmas scan is so named because the packet is sent with multiple flags (FIN, URG, and PSH) set. Port responses are the same as with a FIN scan.\
• ACK Used mainly for Unix/Linux-based systems. ACK scans make use of ICMP destination unreachable messages to determine what ports may be open on a firewall.\
• IDLE Uses a spoofed IP address to elicit port responses during a scan. Designed for stealth, this scan uses a SYN flag and monitors responses as with a SYN scan.\
• NULL Almost the opposite of the XMAS scan. The NULL scan sends packets with no flags set. Responses will vary, depending on the OS and version, but NULL scans are designed for Unix/Linux machines.

Table 4-4 Network Scan Types correlates a scan type and what response to expect from an open or closed port.&#x20;

A quick-and-easy tip to remember is that all scans return an RST on a closed port, with the exception of the ACK scan, which returns no response. nmap handles all these scans, using the switches identified earlier, and more. (Walker, 2012, p. 100)

<figure><img src="../../../.gitbook/assets/image (18).png" alt="Network Scan Types"><figcaption><p>Source: Walker (2012, p. 100)</p></figcaption></figure>

### Enumeration



***
