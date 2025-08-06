# Scanning and enumeration

### Scanning for Targets

Scanning is "the process of discovering systems on the network and taking a look at what open ports and applications may be running" (Walker, 2012, p. 86).&#x20;

The steps for a scanning methodology according to EC-Council's CEH curriculum are (Walker, 2012, pp. 86-87):

1. Identify live systems (finding out which IP addresses are actually alive). Something as simple as a ping can provide this. This gives you a list of what’s actually alive on your network subnet.
2. Discover open ports. Once you know which IP addresses are active, find what ports they’re listening on.
3. Identify the OS and services. Banner grabbing and OS fingerprinting will tell you what operating system is on the machines and which services they are running.
4. Scan for vulnerabilities. Perform a more focused look at the vulnerabilities these machines haven’t been patched for yet.&#x20;

#### Identifying Active Machines (As Potential Targets)

The simplest and easiest way to check for live systems on a network is to take advantage of ICMP (Internet Control Message Protocol), i.e., pinging target hosts. ICMP is built into every TCP/IP device. ICMP presents information back to the sender in one of several ICMP types. The most common of these are Type 8 (Echo Request) and Type 0 (Echo Reply). Table 4-1 lists some of the more relevant message type codes.

<figure><img src="../../.gitbook/assets/image (2).png" alt="ICMP message types"><figcaption><p>Source: Walker (2012, p. 88)</p></figcaption></figure>

An ICMP Type 8 packet received by a host tells the recipient, “Hey! I’m sending you a few packets. When you get them, reply back with the same number so I know you’re there.” The recipient will respond with an ICMP Type 0, stating, “Sure, I’m alive. Here are the data packets you just sent me as proof!” (Walker, 2012, p. 87)

The associated responses provide detailed information about the recipient host. Consider, for example, an Echo Request (Type 8) sent to a host returning a Type 3. Code 7 would tell us whether the host is down. Code 0 would tell us whether the network route is missing or corrupt in our local route tables. Code 13 would tell us whether a filtering device, such as a firewall, is preventing ICMP messages altogether.

Combining pings to each and every address within a subnet range is known as a ping sweep. A ping sweep is the easiest method to identify active machines on the network, though it may not necessarily be the only or best option. Sometimes it's convenient to combine the search for active machines with a port scan.

Another option for identifying machines (not necessarily live ones, but ones that were live at some time) is called a list scan, performed by running a reverse DNS lookup on all IPs in the subnet.

In addition to the ping command on its own, several tools can be used for a ping sweep. Examples include Angry IP Scanner, Pinger, WS\_Ping, SuperScan, and Friendly Pinger.

#### Port Scanning

Port scanning is "the method by which systems on a network are queried to see which ports they are listening to" (Walker, 2012, p. 92). Since well-known port numbers are associated with specific upper-layer protocols, we can tell a lot about what services a system is running by performing port scanning. A system is said to be "listening for a port" when it has that port open (Walker, 2012, p. 92).

All port scanners work by manipulating Transport Layer (TCP/UDP) flags and analyzing responses to identify active hosts and scan their ports remotely.

#### TCP and UDP Communication

So what is a TCP flag and how does TCP and UDP communication work?

When two TCP/IP-enabled hosts communicate with each other … two methods of data transfer are available at the transport layer: connectionless and connection-oriented. (Walker, 2012, p. 94)

### Enumeration
