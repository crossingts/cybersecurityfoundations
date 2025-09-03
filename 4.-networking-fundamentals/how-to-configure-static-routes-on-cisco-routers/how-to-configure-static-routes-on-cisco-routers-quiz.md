# How to configure static routes on Cisco routers — Quiz

### How to configure static routes on Cisco routers

#### 1. Which of the following commands configures a default route on a Cisco router? (Choose one answer)

**a) R(config)#ip route 0.0.0.0 0.0.0.0 10.1.1.255**

b) R(config)#ip route 0.0.0.0/0 10.1.1.255

c) R(config-if)#ip route 0.0.0.0 255.255.255.255 10.1.1.255

d) R(config)#ip route 0.0.0.0/32 10.1.1.255

#### 2. What is the primary purpose of configuring a static route on a router? (Choose one answer)

a) To automatically learn all possible network paths

**b) To manually define a path to a remote network that is not directly connected**

c) To assign an IP address to a router's physical interface

d) To encrypt traffic between two remote hosts

#### 3. A network administrator configures the following static route: R(config)# ip route 192.168.99.0 255.255.255.0 GigabitEthernet0/1. What is a potential issue with this configuration if the link to the next-hop router is down? (Choose one answer)

a) The route will be automatically removed from the routing table until the interface comes back up

**b) The route will remain in the routing table, and packets will be dropped because they are forwarded to a down interface**

c) The router will not accept the command because a next-hop IP address must be specified

d) The router will dynamically reroute traffic using a different known path

#### 4. For a host on a network to communicate with a host on a different network, it must be configured with which of the following? (Choose one answer)

a) A Dynamic Host Configuration Protocol (DHCP) server address

b) A DNS server address

**c) A default gateway address**

d) A subnet mask for the remote network

#### 5. When a router processes a packet, which part of the packet's headers remains unchanged from source to destination? (Choose one answer)

a) The source and destination MAC addresses

**b) The source and destination IP addresses**

c) The Time-To-Live (TTL) value

d) The Layer 2 frame header
