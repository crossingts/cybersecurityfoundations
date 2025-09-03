# Lab: Configuring and troubleshooting static routes

### Configuring static routes – Packet Tracer Lab 1

[**Get the lab file (.pkt) from Google Drive (Jeremy McDowell's Free CCNA Online Course)**](https://drive.google.com/drive/folders/1PwK_jWqfUtOjV7gHt8ODutq9QA5cxCgi)**: Day 11 Lab - Configuring Static Routes.pkt**

<figure><img src="https://itnetworkingskills.wordpress.com/wp-content/uploads/2024/05/f5a7b-config-static-routes-day11-lab-24.webp?w=1201" alt="Config-Static-Routes-Day11-lab" height="607" width="1201"><figcaption><p>Image courtesy of Jeremy’s IT Lab (Free CCNA | Configuring Static Routes | Day 11 Lab 1)</p></figcaption></figure>

**1. Configure the PCs and routers according to the network diagram (hostnames, IP addresses, etc.). Remember to configure the gateway on the PCs. (You don’t have to configure the switches.)**

1.1. Set the default gateway and IP address for each of PC1 and PC2

1.2. On routers 1, 2, and 3, set the hostname and configure the interfaces.

For example, on R1 configure the interfaces:

1\) Set the IP address on g0/1, add a description, and enable the interface.

2\) Set the IP address on g0/0, add a description, and enable the interface.

3\) Check with show ip interface brief.

**2. Configure static routes on the routers to enable PC1 to successfully ping PC2.**

Step 1: consider what static routes you need to configure. You need two-way reachability, i.e., R1, R2, and R3 each need a route to both PC1’s (192.168.1.0/24) and PC2’s (192.168.3.0/24) networks.

Step 2: configure the routes.

Step 3: check the configured static route with show ip route.

\>R1:&#x20;

-has a route to 192.168.1.0/24.\
-needs a route to 192.168.3.0/24.

R1(config)#ip route 192.168.3.0 255.255.255.0 192.168.12.2

\>R2:

-needs a route to 192.168.1.0/24.\
-needs a route to 192.168.3.0/24.

R2(config)#ip route 192.168.1.0 255.255.255.0 192.168.12.1

R2(config)#ip route 192.168.3.0 255.255.255.0 192.168.13.3

\>R3:

-has a route to 192.168.3.0/24.\
-needs a route to 192.168.1.0/24.

R3(config)#ip route 192.168.1.0 255.255.255.0 192.168.13.2

### Troubleshooting static routes – Packet Tracer Lab 2

[**Get the lab file (.pkt) from Google Drive (Jeremy McDowell's Free CCNA Online Course)**](https://drive.google.com/drive/folders/1PwK_jWqfUtOjV7gHt8ODutq9QA5cxCgi)**: Day 11 Lab - Troubleshooting Static Routes.pkt**

Troubleshoot a configured network that has some problems – using the same network topology of the previous lab.

PC1 and PC2 are unable to ping each other. There is one misconfiguration on each router. Find and fix the misconfigurations. You have successfully completed the lab when PC1 and PC2 can ping each other.

**Step 1:** confirm the problem, can PC1 ping PC2? No.&#x20;

**Step 2:** check the PCs configs, using:

C:\\>ipconfig and/or C:\\>ipconfig /all

Can PC1 ping its default gateway? Yes, no problem.

**Step 3:** go on to R1 to investigate and fix configs/connectivity problems.&#x20;

→check if the interface configs, the IP addresses, are OK using show ip int br. No problem.

→check the routing table using show ip route, to check C, L, and S routes.

Notice: static route to 192.168.3.0/24 is 192.168.12.3 when it should be 192.168.12.2.

You can also check that wrong static route config using show running-config, thus:

R1#show running-config | include ip route

To fix the wrong configuration:

R1(config)#no ip route 192.168.3.0 255.255.255.0 192.168.12.3

This should delete the wrong configuration statement. Check with show ip route or with show running-config | include ip route

The wrong configuration statement is gone. Now configure the correct static route.

**Step 4:** now let’s work on R2.

→show ip int br. No problems.

→check the routing table using show ip route.

Now we can see a wrong static route configuration, it is wrong that g0/0 is the exit interface to reach 192.168.3.0/24.

So again, remove the wrong configuration statement and add the correct one. Do not leave both statements (you don’t want to load balance with this wrong setting, creating problems).

**Step 5:** now let’s look for the issue on R3.

→show ip int br. We see a problem. 192.168.23.3 should be 192.168.13.3, R3’s g0/0 IP address.

We don’t have to remove the wrong IP address first. A new IP address will overwrite a  current IP address, this is unlike when configuring routes.

R3(config)#int g0/0

R3(config-if)#ip address 192.168.13.3 255.255.255.0

Check again with show ip int br and with show running-config. Finally, you can check the routing table with show ip route.

Can PC1 now ping PC2? Yes.
