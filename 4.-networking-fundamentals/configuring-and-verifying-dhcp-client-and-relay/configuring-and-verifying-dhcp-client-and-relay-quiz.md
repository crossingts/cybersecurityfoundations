# 4.12. Quiz

### Configuring and verifying DHCP client and relay

#### 1. What is the primary Cisco IOS command used to configure a router interface to forward DHCP broadcast requests to a central server on a different network? (Choose one answer)

a) `ip dhcp pool`

b) `ip forward-protocol`

**c) `ip helper-address`**

d) `dhcp relay agent`

#### 2. Which of the following accurately describes the purpose of the DHCP Acknowledgement (ACK) message? (Choose one answer)

a) It is a broadcast sent by the client to discover available DHCP servers

b) It is sent by the server to suggest an IP address configuration to the client

c) It is sent by the client to formally request the offered IP address

**d) It is the final message sent by the server to confirm the IP address lease is finalized**

#### 3. A network technician uses the command `ipconfig /release` followed by `ipconfig /renew` on a Windows PC. What is the intended result of these commands? (Choose one answer)

a) To permanently assign a static IP address to the network interface

b) To display the full TCP/IP configuration for all adapters

**c) To force the client to drop its current DHCP lease and immediately initiate the DORA process to obtain a new one**

d) To configure the PC to act as a DHCP relay agent

#### 4. A Windows PC displays an IP address of 169.254.10.5 after running `ipconfig /all`. What is the most likely cause of this? (Choose one answer)

a) The DNS server is misconfigured

b) The PC has a manually configured static IP address

**c) The PC failed to contact a DHCP server**

d) The IP address lease has expired and cannot be renewed

#### 5. During the DORA process, which message is sent as a broadcast to inform all DHCP servers which offer the client has accepted? (Choose one answer)

a) DHCP Discover

b) DHCP Offer

**c) DHCP Request**

d) DHCP Acknowledgement
