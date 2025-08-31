# Chapter 4 review questions

### Network devices and their functions

* What is the fundamental difference between the function of a switch and the function of a router?
* Explain the primary limitation of using a hub in a network.
* What are the two main categories of firewalls covered in the section, and how do they differ in their physical form and placement?
* A host needs to communicate with another host on a different network. What is the role of its "gateway" in this process?

***

### The Open Systems Interconnection (OSI) model

* Briefly describe the primary function of the Network Layer (Layer 3) in the OSI model.
* List three key protocols that operates at the Application Layer (Layer 7) and state their purpose.
* Identify three addressing schemes used at Layers 2, 3, and 4 of the OSI model and state the purpose of each.

***

### Host to host communication in networking

* Briefly explain the difference in the ARP process when a host communicates with another host on its local network versus one on a foreign network.
  * Answer: For a host on the local network, the host sends an ARP request to resolve the destination host's IP address to the destination host's MAC address. For a host on a foreign network, the host sends an ARP request to resolve the default gateway's IP address to the default gateway's MAC address.
* What are the three key pieces of information a host must be configured with to communicate on an IP network?
  * Answer: 1) An IP address, 2) A subnet mask, and 3) A default gateway.
* After a packet arrives at its final destination host, what happens to the Layer 2 and Layer 3 headers?
  * Answer: The destination host discards the Layer 2 header (as its job for NIC-to-NIC delivery is done) and then retires the Layer 3 header (as its job for end-to-end delivery is done), leaving only the data for the application to process.
* Once a host has resolved the MAC address of its default gateway via ARP, how does this benefit future communications?
  * Answer: The MAC-to-IP mapping is stored in the host's ARP cache. This resolved MAC address can be reused for any subsequent packet destined for any foreign network, as the first hop for all such traffic is the same router. The host does not need to ARP for the gateway again until the cache entry expires.
* Where does a host store the IP-to-MAC address mappings it learns from ARP responses?
  * Answer: The host stores them in its ARP cache (also called an ARP table).

***

### Network protocols and their functions

* Point 1

***

### Typing www.google.com into a web browser

* Point 1

***

### Cisco IOS CLI and basic device security

* What is the primary functional difference between User EXEC mode and Privileged EXEC mode
  * Answer: User EXEC mode is for basic, read-only monitoring commands. Privileged EXEC mode provides full administrative access to all viewing, debugging, and device control commands (e.g., reload, copy).
* What is the single, most important CLI shortcut for getting help and how is it used?
  * Answer: The question mark `?`. It is used for context-sensitive help. Typing it at a prompt lists all available commands. Typing it after a partial command shows possible completions and arguments.
* Which command should always be used over `enable password` to secure access to privileged EXEC mode and why?
  * Answer: The `enable secret` command. It should always be used because it encrypts the password using a strong, irreversible MD5 hash, whereas the `enable password` stores it in plain text, which is a security risk.
* A colleague can see a password in plain text when they use the `show running-config` command. What single global configuration command can you use to prevent this for all such passwords?
  * Answer: `service password-encryption`
* What is the specific purpose of the `show startup-config` command?
  * Answer: To display the configuration file (`startup-config`) that is stored in NVRAM. This is the configuration that the device will load and use when it boots up or is reloaded.

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
* List the three main types of NAT mentioned in the text introduction.
* Briefly explain the main operational difference between dynamic NAT and PAT (Port Address Translation).
* What is the purpose of the `clear ip nat translation` command in the context of verifying a static NAT configuration?

***

### OSI model layers and security threats

* Identify two common network attack types associated with each OSI layer.
* Briefly describe how each identified attack type can compromise a network.
* Identify two key mitigation methods for each identified attack type.
* Sort the identified network attack types by their potential level of risk (consider attack likelihood and potential impact).
