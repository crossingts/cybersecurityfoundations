---
description: >-
  This section discusses replay attacks, and anti-replay methods (sequence
  numbers, cryptographic hashes, and rotating the secret keys)
---

# Replay attacks and anti-replay methods

This section discusses [replay attacks and anti-replay methods](https://www.baeldung.com/cs/replay-attacks). Six anti-replay methods that are not mutually exclusive are covered, including using sequence numbers, using cryptographic hashes, and rotating the secret keys.

* **Replay attacks**
* **Anti-replay methods**

### Replay attacks

A replay attack is a type of cyberattack in which an attacker intercepts and retransmits valid data transmissions to impersonate legitimate users, disrupt services, or gain unauthorized access. For example, an attacker could capture a financial transaction approval and replay it to fraudulently withdraw funds multiple times. These attacks pose a critical threat to network security, compromising systems like online banking, authentication protocols, and encrypted communications (e.g., VPNs, TLS, and SSH). Without proper protections—such as sequence numbers, cryptographic hashes, and key rotation—attackers could hijack sessions, bypass authentication, or replay old transactions, leading to financial losses, data breaches, and system compromises. Anti-replay methods are therefore essential for maintaining data integrity and preventing unauthorized retransmissions.

Suppose we have some packets we want to securely transmit over the wire. We start sending the packets to their destination over the wire. The packets use a 16 bit sequence number field, allowing for sequence number range of 1 – 65536.

A malicious hacker manages to capture some packets from our transmission with the sequence numbers 10,000-10,099. The malicious hacker can wait for the sequence number to loop past 65536 and restart at 0, count 9,999 packets, and then inject the replayed packets with the sequence numbers 10,000-10,099. Since the replayed packets would have arrived at the right time, they would have been accepted by the receiver.

Sequence number looping vulnerability: Modern protocols (like IPSec and TLS) use larger sequence numbers (e.g., IPSec uses 32-bit), reducing rollover risk.

### Anti-replay methods

Anti-replay methods are techniques used to prevent attackers from capturing and retransmitting legitimate data packets to gain unauthorized access or disrupt communications. Here are the common anti-replay methods:

**1. Sequence numbers:**

Each packet that is sent over a secure connection is assigned a unique sequence number by the sender. The receiver maintains a window of expected sequence numbers and discards any packets with numbers outside that window or those already received.

The unique sequence number typically starts at 1, and increases with every packet sent, uniquely identifying one packet from the prior one. The receiving end of the connection keeps track of the sequence numbers of the packets that it receives.

If a packet with a sequence number that has already been received is received, then the anti-replay mechanism will drop the packet. This prevents the attacker from retransmitting a packet that has already been sent and received.

<figure><img src="https://professionaludev.wordpress.com/wp-content/uploads/2023/12/anti-replay-attacks.webp?w=1024" alt="anti-replay-attacks" height="252" width="1024"><figcaption><p>Image courtesy of Practical Networking (PracNet)</p></figcaption></figure>

The packet with sequence number 3 is a replayed packet. The receiver can detect this because they have already received a packet with sequence number 3, and was expecting 5 next.

The sequence number is a finite field, meaning, it has a predefined range based on the number of bits allocated in the data packet. For example, if the data packet only allows a 16 bit field for the sequence number, you would have a total range of 1 – 65536. The maximum sequence number imposes a limit on the number of packets that can be sent. If exceeded, it can result in a looped sequence number vulnerability when the sequence number rolls back to zero.

**2. Timestamps:**

The sender includes a timestamp in each packet, indicating the time of transmission. The receiver compares the timestamp with its own clock and rejects packets with timestamps older than a certain threshold.

**3. Nonces:**

The sender includes a random number (nonce) in each packet. The receiver keeps track of received nonces and discards any packets with duplicate nonces.

**4. Cryptographic hashes:**

Cryptographic hashes are typically Message Authentication Codes (MACs) or HMACs, ensuring both integrity and authenticity.

The sender includes a cryptographic hash of the packet’s contents (message authentication code or MAC). The receiver verifies the hash to ensure the packet has not been modified in transit.

The sequence number, along with the data, can be protected by a hashing algorithm to prevent a malicious user from tampering with the numbers in order to send a replayed packet. The message, the secret key, and the sequence number together are run through a hashing algorithm. In this way, any illicit modification of any of these fields will be detected.

**5. Windowing:**

The receiver only accepts packets within a certain window of sequence numbers, discarding those outside the window or already received.

The size of the anti-replay window is the number of packets that are kept track of by the receiving end of the connection. The larger the window size, the more packets that can be protected from replay attacks. However, a larger window size also means that more memory is required to keep track of the sequence numbers. The default anti-replay window size is 64 packets. This is a good balance between security and performance. For more demanding applications, the window size can be increased.

**6. Rotating the secret keys**:

Keys should be rotated before sequence number exhaustion to prevent replay attacks during the reset.

Rotating the secret keys used in the hashing algorithms is a way to prevent replayed packets. When the secret keys are rotated, the hash values of the packets will also change. This is because the secret keys are used to encrypt the data before it is hashed. If an attacker tries to replay a packet that was encrypted with the expired secret keys, the hash value of the packet will not match the hash value that is expected by the receiver.

This will allow the receiver to detect the replay attack and drop the packet. If the secret keys are rotated when the sequence number resets to zero, replayed packets injected after the reset are identified by their sequence numbers (these replayed packets, with their specific sequence numbers, have an old/wrong hash value than legitimate packets).

**Common anti-replay applications**

Here are some examples of how anti-replay can be used to protect against replay attacks:

* To protect a financial transaction from an attacker who is trying to replay a previous transaction.
* To protect a VPN connection from an attacker who is trying to impersonate a valid user.
* To protect a file transfer from an attacker who is trying to steal a file.

**Common protocols and anti-replay methods**

* IPSec: Implements anti-replay protection in its ESP (Encapsulating Security Payload) protocol. IPSec anti-replay uses sequence numbers and a sliding window to prevent replay attacks.
* TLS/SSL: Uses sequence numbers and timestamps for anti-replay protection.
* Secure Shell (SSH): Uses sequence numbers and timestamps for anti-replay protection.
* WireGuard: Employs a cryptographic nonce system for anti-replay protection.

### References

[Ed Harmoush. (December 8, 2021). Anti-Replay. Practical Networking.](https://www.practicalnetworking.net/series/cryptography/anti-replay/)
