---
description: >-
  This section discusses replay attacks, and anti-replay methods (sequence
  numbers windowing, cryptographic hashes, and rotating the secret keys)
---

# Replay attacks and anti-replay methods

## Learning objectives

* Understand what are replay attacks and what security risks they pose
* Become familiar with major anti-replay methods
* Develop a basic understanding of how replay attacks can threaten SSL/TLS security
* Develop a basic understanding of how TLS 1.3 mitigates most SSL/TLS security risks

This section discusses replay attacks and anti-replay methods. Five anti-replay methods that are not mutually exclusive are covered, including using sequence numbers windowing, using cryptographic hashes, and rotating the secret keys.

## Topics covered in this section

* **Replay attacks**
* **Anti-replay methods**
* **Anti-replay methods and SSL/TLS security**

### Replay attacks

A replay attack is a type of cyberattack in which an attacker intercepts and retransmits valid data transmissions to impersonate legitimate users, gain unauthorized access, or disrupt services. For example, an attacker could capture a financial transaction approval and replay it to fraudulently withdraw funds multiple times.

A replay attack is an umbrella term for various techniques involving the use of previous transmissions or transactions to bypass authentication and steal data or disrupt computer systems. There are several types of replay attacks, the most common ones being network, wireless, session, and HTTP.

Replay attacks involve three basic phases. First, the attacker waits for data transmission to begin. Next, the attackers sniffs the communication between a client and server to extract transmission packets. Third, the attacker injects the extracted transmission packets into the communication channel, thus replaying the transmission or repeating the transaction.

Suppose we have some packets we want to securely transmit over the wire. We start sending the packets to their destination over the wire. The packets use a 16 bit sequence number field, allowing for sequence number range of 1 – 65536.

A malicious hacker manages to capture some packets from our transmission with the sequence numbers 10,000-10,099. The malicious hacker can wait for the sequence number to loop past 65536 and restart at 0, count 9,999 packets, and then inject the replayed packets with the sequence numbers 10,000-10,099. Since the replayed packets would have arrived at the right time, they would have been accepted by the receiver.

Modern networking protocols use larger sequence numbers (e.g., IPSec uses 32-bit) to reduce rollover risk (sequence number looping vulnerability).

### Anti-replay methods

Anti-replay methods are essential for maintaining data integrity and for preventing attackers from capturing and retransmitting legitimate data packets to gain unauthorized access or disrupt communications. Here are the common anti-replay methods:

**1. Sequence numbers windowing:**

Each packet that is sent over a secure connection is assigned a unique sequence number by the sender. The receiver maintains a window of expected sequence numbers and discards any packets with numbers outside that window or those already received.

The size of the anti-replay window is the number of packets that are kept track of by the receiving end of the connection. The larger the window size, the more packets that can be protected from replay attacks. However, a larger window size also means that more memory is required to keep track of the sequence numbers. The default anti-replay window size is 64 packets. This is a good balance between security and performance. For more demanding applications, the window size can be increased.

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

**5. Rotating the secret keys**:

Keys should be rotated before sequence number exhaustion to prevent replay attacks during the reset.

Rotating the secret keys used in the hashing algorithms is a way to prevent replayed packets. When the secret keys are rotated, the hash values of the packets will also change. This is because the secret keys are used to encrypt the data before it is hashed. If an attacker tries to replay a packet that was encrypted with the expired secret keys, the hash value of the packet will not match the hash value that is expected by the receiver.

This will allow the receiver to detect the replay attack and drop the packet. If the secret keys are rotated when the sequence number resets to zero, replayed packets injected after the reset are identified by their sequence numbers (these replayed packets, with their specific sequence numbers, have an old/wrong hash value than legitimate packets).

**Common anti-replay applications**

Examples of how anti-replay measures can be used to protect against replay attacks include:

* Protecting a financial transaction from an attacker who is trying to replay a previous transaction.
* Protecting a VPN connection from an attacker who is trying to impersonate a valid user.
* Protecting a file transfer from an attacker who is trying to steal a file.

### Anti-replay methods and SSL/TLS security

Anti-replay methods are a fundamental part of how SSL/TLS secures data. SSL/TLS relies on cryptographic tools to ensure **confidentiality, integrity, and authenticity** of data in transit. Replay attacks pose a threat to these guarantees, so SSL/TLS incorporates anti-replay mechanisms as part of its security design.&#x20;

#### **How Replay Attacks Threaten SSL/TLS Security Guarantees and Modern Defenses**

SSL/TLS provides three core security guarantees:

1. **Confidentiality** – Data is encrypted and cannot be read by eavesdroppers.
2. **Integrity** – Data cannot be altered in transit without detection.
3. **Authenticity** – Parties can verify each other’s identity.

Replay attacks undermine these guarantees by allowing an attacker to reuse previously captured legitimate traffic, potentially bypassing security controls. Below is a breakdown of how replay attacks threaten each guarantee and how modern TLS (especially TLS 1.3) mitigates them.

#### **1. Threat to Confidentiality (Encryption Alone Isn’t Enough)**

Even if traffic is encrypted, replaying an old session could allow an attacker to reuse an old session key (if session resumption is insecure) or to decrypt future traffic if key material is compromised. A session in TLS refers to a temporary secure connection between a client and server, established via the TLS handshake. It includes session keys (used for encryption), and session tickets/resumption IDs (for faster reconnection). Replaying a session means reusing these components maliciously to bypass authentication or decrypt data.

**Example:**

* In TLS 1.2, if an attacker captures a session ticket and replays it, they might resume a session without a full handshake, gaining access to encrypted data.

**Mitigation:**

✔ **Ephemeral Key Exchanges (ECDHE, DHE)**

* Ensures forward secrecy—even if a session key is compromised later, past sessions remain secure.
* Prevents replay attacks from decrypting old traffic.

✔ **One-Time-Use Session Tickets (TLS 1.3)**

* Unlike TLS 1.2 (where session tickets could be reused), TLS 1.3 tickets are single-use.
* Forces a full handshake if an attacker tries to replay a ticket.

✔ **TLS 1.3’s One-RTT Handshake**

* Reduces the window for replay attacks by minimizing handshake steps.

#### **2. Threat to Integrity (Data Can Be Replayed Without Modification)**

TLS ensures that data is not modified in transit (via MACs/AEAD ciphers), but it doesn’t inherently prevent the same data from being retransmitted. A replayed request (e.g., a bank transaction) could execute the same action multiple times.

**Example:**

* An attacker intercepts an HTTPS `POST /transfer?amount=1000` request and replays it, causing duplicate transfers.

**Mitigation:**

✔ **Strict Key Rotation (TLS 1.3)**

* Each session derives fresh keys, preventing reuse of past encryption material.

✔ **Application-Layer Defenses (Required for Full Protection)**

* Idempotency keys (unique identifiers for transactions).
* Timestamps/nonces to detect stale requests.

#### **3. Threat to Authenticity (Impersonation via Replayed Sessions)**

If an attacker replays authentication tokens or handshake messages, they can impersonate a legitimate user or server.

**Examples:**

* **Session Hijacking via Cookie Replay:** An attacker steals a session cookie and replays it in a new request.
* **TLS Handshake Replay (Pre-TLS 1.3):** An attacker replays a `ClientHello` or session ticket to resume an old session.

**Mitigation:**

✔ **No Replayable Messages in TLS 1.3**

* The `ClientHello` and `ServerHello` include fresh randomness (nonces), making each handshake unique.
* Prevents replay of handshake messages.

✔ **Strict Session Resumption Rules**

* TLS 1.3 enforces one-time PSKs (Pre-Shared Keys) for session resumption.

#### **4. TLS 1.3 Anti-Replay Mechanisms**

| **Defense**                                    | **How It Counters Replay Attacks**                      |
| ---------------------------------------------- | ------------------------------------------------------- |
| **Ephemeral Key Exchange (ECDHE/DHE)**         | Ensures forward secrecy; keys can’t be reused.          |
| **One-Time-Use Session Tickets**               | Prevents session ticket replay.                         |
| **One-RTT Handshake**                          | Reduces exposure window for attacks.                    |
| **Strict Key Derivation**                      | Fresh keys per session, no reuse.                       |
| **Nonces in Handshake (Client/Server Random)** | Ensures uniqueness of each handshake.                   |
| **No Static RSA Key Exchange**                 | Eliminates risk of key compromise replay.               |
| **Mandatory Forward Secrecy**                  | Prevents decryption of past sessions even if keys leak. |

**Conclusion: TLS 1.3 Closes Most Replay Attack Vectors**

While TLS 1.2 had vulnerabilities (reusable session tickets, static RSA key exchange), TLS 1.3 introduces robust anti-replay protections:\
✔ One-time session tickets\
✔ Ephemeral keys for forward secrecy\
✔ Non-replayable handshake messages\
✔ Strict key rotation

However, application-layer defenses (idempotency keys, CSRF tokens) are still needed for full protection against duplicate transactions.

**Common protocols and anti-replay methods**

* IPSec: Implements anti-replay protection in its ESP (Encapsulating Security Payload) protocol. IPSec anti-replay uses sequence numbers and a sliding window to prevent replay attacks.
* TLS/SSL: Uses sequence numbers and timestamps for anti-replay protection.
* Secure Shell (SSH): Uses sequence numbers and timestamps for anti-replay protection.
* WireGuard: Employs a cryptographic nonce system for anti-replay protection.

### Key takeaways

* Major anti-replay methods include sequence numbers, timestamps, nonces, cryptographic hashes, windowing, and rotating secret keys.
* Replay attacks threaten SSL/TLS security guarantees.
* TLS 1.3 introduces robust anti-replay protections, including one-time session tickets and secret key rotation.

### References

[Ed Harmoush. (December 8, 2021). Anti-Replay. Practical Networking.](https://www.practicalnetworking.net/series/cryptography/anti-replay/)
