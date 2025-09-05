---
description: >-
  This section explores how hashing algorithms (e.g., SHA-256) can be used to
  ensure the integrity of messages exchanged between hosts
---

# Hashing algorithms and message integrity

## Learning objectives

* Develop a foundational understanding of how hashing algorithms function
* Know the key characteristics of an industry grade hashing algorithm&#x20;
* Develop a foundational understanding of how hashing can be used to ensure message integrity
* Develop a foundational understanding of how hashing can be used to authenticate someone

This section discusses [hashing algorithms and message integrity](https://builtin.com/cybersecurity/what-is-hashing). This section explains the key qualities (characteristics) of a hashing algorithm and how hashing algorithms can be used to ensure the integrity of messages exchanged between a client and a server.

## Topics covered in this section

* **Hashing algorithms**
* **How hashing and HMAC ensure message integrity and authentication**

### Hashing algorithms

A hashing algorithm is a mathematical function that takes an input (data) of arbitrary size and produces a fixed-size output, a representational sample of the original data called a hash value or hash. Hashing algorithms are used in a variety of applications, including data integrity, password hashing, file indexing, identifying duplicate files/data, and digital signatures.

A basic hashing algorithm can be converting letters to numbers (e.g., a = 1, b = 2, c = 3, etc.):

hello (message) –— hashing algorithm (8+5+12+12+15) → 52 (message digest)

The result of a hashing algorithm is called a message digest (or sometimes checksum or fingerprint).

If someone changed the h (in hello) to c:

cello (message) → 47 (message digest)

Comparing the two message digests shows the original message has changed.

But this hashing algorithm is terrible. If the original message was changed to celt, running the message through the hashing algorithm would produce the same hash value of 52.

Note — The message digest (52 for hello) is more technically a hash or checksum in this case, but calling it a digest is fine for illustration. See [Understanding hash, digest, checksum, and fingerprint](understanding-hash-digest-checksum-and-fingerprint.md).

#### Characteristics of industry grade hashing algorithms

A hashing algorithm must maintain four qualities before it is approved for industry usage:

1\. It is mathematically impossible to extract the original message from the digest. You should not be able to reverse engineer the hashing algorithm to know the original message by just inspecting the hash value. Hashing is a one-way function, meaning that it is computationally infeasible to reverse the hash function to find the original input. Hashing is sometimes referred to as one-way encryption – you can only encrypt the message but not decrypt it.

2\. A slight change to the original message causes a drastic change in the resulting digest. A minor modification to the original message should greatly alter the computed digest (the avalanche effect). An industry approved hashing algorithm is not simply one calculation. A hashing algorithm is a series of calculations done iteratively. As a result, a small change in the beginning creates an exponentially bigger change in the resulting digest.

3\. The result of the hashing algorithm is always the same length. The resulting digest cannot provide any hints or clues about the original message, including its length. A digest should not increase in size as the length of the message increases.

4\. It is infeasible to construct a message which generates a given digest. In our example, it would not be overly difficult to generate a list of words that can produce a digest of 52 (one of which might have been the original message). In a proper hashing algorithm, this should be infeasible.

There are many different hashing algorithms available, each with its own strengths and weaknesses. Hashing algorithms examples include MD5, SHA-1, and SHA-256.

**Common Hashing Algorithms in SSL/TLS (Showing Digest Lengths)**

| Algorithm                           | Use Case in SSL/TLS                                          |
| ----------------------------------- | ------------------------------------------------------------ |
| **SHA-256 (256 Bits)**              | Default for certificates (replacing SHA-1, which is broken). |
| **SHA-384 (384 Bits)**              | Used in higher-security contexts (e.g., banking).            |
| **SHA-3**                           | Emerging, but not yet widely adopted in TLS.                 |
| **MD5 (128 Bits)/SHA-1 (160 Bits)** | Deprecated due to collision vulnerabilities.                 |

**Security considerations:**

* Collision resistance: A hash function must make it nearly impossible for two different inputs to produce the same hash (SHA-256 is secure; MD5/SHA-1 are broken).
* A longer digest tends to be regarded as more secure.

### How hashing and HMAC ensure message integrity and authentication

When exchanging messages between a client and a server, hashing algorithms can help verify that the message was not altered in transit—a property known as message integrity. Here’s how it works:

**1. Basic Integrity Check Using Hashing**

* The sender calculates a hash digest of the original message (e.g., using SHA-256).
* The sender transmits both the message and the hash digest to the receiver.
* Upon receiving the message, the receiver independently recomputes the hash and compares it to the received digest.
* If they match, the message has not been altered or corrupted.

**Problem:** This method alone is vulnerable to active attacks. If a man-in-the-middle (MITM) intercepts the message, they could:

1. Modify the message.
2. Compute a new hash of the altered message.
3. Send the modified message + new hash to the receiver. Since the receiver only checks if the hashes match, they would falsely believe the message is authentic.

**2. Strengthening Security with a Secret Key (HMAC)**

To prevent tampering, the sender and receiver share a secret key. Instead of just hashing the message, the sender computes a Message Authentication Code (MAC) over the message using this key, which ensures integrity (the message was not altered) and authenticity (the sender possesses the secret key). The most widely used MAC is HMAC (Hash-Based Message Authentication Code), which securely combines the key and message.

**How HMAC Works:**

1. **Sender’s Side:**
   * The sender inputs the message + secret key into the HMAC algorithm (e.g., HMAC-SHA256).
   * The output is a fixed-size MAC (tag).
   * The sender transmits the original message + MAC.
2. **Receiver’s Side:**
   * The receiver recomputes the MAC using the received message + their copy of the secret key.
   * If the computed MAC matches the received MAC, the message is:
     * Untampered (message integrity preserved).
     * Authentic (sent by someone with the secret key).

**3. Alternatives to HMAC**

* Digital Signatures (e.g., RSA, ECDSA) can also ensure integrity and authenticity but use asymmetric cryptography (public/private keys) instead of a shared secret.
* Encryption + MAC (e.g., AES-GCM) can provide integrity + confidentiality, but HMAC is often used when encryption is not required.

Hashing Demonstration with Linux: [Run a hashing algorithm (md5sum or sha1sum) on a string of text in a Linux terminal.](https://www.practicalnetworking.net/series/cryptography/hashing-algorithm/)

### Key takeaways

* An industry grade hashing algorithm has four fundamental characteristics.
* A hashing algorithm performs a series of calculations iteratively.
* Hashing alone cannot detect malicious tampering during message exchange.
* HMAC (key + hashing) ensures integrity and authenticity against active attackers.
* HMAC is preferred over simple keyed hashes due to stronger security.
* For even stronger guarantees, digital signatures or encryption + MAC can be used.

### References

[Ed Harmoush. (December 15, 2021). Hashing Algorithm. Practical Networking.](https://www.practicalnetworking.net/series/cryptography/hashing-algorithm/)

[Ed Harmoush. (December 8, 2021). Message Integrity. Practical Networking.](https://www.practicalnetworking.net/series/cryptography/message-integrity/)
