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

This section discusses [hashing algorithms and message integrity](https://builtin.com/cybersecurity/what-is-hashing). This section begins by explaining hashing's mechanism of action through a simplified example. It then explains the key characteristics (qualities) of an industry-grade hashing algorithm. It then explores how basic hashing can be used to ensure the integrity of messages exchanged between a client and a server. Finally, the lesson introduces the concept of message authentication, demonstrating how a shared secret key is combined with a hash function to create a Hash-based Message Authentication Code (HMAC). You will learn how HMAC provides a robust defense against tampering by ensuring both data integrity and authenticity.

## Topics covered in this section

* **Hashing algorithms**
* **How hashing and HMAC ensure message integrity and authentication**

### Hashing algorithms

#### A simplified explanation of hashing

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

Industry grade hashing algorithms have five key characteristics or properties. Pre-image resistance, second pre-image resistance, and collision resistance are core security properties. Fixed-length output and the Avalanche Effect are two essential features that enable those properties.

**1. Pre-image Resistance (One-Wayness)**

* **Definition:** Given a hash value `h`, it is computationally infeasible to find _any_ input `m` such that `hash(m) = h`. Hashing is a **one-way function**, meaning that it is computationally infeasible to reverse the hash function to know the original input.&#x20;
* **Simple Analogy:** If you are given a fingerprint, you cannot reconstruct the person it came from.
* **Why it matters:** This ensures an attacker cannot reverse-engineer the original data/message from its digest.

**2. Second Pre-image Resistance**

* **Definition:** Given a specific input `m1`, it is computationally infeasible to find a _different_ input `m2` (`m2 ≠ m1`) such that `hash(m1) = hash(m2)`.
* **Simple Analogy:** If you have a specific document and its fingerprint, you cannot create a _different_, fraudulent document that has the _exact same fingerprint_.
* **Why it matters:** This protects against forgery. An attacker cannot substitute a malicious message for a legitimate one while keeping the same hash value.

**3. Collision Resistance**

* **Definition:** It is computationally infeasible to find _any two distinct inputs_ `m1` and `m2` (where `m1 ≠ m2`) such that `hash(m1) = hash(m2)`. A hash function must make it nearly impossible for two different inputs to produce the same hash (SHA-256 is secure; MD5/SHA-1 are broken).
* **Simple Analogy:** You cannot find any two different people in the world who have an identical fingerprint.
* **Why it matters:** This is the hardest property to achieve and is crucial for digital signatures and commitments. If collisions are easy to find, an attacker can create two different documents with the same hash, sign the benign one, and claim the signature applies to the malicious one.

**4. Fixed-Length Output (Not a "security property" but a fundamental feature)**

* **Definition:** The hash function always produces an output (digest) of a fixed, predefined length, regardless of the size of the input message. The resulting digest cannot provide any hints or clues about the original message, including its length. A digest should not increase in size as the length of the message increases.
* **Why it matters:** This provides efficiency and predictability in protocols. It also prevents leakage of information about the input size.

**5. The Avalanche Effect (A critical design mechanism)**

* **Definition:** A small change to the input (e.g., flipping a single bit) produces a drastic change in the output, such that the new hash appears uncorrelated to the old hash. A hashing algorithm is a series of calculations done iteratively. As a result, a small change in the beginning creates an exponentially bigger change in the resulting digest.
* **Why it matters:** This is not a standalone security property but the _mechanism_ that makes the three properties above possible. It ensures the hash function's output is unpredictable and random-looking.

**The Three Core Security Properties of Cryptographic Hash Functions (Hashing Algorithms)**

| Property                        | The Challenge For an Attacker                                                           |
| ------------------------------- | --------------------------------------------------------------------------------------- |
| **Pre-image Resistance**        | "Here's a hash `h`. Find me _any_ input that creates it."                               |
| **Second Pre-image Resistance** | "Here's a specific message `m1`. Find me a _different_ message that has the same hash." |
| **Collision Resistance**        | "Find me _any two different messages_ that have the same hash."                         |

An industry-grade algorithm (like SHA-256) is designed to make all three of these attacks computationally infeasible.

#### Common hashing algorithms in SSL/TLS

There are many different hashing algorithms available, such as MD5, SHA-1, and SHA-256, each with its own strengths and weaknesses. A longer digest tends to be regarded as more secure.

**Common Hashing Algorithms in SSL/TLS (Showing Digest Lengths)**

| Algorithm                           | Use Case in SSL/TLS                                          |
| ----------------------------------- | ------------------------------------------------------------ |
| **SHA-256 (256 Bits)**              | Default for certificates (replacing SHA-1, which is broken). |
| **SHA-384 (384 Bits)**              | Used in higher-security contexts (e.g., banking).            |
| **SHA-3**                           | Emerging, but not yet widely adopted in TLS.                 |
| **MD5 (128 Bits)/SHA-1 (160 Bits)** | Deprecated due to collision vulnerabilities.                 |

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

To prevent tampering, the sender and receiver share a secret key. Instead of just hashing the message, the sender computes a Message Authentication Code (MAC) over the (whole) message using this key, which ensures integrity (the message was not altered) and authenticity (the sender possesses the secret key). The most widely used MAC is HMAC (Hash-Based Message Authentication Code), which securely combines the key and message.

While the first idea for a MAC might be to just put the key and message together and hash them (a simple keyed hash), this turns out to be vulnerable to specific attacks. HMAC securely combines the key and message in a method much more secure than a simple keyed hash, which is susceptible to length extension attacks.

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

* Digital signatures (such as ones based on the RSA or ECDSA algorithms) can also ensure integrity and authenticity but use asymmetric cryptography (public/private keys) instead of a shared secret.
* Encryption + MAC (e.g., AES-GCM) can provide integrity + confidentiality, but HMAC is often used when encryption is not required.

Hashing Demonstration with Linux: [Run a hashing algorithm (md5sum or sha1sum) on a string of text in a Linux terminal.](https://www.practicalnetworking.net/series/cryptography/hashing-algorithm/)

### Key takeaways

* An industry grade hashing algorithm has **four** fundamental characteristics.
* A hashing algorithm performs a series of calculations iteratively.
* Hashing alone cannot detect malicious tampering during message exchange.
* HMAC (key + hashing) ensures integrity and authenticity against active attackers.
* HMAC is preferred over simple keyed hashes due to stronger security.
* For even stronger guarantees, digital signatures or encryption + MAC can be used.

### References

[Ed Harmoush. (December 15, 2021). Hashing Algorithm. Practical Networking.](https://www.practicalnetworking.net/series/cryptography/hashing-algorithm/)

[Ed Harmoush. (December 8, 2021). Message Integrity. Practical Networking.](https://www.practicalnetworking.net/series/cryptography/message-integrity/)

Kaufman, C., Perlman, R., & Speciner, M. (2002). Network security: Private communication in a public world (2nd ed.). Prentice Hall.

Paar, C., & Pelzl, J. (2010). Understanding cryptography: A textbook for students and practitioners. Springer.

Stallings, W. (2024). Cryptography and network security: Principles and practice (9th ed.). Pearson.
