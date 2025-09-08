---
description: >-
  This section looks at how hashing algorithms (e.g., SHA-256) and asymmetric
  keys can be used for message signing
---

# Message signing using asymmetric keys

## Learning objectives <a href="#learning-objectives" id="learning-objectives"></a>

* Understand why message signing can provide non-repudiation, authentication, and message integrity verification
* Develop a foundational understanding of how message signing is done using hashing and asymmetric encryption

This section looks at how a combination of hashing and asymmetric encryption can be used for message signing and the potential security benefits of message signing—non-repudiation, authentication, and message integrity verification.

## Topics covered in this section <a href="#topics-covered-in-this-section" id="topics-covered-in-this-section"></a>

* **Introduction to message signing**
* **How message signing works (hashing + asymmetric encryption)**

### Introduction to message signing

Alice wants to send a message to Bob. Alice wants Bob to know beyond a shadow of a doubt that it was her that sent the message. To do this, Alice signs the message with her private key. Bob can then verify the signature using Alice’s public key. If the verification succeeds, Bob knows the message was signed with Alice’s private key, confirming it came from her.

This process is called message signing. It provides authentication and non-repudiation, meaning Alice cannot deny sending the message. It also ensures the message was not altered, as any tampering would invalidate the signature.

### How message signing works (hashing + asymmetric encryption)

**1. Hashing the Message:** Alice generates a cryptographic hash (e.g., using SHA-256) of the message. A hash is a fixed-size fingerprint of the message. This ensures integrity—any change to the message would produce a different hash.

**2. "Encrypting" the Hash:** Alice encrypts the hash with her private key. Alice takes the hash and performs a private-key operation (not classic encryption, but mathematically similar). The result is a digital signature, which is tied to both the message and Alice’s private key. This step is referred to as "signing," but technically, it’s asymmetrically encrypting the hash (with Alice's private key).

**3. Verification by Bob:** Bob uses Alice’s public key to "decrypt" the signature, revealing the original hash. Bob then independently hashes the received message. If the hashes match, the message is authentic (sender verified), unaltered (integrity preserved), and the sender cannot deny sending it (non-repudiation).

#### Important Notes:

* Non-repudiation relies on the assumption that only the sender possesses their private key. If the private key is compromised, this property is weakened.
* Common algorithms used for signing include RSA-PSS, ECDSA, and EdDSA.

### Key takeaways

* Signing uses hashing (for integrity) + asymmetric encryption (for authentication).&#x20;
* Signing is not pure encryption (but mathematically similar).
* Signing is not pure hashing (since it adds a private-key step for verification).
* Message signing provides the following three key security properties:
  * Non-repudiation – The sender cannot later deny having signed the message, as the signature is uniquely tied to their private key (assuming the private key was kept secure).
  * Authentication (sender verification) – The recipient can verify the identity of the sender by validating the signature using the sender's public key.
  * Message Integrity – The signature ensures that the message has not been altered in transit, as any modification would invalidate the signature.

### References

[Ed Harmoush. (December 8, 2021). Using Asymmetric Keys. Practical Networking.](https://www.practicalnetworking.net/series/cryptography/using-asymmetric-keys/)
