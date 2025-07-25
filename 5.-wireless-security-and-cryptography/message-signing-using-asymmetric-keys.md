---
description: This section looks at how asymmetric keys can be used for message signing
---

# Message signing using asymmetric keys

### Message signing

Alice wants to send a message to Bob. Alice wants Bob to know beyond a shadow of a doubt that it was her that sent the message. To do this, Alice signs the message with her **private key**. Bob can then verify the signature using Alice’s **public key**. If the verification succeeds, Bob knows the message was signed with Alice’s private key, confirming it came from her.

This process, called **message signing**, provides **non-repudiation**, meaning Alice cannot deny sending the message. It also ensures the message was not altered, as any tampering would invalidate the signature.

#### **How Signing Works (Hashing + Asymmetric Encryption)**

1. **Hashing the Message**:
   * Alice generates a cryptographic hash (e.g., using SHA-256) of the message. A _hash_ is a fixed-size fingerprint of the message. This ensures _integrity_—any change to the message would produce a different hash.
2. **"Encrypting" the Hash**:

* Alice encrypts the hash with her private key.
* Alice takes the hash and performs a **private-key operation** (not classic encryption, but mathematically similar).
* The result is a **digital signature**, which is tied to both the message and Alice’s private key. This step is referred to as "signing," but technically, it’s asymmetrically encrypting the hash (with Alice's private key).

#### Verification by Bob:

1. Bob uses Alice’s _public key_ to "decrypt" the signature, revealing the original hash.
2. Bob independently hashes the received message.
3. If the hashes match, the message is authentic and untampered.

**In other words:**

Alice wants to sign a message to Bob. Alice runs her message through a hashing algorithm (e.g., SHA-256), and then encrypts the resulting digest with her own private key. Alice then sends the encrypted digest to Bob, along with the original message.

Bob then uses Alice’s public key to decrypt the digest, then he independently calculates the hash of the original message using the same hashing algorithm that Alice used to hash the message. Bob then compares the digests. If they match, Bob knows that Alice must have sent the original message (authenticity). Bob also knows that the message has not changed (message integrity).

#### **Key takeaways**

* Signing **uses hashing** (for integrity) + **asymmetric encryption** (for authenticity).
* Signing is **not pure encryption** (only the hash is processed).
* Signing is **not pure hashing** (since it adds a private-key step for verification).
* **Private key operation ≠ classic encryption**: It’s a mathematical proof, not secrecy.

### References

[Ed Harmoush. (December 8, 2021). Using Asymmetric Keys. Practical Networking.](https://www.practicalnetworking.net/series/cryptography/using-asymmetric-keys/)
