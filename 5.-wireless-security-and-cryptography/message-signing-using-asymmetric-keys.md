---
description: This section looks at how asymmetric keys can be used for message signing
---

# Message signing using asymmetric keys

This section discusses how asymmetric keys can be used to perform message signing. We look at how the asymmetric key pair can be used to perform real world signatures.&#x20;

* **Message signing**
* **Real world signatures**

### Message signing

Alice wants to send a message to Bob. Alice wants Bob to know beyond a shadow of a doubt that it was her that sent the message.

To do this, Alice signs the message with her **private key**. Bob can then verify the signature using Alice’s **public key**. If the verification succeeds, Bob knows the message was signed with Alice’s private key—confirming it came from her.

This process, called **message signing**, provides **non-repudiation**, meaning Alice cannot deny sending the message. It also ensures the message was not altered, as any tampering would invalidate the signature.

#### **How Signing Works (Hashing + Asymmetric Encryption)**

1. **Hashing the Message**:
   * Alice generates a cryptographic hash (e.g., using SHA-256) of the message. A _hash_ is a fixed-size fingerprint of the message. This ensures _integrity_—any change to the message would produce a different hash.
2. **"Encrypting" the Hash with Her Private Key**:

* Alice _does not encrypt the whole message_—just the hash.
* Alice takes the hash and performs a **private-key operation** (not classic encryption, but mathematically similar).
* In RSA, this is technically `Signature = Hash^d mod N` (where `d` is her private key).
* For ECC (Elliptic Curve), it’s a more complex signing algorithm (ECDSA).
* This step is sometimes called "signing," but technically, it’s _asymmetrically encrypting the hash (with Alice's private key)_.

1. **Result = Digital Signature**:
   * The output is the **signature**, which is tied to both the message _and_ Alice’s private key.

#### Verification by Bob:

1. Bob uses Alice’s _public key_ to "decrypt" the signature, revealing the original hash.
2. Bob independently hashes the received message.
3. If the hashes match, the message is authentic and untampered.

#### Why "Encrypting" is a Misleading Term:

* Technically, this step isn’t _encryption_ (which implies secrecy).
* It’s a **one-way transformation** using the private key to prove ownership.
* Only the matching public key can "reverse" it (during verification).

### Real world signatures

A hashing algorithm can be used to reduce a message of variable length to a constant, more manageable representational value.

Alice wants to sign a message to Bob. Alice runs her message through a hashing algorithm, and then encrypts the resulting digest with her own private key. Alice then sends the encrypted digest to Bob, along with the original message.

Bob then uses Alice’s public key to decrypt the digest, then he independently calculates the hash of the original message using the same hashing algorithm that Alice used to encrypt the message. Bob then compares the digests.

If they match, Bob knows that Alice must have sent the original message (for authenticity). Bob also knows that the message has not changed (message integrity was preserved).

#### **Key Takeaway**

* Signing **uses hashing** (for integrity) + **asymmetric encryption** (for authenticity).
* Signing is **not pure encryption** (only the hash is processed).
* Signing is **not pure hashing** (since it adds a private-key step for verification).
* **Private key operation ≠ classic encryption**: It’s a mathematical proof, not secrecy.

### References

[Ed Harmoush. (December 8, 2021). Using Asymmetric Keys. Practical Networking.](https://www.practicalnetworking.net/series/cryptography/using-asymmetric-keys/)
