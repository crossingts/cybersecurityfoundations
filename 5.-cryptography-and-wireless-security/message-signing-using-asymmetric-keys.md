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

**3. Verification by Bob:** Bob uses Alice’s public key to "decrypt" the signature, revealing the original hash. Bob then independently hashes the received message. If the hashes match, the message is authentic (sender verified), unaltered (integrity preserved), and the sender cannot deny sending it (non-repudiation). Non-repudiation relies on the assumption that only the sender possesses their private key. If the private key is compromised, this property is weakened.

**Summary of Common Digital Signature Algorithms**

The following table outlines key algorithms used for digital signatures, their relative security, and status.

| **Algorithm**                                                               | **Security Level & Key Size (for \~128-bit security)** | **Strengths**                                                                                                                                                                                                                            | **Weaknesses/Considerations**                                                                                                                                                                      | **Status**                         |
| --------------------------------------------------------------------------- | ------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------- |
| **RSA-PSS (RSA Probabilistic Signature Scheme)**                            | 3072-bit key                                           | <p>• Widespread support &#x26; understanding.<br>• Proven security over decades.<br>• Standardized and recommended (PSS is modern and secure).</p>                                                                                       | <p>• Slower than ECC.<br>• Larger key sizes lead to larger signatures.<br>• Older PKCS#1 v1.5 padding (for signing) is vulnerable if implemented incorrectly.</p>                                  | **Current Standard**               |
| **ECDSA (Elliptic Curve Digital Signature Algorithm)**                      | 256-bit key (curve secp256r1 / secp256k1)              | <p>• Much faster and more efficient than RSA.<br>• Significantly smaller key sizes and signatures.</p>                                                                                                                                   | <p>• Security relies on trustworthy random number generation; a repeated random value can reveal the private key.<br>• More complex parameter selection (choosing a secure curve is critical).</p> | **Current Standard**               |
| **EdDSA (Edwards-curve Digital Signature Algorithm)**                       | 256-bit key (Ed25519 curve)                            | <p>• High performance and security.<br>• <strong>Deterministic:</strong> Does not rely on a random number generator, eliminating a class of vulnerabilities.<br>• Simple, constant-time implementation resists side-channel attacks.</p> | <p>• Relatively newer than RSA and ECDSA (though widely considered secure).<br>• Support might not be as universal in all legacy systems.</p>                                                      | **Modern Recommended Standard**    |
| **DSA (Digital Signature Algorithm)**                                       | 2048-bit key, 224-bit subgroup                         | • The original standard upon which ECDSA is based.                                                                                                                                                                                       | <p>• Requires complex parameter validation.<br>• Slower and less efficient than modern alternatives.<br>• Key sizes must be large to be secure, negating any efficiency.</p>                       | **Deprecated / Legacy**            |
| **RSA-PKCS#1 v1.5 (RSA Public-Key Cryptography Standards #1, version 1.5)** | 3072-bit key                                           | • Extreme historical prevalence.                                                                                                                                                                                                         | • The padding scheme has known theoretical attacks and requires very careful implementation to be secure.                                                                                          | **Legacy (Avoid for new designs)** |

**Note on Security:** "Security level" is a measure of the computational effort required to break the algorithm. A 128-bit security level means it would take roughly 2^128 operations to break it, which is considered computationally infeasible with foreseeable technology. Matching key sizes across different algorithms to achieve the same security level is crucial.

**Which algorithm should you choose?**

* For new projects, **EdDSA** (specifically the Ed25519 variant) is often the best choice due to its speed, security properties, and simplicity.
* **ECDSA** is a very strong and widely supported standard, essential for compatibility in many systems (e.g., blockchain, TLS certificates).
* **RSA-PSS** remains a robust and mandatory-to-support algorithm for interoperability. It is a secure modern evolution of RSA.
* **DSA** and **RSA with PKCS#1 v1.5 padding** should be considered legacy and avoided in new implementations. They are primarily encountered when maintaining older systems.

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
