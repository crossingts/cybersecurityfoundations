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

This process is called message signing. It provides authentication and non-repudiation, meaning Alice cannot deny sending the message. It also ensures the message was not altered, as any tampering would invalidate the signature. The core security properties provided by signing (non-repudiation, authentication, and integrity) are formally defined in industry standards such as the Internet Security Glossary (RFC 4949).

Digital signatures are used everywhere in modern digital life.

* Software Distribution: Operating system updates (Windows, macOS), app stores, and open-source packages are signed. Your computer verifies the signature before installing to ensure the software hasn't been tampered with and comes from the legitimate publisher.
* Secure Web Browsing (HTTPS): The TLS/SSL protocol uses digital certificates (which contain a signed public key) to authenticate websites to your browser. This prevents impersonation.
* Digital Documents: Legal documents, PDFs, and government e-filing systems use advanced electronic signatures (AES) based on this technology to provide non-repudiation.
* Blockchain and Cryptocurrencies: Transactions are authorized by digitally signing them with a private key. Your "crypto wallet" is essentially a collection of private keys.

### How message signing works (hashing + asymmetric encryption)

**1. Hashing the Message:** Alice generates a cryptographic hash (e.g., using SHA-256) of the message. A hash is a fixed-size fingerprint of the message. This ensures integrity—any change to the message would produce a different hash.

**2. "Encrypting" the Hash:** Alice encrypts the hash with her private key. Alice takes the hash and performs a private-key operation (not classic encryption, but mathematically similar). The result is a digital signature, which is tied to both the message and Alice’s private key. This step is referred to as "signing," but technically, it’s asymmetrically encrypting the hash (with Alice's private key).

**3. Why Hash Before Signing?** Signing the hash instead of the entire message is done for three primary reasons:

* Performance: Asymmetric crypto operations (RSA, ECC) are computationally slow. Hashing is extremely fast. It's much quicker to sign a fixed-length 256-bit SHA-256 hash than a multi-gigabyte file.
* Security: Some asymmetric algorithms have limits on the amount of data they can process in one operation. Hashing reduces any message to a fixed, manageable size.
* Compatibility: The signature is a single, predictable size (e.g., 256 bytes for a 2048-bit RSA key) regardless of the original message size. This makes it easy to transmit and store.

**4. Verification by Bob:** Bob uses Alice’s public key to "decrypt" the signature, revealing the original hash. Bob then independently hashes the received message. If the hashes match, the message is authentic (sender verified), unaltered (integrity preserved), and the sender cannot deny sending it (non-repudiation). Non-repudiation relies on the assumption that only the sender possesses their private key. If the private key is compromised, this property is weakened.

The combination of hashing and asymmetric cryptography for creating signatures is a classic cryptographic construct, detailed in foundational texts such as Schneier's (1996) Applied Cryptography book.

**The Trust Problem: How Bob Gets Alice's Key**

**How does Bob obtain Alice's public key, and how can he trust that it truly belongs to her and not an imposter?** What if an attacker, Mallory, intercepts the message and replaces Alice's public key with her own? Bob would then use Mallory's public key to verify a signature that Mallory created, falsely believing the message came from Alice.

This problem of trust and secure key distribution is solved by a **Public Key Infrastructure (PKI)**. A PKI is a framework of policies, roles, and technology that binds public keys to identities (e.g., a person or a website) through digital documents called **Certificates**. These certificates are issued and digitally signed by a trusted third party called a **Certificate Authority (CA)**.

In our example, Alice wouldn't just send her public key; she would send a certificate containing her public key and her identity, signed by a CA that Bob already trusts. Bob's software would first verify the CA's signature on the certificate to ensure it's valid and _then_ use the public key inside it to verify Alice's message signature. This chain of trust is the backbone of secure digital communication on the internet.

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

**Signing vs Encrypting**

It's a common misconception to say signing is "encrypting with a private key." While the mathematical operation might be similar, the cryptographic goals are fundamentally different. The goal of encryption for confidentiality is to transform data so only the holder of the private key can read it. Anyone can encrypt with the public key. By comparison, the goal of signing for authentication/integrity is to generate a verifiable proof (signature) that only the holder of the private key could have produced. Anyone can verify with the public key. Furthermore, proper signing algorithms (like RSA-PSS, ECDSA) use a different padding scheme and structure than encryption algorithms (like RSA-OAEP). Using a key for both encryption and signing can introduce vulnerabilities. Therefore, we say we "generate a signature" using the private key, not "encrypt."

### Key takeaways

* Signing uses hashing (for integrity) + asymmetric encryption (for authentication).&#x20;
* Signing is not pure encryption (but mathematically similar).
* Signing is not pure hashing (since it adds a private-key step for verification).
* Message signing provides the following three key security properties:
  * Non-repudiation – The sender cannot later deny having signed the message, as the signature is uniquely tied to their private key (assuming the private key was kept secure).
  * Authentication (sender verification) – The recipient can verify the identity of the sender by validating the signature using the sender's public key.
  * Message Integrity – The signature ensures that the message has not been altered in transit, as any modification would invalidate the signature.

### References

Internet Engineering Task Force (IETF). (2017). Internet Security Glossary, Version 2 (RFC 4949). https://www.rfc-editor.org/rfc/rfc4949

Schneier, B. (1996). Applied cryptography: protocols, algorithms, and source code in C (2nd ed.). John Wiley & Sons.
