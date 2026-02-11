---
description: >-
  This chapter covered how SSL/TLS uses cryptographic tools to secure data over
  the Internet and how the IEEE 802.11 wireless standard enforces security
  through authentication, encryption, and integrity
---

# Cryptography and wireless security

## Chapter 5: Cryptography and wireless security <a href="#chapter-5-wireless-security-and-cryptography" id="chapter-5-wireless-security-and-cryptography"></a>

Chapter 5 explored the critical security mechanisms that protect data in transit, focusing on two essential areas: cryptography for online communications and security for wireless networks. It detailed how cryptographic tools—symmetric encryption (AES), asymmetric encryption (RSA), and hashing (SHA-256)—are combined within the SSL/TLS protocol to provide confidentiality, integrity, and authentication, explaining processes like the TLS handshake and the Diffie-Hellman key exchange. The chapter then applied these principles of authentication and encryption to the wireless domain, analyzing how the IEEE 802.11 standard forms a security framework and comparing the evolution of wireless security protocols (WPA, WPA2, WPA3) in safeguarding network access and data privacy.

**The first section titled Hashing Algorithms and Message Integrity** established cryptographic hashing as the foundation for ensuring message integrity. An industry-grade hashing algorithm, such as SHA-256, is defined by five key characteristics: it must be a one-way function with pre-image resistance; possess second pre-image resistance to prevent forgery; maintain collision resistance to thwart the creation of two different inputs with the same output; produce a fixed-length output regardless of input size; and exhibit the avalanche effect, where a minor change to the input creates a drastically different, unpredictable hash. These properties collectively ensure that a hash digest acts as a unique, tamper-evident fingerprint for any piece of data.

While hashing alone can verify that a message was not accidentally corrupted, it is vulnerable to malicious man-in-the-middle (MITM) attacks, where an attacker can alter both the message and its accompanying hash. To defend against active tampering and verify the sender's authenticity, a shared secret key is introduced via HMAC (Hash-based Message Authentication Code). HMAC securely combines the secret key with the message before hashing, generating a MAC (Message Authentication Code). The receiver, who holds the same key, can recompute the HMAC; a match confirms both the message's integrity and that it originated from a party possessing the secret key. For scenarios without a shared secret, digital signatures using asymmetric cryptography provide a similar guarantee of integrity and authenticity.

**The section Cryptographic Encryption and Confidentiality** explained the two fundamental cryptographic systems used to ensure data confidentiality: symmetric and asymmetric encryption. Symmetric encryption, exemplified by algorithms like AES-128, AES-192, and AES-256, uses a single, shared secret key for both encryption and decryption. Its mathematical operations are computationally efficient, making it the preferred choice for encrypting bulk data, though it necessitates a secure method to distribute the secret key to all communicating parties. Asymmetric encryption, using algorithms such as RSA and ECC, employs a mathematically linked pair of keys: a public key for encryption and a private key for decryption. This design eliminates the key distribution problem, as the public key can be freely shared, allowing anyone to encrypt data that only the holder of the corresponding private key can decrypt.

To leverage the strengths of both systems, hybrid encryption can be employed as a practical solution. This approach uses asymmetric encryption to securely exchange a randomly generated symmetric session key. For instance, a sender encrypts a symmetric AES key using the recipient's public RSA key. Once both parties securely possess this session key, they switch to faster symmetric encryption for the actual data transmission. This method resolves the key exchange problem inherent in symmetric encryption while maintaining the performance necessary for large-scale data confidentiality, forming the basis for secure protocols like TLS/SSL.

Message Signing Using Asymmetric Keys
This section details **digital signatures**, a cryptographic technique that combines hashing and asymmetric encryption to provide non-repudiation, authentication, and message integrity. The process begins with the sender generating a cryptographic hash (e.g., SHA-256) of the message, creating a fixed-size fingerprint. This hash is then encrypted using the sender's **private key**—a mathematical operation often called "signing"—to produce the digital signature. The original message and this signature are sent to the recipient. Crucially, hashing the message first is essential for performance (asymmetric operations are slow), ensures compatibility with algorithms that have input size limits, and guarantees that the signature is a consistent size regardless of the original message length.

Verification is performed by the recipient using the sender's publicly available **public key**. The recipient decrypts the received signature with this key to extract the original hash, then independently hashes the received message. A match confirms three security properties: **integrity** (the message is unaltered), **authentication** (it originated from the possessor of the private key), and **non-repudiation** (the sender cannot later deny sending it). This trust model typically relies on a Public Key Infrastructure (PKI) and Certificate Authorities (CAs) to validate the binding between the public key and the sender's identity. Common signing algorithms include RSA-PSS, ECDSA, and the modern, efficient EdDSA (Ed25519), while legacy schemes like DSA and RSA-PKCS#1 v1.5 are deprecated.

Cryptographic Authentication Methods
This section examines three distinct cryptographic authentication methods, each operating at different points on the spectrum of complexity and trust. **Username and password** authentication relies on cryptographic hashing to protect the secret; the server stores only a hash digest of the password (e.g., SHA-256, bcrypt), and the plaintext password is either hashed client-side before transmission or hashed server-side upon receipt. **Pre-Shared Keys (PSKs)** are symmetric secrets shared out-of-band and used for mutual authentication. Rather than transmitting the PSK directly, modern implementations derive ephemeral session keys by combining the PSK with randomly generated nonces exchanged during the handshake. This provides forward secrecy: each session uses a unique key, and compromise of a session key does not reveal the long-term PSK nor decrypt past or future sessions.

**Digital certificates** provide the most robust authentication framework by binding a public key to an identity through a trusted third party—a Certificate Authority (CA). Certificates serve three core cryptographic functions: **authentication** via proof of private key possession (challenge-response or signing handshake transcripts); **key establishment** during the TLS handshake, where the certificate's public key either encrypts a pre-master secret (RSA) or verifies signed Diffie-Hellman parameters (ECDHE); and **integrity** through digital signatures on handshake messages (preventing tampering) and HMAC or AEAD modes (e.g., AES-GCM) on application data. The TLS handshake thus achieves server authentication, secure session key agreement, and cipher suite negotiation, with trust anchored in pre-installed CA root certificates. Certificates are foundational to HTTPS, email security (S/MIME), and code signing, providing non-repudiation and verifiable identity that PSKs and passwords cannot offer in open, untrusted environments.

The SSL/TLS Handshake

How SSL/TLS uses Cryptography

Replay Attacks and Anti-Replay Methods

Wireless Client Authentication mMethods

Wireless Privacy and Integrity Methods

Authentication and Encryption in WPA, WPA2, and WPA3