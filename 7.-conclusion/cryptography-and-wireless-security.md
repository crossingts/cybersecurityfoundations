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

Cryptographic Encryption and Confidentiality

Message Signing Using Asymmetric Keys

Cryptographic Authentication Methods

The SSL/TLS Handshake

How SSL/TLS uses Cryptography

Replay Attacks and Anti-Replay Methods

Wireless Client Authentication mMethods

Wireless Privacy and Integrity Methods

Authentication and Encryption in WPA, WPA2, and WPA3