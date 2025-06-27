# Wireless security and cryptography

## Chapter 5: Wireless security and cryptography <a href="#chapter-5-wireless-security-and-cryptography" id="chapter-5-wireless-security-and-cryptography"></a>

This chapter covers how SSL/TLS uses cryptographic tools to secure data, and how the IEEE 802.11 wireless standard enforces security through authentication, encryption, and integrity mechanisms

This chapter covers how SSL/TLS uses cryptographic tools (symmetric encryption, asymmetric encryption, and hashing) to secure data over the Internet, and how the IEEE 802.11 wireless standard enforces security through authentication, encryption, and integrity mechanisms.

***

SSL/TLS secures web traffic between a client and a server through a process called the TLS handshake. Here’s a breakdown of the key steps in TLS 1.3:

A simplified **TLS 1.3 handshake** (modern standard):

1. **Client Hello** → Supported cipher suites, TLS version.
2. **Server Hello** → Chooses cipher, sends certificate.
3. **Key Exchange** → Ephemeral keys (ECDHE, etc.).
4. **Finished** → Encrypted communication begins.

(SSL handshakes were similar but less efficient and secure.)

SSL/TLS Encryption: This protocol uses the public key from the digital certificate to encrypt data sent between the website and visitors’ browsers. This ensures confidentiality and integrity of the information exchanged.
