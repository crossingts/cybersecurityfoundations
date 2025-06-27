# Wireless security and cryptography

### Chapter 5: Wireless security and cryptography

SSL/TLS secures web traffic between a client and a server through a process called the TLS handshake. Here’s a breakdown of the key steps in TLS 1.3:

A simplified **TLS 1.3 handshake** (modern standard):

1. **Client Hello** → Supported cipher suites, TLS version.
2. **Server Hello** → Chooses cipher, sends certificate.
3. **Key Exchange** → Ephemeral keys (ECDHE, etc.).
4. **Finished** → Encrypted communication begins.

(SSL handshakes were similar but less efficient and secure.)

SSL/TLS Encryption: This protocol uses the public key from the digital certificate to encrypt data sent between the website and visitors’ browsers. This ensures confidentiality and integrity of the information exchanged.
