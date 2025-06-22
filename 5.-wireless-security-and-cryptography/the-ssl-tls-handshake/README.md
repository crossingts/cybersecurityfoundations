---
description: >-
  This section sheds light on how the SSL/TLS handshake enables secure,
  encrypted communication
---

# The SSL/TLS handshake

This section explains how the SSL/TLS handshake establishes a secure communication channel between two endpoints: Typically, client (e.g., web browser, mobile app) and server (e.g., website, API). For example, when you visit `https://example.com`, your browser (client) performs a TLS handshake with `example.com`'s server to encrypt all traffic.

**Other scenarios**

* Server-to-server communication (e.g., microservices, API gateways).
* Peer-to-peer (P2P) applications where both sides authenticate (less common but possible with mutual TLS/mTLS).

The TLS handshake establishes a secure session by:

* Authenticating the server (and optionally the client).
* Negotiating encryption algorithms (e.g., AES for symmetric encryption).
* Generating and exchanging symmetric session keys securely (using asymmetric encryption like RSA or ECC initially, then switching to symmetric encryption for efficiency).

The ultimate goal of the TLS handshake is to derive session keys which will encrypt and secure the data transfer between the client and the server. The client must trust the server’s public key (from the certificate) to securely establish session keys.

**Certificate validation**

Before key exchange, the server proves its identity using a **digital certificate**:

* The server sends its certificate (containing its public key and identity) to the client.
* The client validates the certificate by:
  * Checking if it’s issued by a trusted **Certificate Authority (CA)**.
  * Verifying the certificate’s digital signature (to ensure it wasn’t forged).
  * Confirming the certificate hasn’t expired or been revoked (via CRL/OCSP).
  * Ensuring the server’s domain matches the certificate’s **Subject Alternative Name (SAN)** or **Common Name (CN)**.

#### Secure session key negotiation

After certificate validation, the client and server negotiate a symmetric session key (used for encrypting data). Two primary methods:

**A. RSA Key Exchange (older, used in TLS 1.2, now discouraged)**

1. The client generates a **premaster secret**, encrypts it with the server’s public key (from the certificate), and sends it.
2. The server decrypts it with its private key.
3. Both derive the same **symmetric session key** from the premaster secret.

**Weakness**: If the server’s private key is compromised later, past communications can be decrypted (no **forward secrecy**).

**B. (EC)DHE Key Exchange (modern, used in TLS 1.3, preferred)**

1. The server’s certificate is still validated, but its public key is only used for authentication.
2. The client and server perform a **Diffie-Hellman (DH) or Elliptic Curve DH (ECDH)** exchange:
   * They exchange DH parameters (public keys) and compute a shared secret.
   * The shared secret is used to derive the symmetric session key.
3. Even if the server’s private key is later compromised, past sessions remain secure (**forward secrecy**).

**Role of Certificate**: Ensures the DH parameters come from the authenticated server, not an impostor.

**Final steps**

* Both parties derive the same **session keys** (for encryption/MAC).
* They exchange **"Finished" messages** (encrypted with the new keys) to confirm the handshake succeeded.
* All further communication uses the symmetric session keys for efficiency.

The TLS handshake ensures:

1. **Confidentiality** – Data is encrypted (e.g., using AES).
2. **Integrity** – Data isn’t tampered with (via hashes/MACs).
3. **Authentication** – The server (and optionally client) proves identity (via certificates).
4. **Forward Secrecy** (if using ephemeral keys) – Past sessions can’t be decrypted even if the private key is later compromised.
