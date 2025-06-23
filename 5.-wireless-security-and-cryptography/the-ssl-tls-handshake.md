---
description: >-
  This section sheds light on how the SSL/TLS handshake enables secure,
  encrypted communication
---

# The SSL/TLS handshake

This section explains how the [SSL/TLS handshake](https://en.wikipedia.org/wiki/TLS/SSL#TLS_handshake) establishes a secure communication channel between two endpoints: Typically, client (e.g., web browser, mobile app) and server (e.g., website, API). For example, when you visit https://example.com, your browser (client) performs a TLS handshake with example.com's server to encrypt all traffic.

#### SSL/TLS handshake or TLS handshak?

While "SSL/TLS handshake" and "TLS handshake" in modern contexts refer to the same process, there are historical and technical distinctions:

* **SSL (Secure Sockets Layer)** was the original protocol developed by Netscape in the 1990s (SSL 1.0, 2.0, 3.0).
* **TLS (Transport Layer Security)** is the standardized, more secure successor (TLS 1.0, 1.1, 1.2, 1.3).
* Today, **TLS is the actual protocol in use**, but due to SSL's historical dominance, people still say **"SSL/TLS"** out of habit.

#### **What is SSL?**

* Versions: **SSL 1.0** (unreleased, flawed), **SSL 2.0** (broken), **SSL 3.0** (deprecated in 2015 due to POODLE attack).
* Provided basic encryption but had security weaknesses.

#### **What is TLS?**

* **TLS 1.0 (1999)** – Essentially SSL 3.1 (renamed to avoid legal issues).
* **TLS 1.1 (2006)** – Minor improvements.
* **TLS 1.2 (2008)** – Major security upgrade (widely adopted).
* **TLS 1.3 (2018)** – Faster, more secure (removes obsolete features).

#### **Key Differences Between SSL & TLS**

| Feature           | SSL (3.0)                                             | TLS (1.2+)                          |
| ----------------- | ----------------------------------------------------- | ----------------------------------- |
| **Security**      | Vulnerable (POODLE, etc.)                             | Stronger encryption (AES, ChaCha20) |
| **Handshake**     | Slower, more round trips                              | Faster (TLS 1.3 has 1-RTT)          |
| **Cipher Suites** | Weak (RC4, MD5)                                       | Modern (SHA-256, AEAD)              |
| **Certificates**  | Same X.509 format, but TLS enforces better validation |                                     |

**For security**: Disable SSL entirely and enforce **TLS 1.2+**.

When discussing handshakes, "TLS handshake" is more accurate, but "SSL/TLS handshake" is widely understood.

***

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

***

**TLS 1.3 Handshake Explained (Simplified & Secure)**

Below is a step-by-step breakdown of the TLS 1.3 handshake with a simplified workflow.

**Step-by-Step TLS 1.3 Handshake**

**1. Client Hello**

* The client initiates the connection by sending:
  * **Supported TLS version** (1.3).
  * **List of cipher suites** (e.g., AES-256-GCM, ChaCha20-Poly1305).
  * **Key Share (DH public key)** – Used for key exchange (e.g., x25519, P-256).
  * **Optional: Pre-shared Key (PSK) hint** (for session resumption).

📌 _In TLS 1.3, the client guesses the server’s preferred key exchange method and sends its public key upfront (reducing round trips)._

**2. Server Hello**

* The server responds with:
  * **Selected cipher suite** (e.g., AES-256-GCM).
  * **Key Share (DH public key)** – Matches the client’s chosen group.
  * **Digital Certificate** (containing the server’s public key).
  * **CertificateVerify** (proof of private key ownership).
  * **Finished** (MAC to verify handshake integrity).

📌 _TLS 1.3 skips the "Certificate Request" and "Server Key Exchange" steps (used in TLS 1.2)._

**3. Client Verification & Key Derivation**

* The client:
  * **Verifies the server’s certificate** (checks CA, expiry, domain match).
  * **Computes the shared secret** using:
    * Its own private key + server’s public key (Diffie-Hellman).
  * **Derives session keys** (for symmetric encryption).
  * Sends:
    * **Finished** (confirms successful key exchange).

**4. Secure Data Transmission**

* Both sides now have:
  * **Same session keys** (for AES-GCM/ChaCha20 encryption).
  * **Encrypted communication begins**.

***

**TLS 1.3 vs. TLS 1.2 Key Differences**

| Feature                | TLS 1.2                            | TLS 1.3                            |
| ---------------------- | ---------------------------------- | ---------------------------------- |
| **RTTs (Round Trips)** | 2                                  | 1 (0 with 0-RTT\*)                 |
| **Key Exchange**       | Multiple steps (ServerKeyExchange) | Built into Client/Server Hello     |
| **Forward Secrecy**    | Optional                           | Always On                          |
| **Encryption Start**   | After handshake                    | Partially encrypted early          |
| **Obsolete Ciphers**   | Supports weak ones (RSA, RC4)      | Removed (only modern AEAD ciphers) |

📌 \*0-RTT (Zero Round Trip Time Resumption): Allows instant reconnection for returning clients (but risks replay attacks).\*

***

**TLS 1.3 Handshake Workflow (Diagram)**

textCopyDownload

```
Client                                                                 Server
  |                                                                       |
  | --- Client Hello (Key Share, Cipher Suites) ------------------------> |
  |                                                                       |
  | <--- Server Hello (Key Share, Certificate, Finished) ---------------- |
  |                                                                       |
  | --- (Derives Keys, Sends Finished) ---------------------------------> |
  |                                                                       |
  | <=== ENCRYPTED DATA EXCHANGE BEGINS ===>                             |
```

***

**Why TLS 1.3 is Better**

✅ **1-RTT Handshake** (vs. 2 in TLS 1.2).\
✅ **Stronger Security** (no RSA key exchange, only forward-secure methods).\
✅ **Simpler & Faster** (removes obsolete features).\
⚠️ **0-RTT tradeoff**: Faster but vulnerable to replay attacks (mitigated by limiting 0-RTT data).

***

**Final Notes**

* TLS 1.3 is now the **default in modern browsers & servers**.
* Most free certificates (Let’s Encrypt) support TLS 1.3.
* Wireshark/`openssl s_client` can help debug handshakes.
