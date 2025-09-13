---
description: >-
  This section sheds light on how the SSL/TLS handshake enables secure,
  encrypted communication
---

# The SSL/TLS handshake

## Learning objectives <a href="#learning-objectives" id="learning-objectives"></a>

* Develop a basic understanding of the historical development of the SSL/TLS protocol
* Develop a practical understanding of the phases and purposes of the TLS handshake
* Describe the TLS handshake secure session key negotiation in TLS 1.2 and TLS 1.3
* Identify the key cryptographic algorithms involved in the TLS handshake

This section explains how the [SSL/TLS handshake](https://en.wikipedia.org/wiki/TLS/SSL#TLS_handshake) establishes a secure communication channel between two endpoints: typically, client (e.g., web browser, mobile app) and server (e.g., website, API). For example, when you visit https://example.com, your browser (client) performs a TLS handshake with example.com's server to encrypt all traffic.

## Topics covered in this section <a href="#topics-covered-in-this-section" id="topics-covered-in-this-section"></a>

* **The SSL/TLS protocol**
* **The SSL/TLS handshake process**
* **The TLS handshake key exchange**
* **TLS 1.3 handshake simplified workflow**

### The SSL/TLS protocol

Transport Layer Security (TLS) is the essential cryptographic protocol that secures modern digital communication over networks like the Internet. While "SSL/TLS handshake" and "TLS handshake" in modern contexts refer to the same process, there are historical and technical distinctions. Evolving from the now-deprecated Secure Sockets Layer (SSL) specifications developed by Netscape in the 1990s, TLS was first established as an Internet Engineering Task Force (IETF) standard in 1999, with its most recent iteration, TLS 1.3, defined in August 2018. The protocol's primary purpose is to provide critical security guarantees—namely privacy through confidentiality, data integrity, and authenticity—for communications between applications, achieved via cryptographic methods like digital certificates. It operates in the presentation layer and is architecturally composed of two sub-protocols: the TLS handshake and the TLS record. Although it is deployed in a wide array of services including email and messaging, its most visible and widespread use is in securing HTTPS for web browsing. A closely related protocol known as Datagram Transport Layer Security (DTLS) adapts these security principles for datagram-based applications, leading to the frequent use of the combined term "(D)TLS" in technical contexts.

#### **What is SSL?**

* SSL was the original protocol developed by Netscape in the 1990s (SSL 1.0, 2.0, 3.0).
* Versions: SSL 1.0 (unreleased, flawed), SSL 2.0 (broken), SSL 3.0 (deprecated in 2015 due to POODLE attack).
* Provided basic encryption but had security weaknesses.

#### **What is TLS?**

* TLS 1.0 (1999) – Essentially SSL 3.1 (renamed to avoid legal issues).
* TLS 1.1 (2006) – Minor improvements.
* TLS 1.2 (2008) – Major security upgrade (widely adopted).
* TLS 1.3 (2018) – Faster, more secure (removes obsolete features).

#### **Key Differences Between SSL & TLS**

| Feature           | SSL (3.0)                                             | TLS (1.2+)                          |
| ----------------- | ----------------------------------------------------- | ----------------------------------- |
| **Security**      | Vulnerable (POODLE, etc.)                             | Stronger encryption (AES, ChaCha20) |
| **Handshake**     | Slower, more round trips                              | Faster (TLS 1.3 has 1-RTT)          |
| **Cipher Suites** | Weak (RC4, MD5)                                       | Modern (SHA-256, AEAD)              |
| **Certificates**  | Same X.509 format, but TLS enforces better validation |                                     |

### The SSL/TLS handshake process

1. ClientHello and ServerHello
2.  Certificate validation (asymmetric cryptography)&#x20;

    Before key exchange, the server proves its identity using a digital certificate:

    * The server sends its digital certificate (containing its public key and identity) to the client.
    * The client validates the certificate by:
      * Checking if it’s issued by a trusted Certificate Authority (CA), e.g., DigiCert or Let’s Encrypt.
      * Verifying that the CA's digital signature on the server's certificate is authentic using the CA’s public key. This ensures the certificate wasn’t forged or tampered with.
      * Confirming the certificate has not expired and verifying via CRL or OCSP that the certificate has not been revoked.
      * Ensuring the server’s domain matches the certificate’s Subject Alternative Name (SAN) or Common Name (CN).
3. Key exchange: Establishing a shared secret using a method like RSA or Diffie-Hellman. (For TLS 1.2 and earlier, the server's certificate public key is used directly for exchange. For TLS 1.3, the server's certificate public key is used to sign the DH exchange.)
4. Session key generation (symmetric cryptography)
5. Secure data transmission begins

**The TLS handshake establishes a secure session by:**

1. `ClientHello` & `ServerHello`: Negotiating the TLS version and cipher suite (which defines the symmetric encryption algorithm like AES).
2. Authenticating the server to the client using the server's digital certificate and cryptographic signature, and optionally authenticating the client to the server using a client certificate.
3. Generating and exchanging symmetric session keys securely (using the negotiated key exchange method from the chosen cipher suite).
4. Switching to the negotiated symmetric encryption for efficient secure data transmission.

The ultimate goal of the TLS handshake is the secure derivation of a symmetric session key by the client and server which they will use to encrypt all subsequent data transfer between them.&#x20;

#### The Hello Exchange:

The `ClientHello` and `ServerHello` are the foundation for the entire secure session. In these messages, the client and server agree on the following critical parameters:

1. **TLS Protocol Version:** They agree on the highest version of TLS they both support.
2. **Cipher Suite:** This is the most important part of the negotiation. A cipher suite is a combination of algorithms that defines:
   * **Key Exchange Algorithm:** How the symmetric key will be established (e.g., `ECDHE_RSA`, `ECDHE_ECDSA`). _(Note: In TLS 1.3, the list only contains key exchange algorithms that provide forward secrecy)._
   * **Authentication Algorithm:** What algorithm the server will use to prove its identity (e.g., `RSA` or `ECDSA`). This is often tied to the type of certificate.
   * **Bulk Encryption Algorithm:** The symmetric cipher (like `AES_256_GCM` or `CHACHA20_POLY1305`) that will be used to encrypt the actual application data.
   * **Message Authentication Code (MAC) Algorithm:** How message integrity is verified. In modern cipher suites (like those using AES-GCM), this is a built-in part of the encryption mode.
3. **Session ID / Resumption Parameters:** Mechanisms for resuming a previous session to save on future handshake overhead.
4. **(Extensions) Key Share Parameters:** In TLS 1.3, the client often sends its Diffie-Hellman key share in the `ClientHello`,

#### How the Negotiation Works:

* **ClientHello:** The client sends a list of all the TLS versions, cipher suites, and compression methods it supports. It also generates and sends a random value.
* **ServerHello:** The server responds by selecting one TLS version and one cipher suite from the client's provided lists. It also sends its own random value.

### The TLS handshake key exchange

This part of the handshake is version-dependent. In TLS 1.2, server authentication (the Certificate message) and the key exchange (e.g., RSA or Diffie-Hellman) were distinct sequential phases, often requiring multiple round trips. The handshake flow was:

* Authentication: The server sends a Certificate message. This structured TLS protocol message contains the server's digital certificate chain. This chain includes the server's own certificate plus any intermediate certificates required to connect the server's certificate to a trusted root certificate.
* Key Exchange: Depending on the cipher suite, this is followed by a ServerKeyExchange message (e.g., containing its Diffie-Hellman parameters) or the client simply uses the RSA public key from the received certificate to encrypt the pre-master secret.

In TLS 1.3, the protocol was simplified for performance and security by integrating server authentication and the key exchange into a single, cryptographically bound process. This process begins with the Diffie-Hellman key exchange, which is performed immediately within the first round trip using the key\_share extension. In a DH exchange, shares are the individual pieces of information that each party contributes, which are then used to calculate the final shared session key. In this context, a share is the DH public key that each party contributes to calculate the pre-master secret. After the DH key exchange, the server uses its certificate to generate a digital signature over the entire handshake transcript, which includes the key exchange shares. This signature proves the server's identity and cryptographically binds that identity to the specific key exchange and the generated session keys. This design guarantees Forward Secrecy and prevents downgrade attacks.

The client-server key exchange method is version-dependent, with a major evolution occurring in TLS 1.3.

**TLS 1.2 and Earlier (The "Classic" Handshake)**

After the server’s certificate is validated, the client and server use one of two methods to establish a shared **pre-master secret**, from which the symmetric session keys are derived:

* **A. RSA Key Exchange (Now discouraged):**
  * The client generates the pre-master secret, encrypts it with the server’s public RSA key (from its certificate), and sends it to the server.
  * The server decrypts the pre-master secret with its private key.
  * **Weakness: This method lacks Forward Secrecy.** If the server’s private key is ever compromised, an attacker can decrypt all past recorded communications.
* **B. (EC)DHE Key Exchange (Preferred):**
  * The server sends its Diffie-Hellman (or Elliptic Curve DH) parameters in a `ServerKeyExchange` message after the Certificate message. In the DH key exchange, the server first sends the `ServerHello` message (which finalizes the basic connection rules, like which version of TLS and which cipher suite they will use) and then the `Certificate` message (where the server delivers its digital certificate chain which acts like a digital ID card to prove its identity to the client). The server then sends a `ServerKeyExchange` message. This message contains the server's specific DH parameters, which include its public key. To ensure these parameters cannot be altered by an attacker, the server digitally signs this message using the private key that matches its certificate. Finally, the server sends a `ServerHelloDone` message to signal to the client that the server has finished its part of the initial negotiation.
  * The client and server exchange these DH public keys (parameters) to jointly calculate the pre-master secret.
  * **Benefit: This method provides Forward Secrecy.** The ephemeral DH keys are used once. Compromising the server's long-term private key later does not expose past session keys.
  * **Role of Certificate:** The server's certificate ensures the DH parameters come from the authenticated server and not an impostor.

**TLS 1.3 (The Modern Handshake): (EC)DHE Key Exchange Method is Mandatory and Integrated**

TLS 1.3 was radically simplified and optimized for security and performance:

* **Diffie-Hellman is Mandatory:** RSA-based key exchange was completely removed. Every connection must use an ephemeral (EC)DHE exchange, guaranteeing Forward Secrecy for all sessions.
* **Integrated Key Exchange:** The Diffie-Hellman exchange is performed immediately within the first round trip. The client sends its DH public key (its "share") in the `key_share` extension of the `ClientHello` message, and the server responds with its share in the `ServerHello`.
* **Authentication Follows:** The server then proves it owns the private key corresponding to its certificate by using it to digitally sign the entire handshake conversation (including the DH shares). This signature cryptographically binds the server’s identity to the specific key exchange, preventing tampering and downgrade attacks.

**Final Steps (All TLS Versions)**

Following a successful key exchange:

1. Both parties derive the same set of symmetric session keys from the exchanged secrets.
2. "They exchange `Finished` messages, encrypted with the new session keys, to verify that the handshake was successful and that the entire process has not been tampered with."
3. All further application data is encrypted and authenticated using the efficient symmetric session keys.

In (EC)DHE key exchange used in TLS 1.3, the client verifies the server’s identity just like in TLS 1.2 via the server's digital certificate (before key exchange, the server proves its identity using a digital certificate), but the server's public key is only used for authentication, not in key exchange as in RSA based TLS 1.2. In the TLS 1.3 handshake, the server's public key is only used for authentication thus:&#x20;

**Authentication via `CertificateVerify`**

* The server signs a hash of the handshake messages (including the ephemeral DH parameters) using its private key.
* The client verifies this signature using the server's public key (from its certificate).
* This proves:
  * The server owns the private key matching the certificate.
  * The server was present during the handshake (not a replay attack).
  * The server is the same entity that generated the ephemeral DH keys (prevents man-in-the-middle).

**Key Clarifications TLS 1.2 vs TLS 1.3**&#x20;

* **TLS 1.2 (RSA Key Transport)**:
  * Server’s public key encrypts the pre-master secret (key exchange + authentication coupled).
  * No Perfect Forward Secrecy (PFS) unless using (EC)DHE.
* **TLS 1.3 (Only (EC)DHE)**:
  * Server’s public key never touches key exchange (only authentication via `CertificateVerify`).
  * Perfect Forward Secrecy (PFS) is mandatory.
  * The shared secret is derived solely from ephemeral (EC)DHE keys, independent of the server’s long-term public key. This ensures PFS by design.

**The TLS handshake ensures:**

1. **Confidentiality** – Data is encrypted (e.g., using AES).
2. **Integrity** – Data isn’t tampered with (via hashes/MACs).
3. **Authentication** – The server (and optionally client) proves identity (via certificates).
4. **Forward Secrecy** (if using ephemeral keys) – Past sessions can’t be decrypted even if the private key is later compromised.

### TLS 1.3 handshake simplified workflow

Below is a step-by-step breakdown of the TLS 1.3 handshake with a simplified workflow.

**1. Client Hello**

* The client initiates the connection by sending:
  * Supported TLS version (1.3).
  * List of cipher suites (e.g., AES-256-GCM, ChaCha20-Poly1305).
  * Key Share (DH public key) – Used for key exchange (e.g., x25519, P-256).
  * Optional: Pre-Shared Key (PSK) hint (for session resumption).

_In TLS 1.3, the client guesses the server’s preferred key exchange method and sends its public key upfront (reducing round trips)._

**2. Server Hello**

* The server responds with:
  * Selected cipher suite (e.g., AES-256-GCM).
  * Key Share (DH public key) – Matches the client’s chosen group.
  * Digital Certificate (containing the server’s public key).
  * CertificateVerify (proof of private key ownership).
  * Finished (MAC to verify handshake integrity).

_TLS 1.3 skips the "Certificate Request" and "Server Key Exchange" steps (used in TLS 1.2)._

**3. Client Verification & Key Derivation**

* The client:
  * Verifies the server’s certificate (checks CA, expiry, domain match).
  * Computes the shared secret using:
    * Its own private key + server’s public key (Diffie-Hellman).
  * Derives session keys (for symmetric encryption).
  * Sends: Finished (confirms successful key exchange).

**4. Secure Data Transmission**

* Both sides now have the same session keys (for AES-GCM/ChaCha20 encryption).
* Encrypted communication begins.

**TLS 1.3 vs. TLS 1.2 Key Differences**

| Feature                | TLS 1.2                            | TLS 1.3                            |
| ---------------------- | ---------------------------------- | ---------------------------------- |
| **RTTs (Round Trips)** | 2                                  | 1 (0 with 0-RTT\*)                 |
| **Key Exchange**       | Multiple steps (ServerKeyExchange) | Built into Client/Server Hello     |
| **Forward Secrecy**    | Optional                           | Always On                          |
| **Encryption Start**   | After handshake                    | Partially encrypted early          |
| **Obsolete Ciphers**   | Supports weak ones (RSA, RC4)      | Removed (only modern AEAD ciphers) |

\*0-RTT (Zero Round Trip Time Resumption): Allows instant reconnection for returning clients (but risks replay attacks).\*

**TLS 1.3 Handshake Simplified Workflow (Diagram)**

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

**Why TLS 1.3 is Better**

✅ **1-RTT Handshake** (vs. 2 in TLS 1.2).\
✅ **Stronger Security** (no RSA key exchange, only forward-secure methods).\
✅ **Simpler & Faster** (removes obsolete features).\
⚠️ **0-RTT tradeoff**: Faster but vulnerable to replay attacks (mitigated by limiting 0-RTT data).

**Final Notes**

* TLS 1.3 is now the default in modern browsers & servers.
* Most free certificates (Let’s Encrypt) support TLS 1.3.
* Wireshark/`openssl s_client` can help debug handshakes.

### Key takeaways

* TLS 1.0 (1999) is essentially SSL 3.1 (renamed to avoid legal issues). TLS 1.2 (2008) was a major security upgrade and is widely adopted. TLS 1.3 (2018) is faster and more secure
* Key phases of the TLS handshake are client and server hellos, certificate validation, session key negotiation, and exchanging finished messages
