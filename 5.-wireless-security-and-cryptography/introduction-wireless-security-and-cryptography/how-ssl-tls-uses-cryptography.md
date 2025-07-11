---
hidden: true
---

# How SSL/TLS uses Cryptography

## Learning objectives

• Understand why hashing acts as a foundational layer for securing web traffic\
• In SSL/TLS, a combination of hashing and asymmetric encryption secures websites, APIs, and online transactions

This section explains how cryptographic tools (symmetric/asymmetric encryption, and hashing) secure Internet communications via SSL/TLS.

## Topics covered in this section

* **Introduction**
*

### Introduction

SSL/TLS are cryptographic protocols that provide **encryption, authentication, and data integrity** for secure communication over a network. For example, the HTTPS protocol ensures that data exchanged between a client (e.g., a web browser) and a server (e.g., a website) is private and tamper-proof.

While commonly associated with **HTTPS** (securing web traffic), SSL/TLS is widely used in many other applications, including:

* **Email (SMTPS, IMAPS, POP3S)** – Secures email transmission (sending/receiving) and prevents eavesdropping.
* **VPNs (e.g., OpenVPN)** – Encrypts all traffic between a client and a private network.
* **File transfers (FTPS)** – Protects file transfers (different from SFTP, which uses SSH).
* **Databases (MySQL, PostgreSQL, MongoDB with TLS)** – Encrypts queries and prevents unauthorized access to sensitive data.
* **Directory services (LDAPS)** – Secures authentication and queries in systems like Active Directory.
* **VoIP & messaging (SIP over TLS, XMPP)** – Encrypts call setup (VoIP) and instant messages.
* **IoT & APIs** – Ensures secure firmware updates and encrypted API communications (e.g., payment processing).
* **DNS security (DNS over TLS)** – Prevents tampering or spying on domain name lookups.
* **Remote desktop (RDP with TLS)** – Secures remote access to workstations/servers.

SSL/TLS is the backbone of secure communications. SSL/TLS is used almost anywhere secure communication is needed—not just for websites. If an application transmits sensitive data over a network, there’s a good chance TLS is involved.

**How SSL/TLS uses Cryptography**

<figure><img src="../../.gitbook/assets/image (1).png" alt="How-SSL-TLS-uses-Cryptography"><figcaption><p>How SSL/TLS uses cryptographic tools to secure data transmission (image courtesy of Ed Harmoush, Practical Networking)</p></figcaption></figure>

### 1. Hashing

TLS uses hashing for fingerprint verification, message Authentication Codes (MAC), and digital signatures, thus ensuring **data integrity, authentication, and non-repudiation** in encrypted communications.&#x20;

Hashing role in TLS handshake:

• Integrity Checks: Verifies data integrity (prevents data alteration in transit). Example Algorithms: SHA-256, HMAC.

• Digital Signatures (Asymmetric + Hashing): Authenticates server identity (ensures the server is trusted, preventing MITM attacks). Example Algorithms: RSA + SHA, ECDSA.

Here’s a table correlating data integrity, authentication, and non-repudiation with how TLS uses hashing for fingerprint verification, MACs, and digital signatures:

| **TLS Hashing Application**            | **Security Parameter** | **Explanation**                                                                                                                                                            |
| -------------------------------------- | ---------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Fingerprint Verification**           | **Authentication**     | Public key certificates (e.g., server’s certificate) are hashed to produce fingerprints. Clients verify these against trusted stores to authenticate the server.           |
| **Message Authentication Codes (MAC)** | **Data Integrity**     | TLS uses hash-based MACs (HMAC) or authenticated encryption (AEAD) to ensure transmitted data is unaltered. The hash ensures any tampering is detectable.                  |
| **Digital Signatures**                 | **Non-Repudiation**    | TLS uses hashing (e.g., SHA-256) in digital signatures (e.g., RSA/ECDSA). The sender signs a hash of the message, proving their identity and preventing denial of sending. |

#### **Clarifying Comments:**

1. **Fingerprint Verification**
   * When a Certificate Authority (CA) issues a digital certificate, it digitally signs the certificate (which involves hashing the certificate's contents and encrypting the hash with the CA’s private key).
   * Public key certificates (digital certificates) are hashed (e.g., using SHA-256) to produce a digest (fingerprint). Clients compare the fingerprint with trusted values to ensure they’re connecting to the legitimate server. During TLS handshakes, clients compute the fingerprint by hashing (e.g., using SHA-256) the server’s certificate.
   * Example: Browser checks a certificate's fingerprint against Certificate Authorities. The fingerprint is compared against trusted fingerprints (pre-stored in the client’s CA bundle) or pinned fingerprints (if the app uses Certificate Pinning).
2. **Message Authentication Codes (MAC)**
   * TLS 1.2 uses HMAC (Hash-based MAC) to verify message integrity. The sender and receiver compute a hash of the data + shared secret; mismatches indicate tampering.
   * TLS 1.3 replaces HMAC with **AEAD** (e.g., AES-GCM), which integrates encryption + integrity checks.
   * HMAC uses hashes (SHA-256, SHA-384) combined with a secret key.
3. **Digital Signatures**
   * Used in TLS handshakes (e.g., server’s CertificateVerify message). The sender hashes the handshake messages, then signs the hash with their private key.
   * Ensures **non-repudiation**: The sender cannot later deny sending the message, as only they possess the private key.

#### **Summary:**

* **Hashing** underpins all three mechanisms:
  * **Fingerprints** (authentication) rely on irreversible hashes of certificates.
  * **MACs** (integrity) use hashing (+ secret keys) to detect tampering.
  * **Digital signatures** (non-repudiation) sign hashes to bind messages to identities.

***

### 2. Symmetric Encryption

#### **Role of Symmetric Encryption in SSL/TLS**

Symmetric encryption plays a crucial role in SSL/TLS by ensuring **data confidentiality** during secure communication. It is used to encrypt the actual data transmitted between a client (e.g., a web browser) and a server (e.g., a website).

**Why Symmetric Encryption is Essential:**

* **Efficiency**: Symmetric encryption (e.g., AES, 3DES, ChaCha20) is much faster than asymmetric encryption, making it ideal for encrypting large volumes of data.
* **Confidentiality**: Only the sender and receiver share the same secret key, preventing unauthorized parties from decrypting the data.

**How It Works in SSL/TLS:**





#### Symmetric Encryption

* Purpose: Confidentiality of bulk data
* Common algorithms: AES (128/256-bit), ChaCha20
* **How TLS Uses Symmetric Encryption**:
  1. **Bulk Data Encryption**:
     * Encrypts all application data (web pages, files, etc.) after the handshake
     * Processes millions of bits efficiently with minimal overhead
  2. **Session Keys**:
     * Unique keys generated for each session via the handshake
     * Typically 128-256 bit keys (e.g., AES-256-GCM in TLS 1.3)
  3. **Performance Advantage**:
     * 100-1,000x faster than asymmetric crypto for data transfer
     * Enables high-speed secure communication (e.g., video streaming, large downloads)
  4. **Cipher Modes**:
     * Authenticated Encryption (AEAD): Combines encryption + integrity (e.g., AES-GCM)
     * CBC mode (older TLS versions) with HMAC for integrity
* Why symmetric encryption is used for data transmission
* Key characteristics:
  * Fast processing (optimized for hardware/software)
  * Suitable for large amounts of data
  * Minimal latency impact on user experience
  * Perfect for protecting the actual content of communications



***

### 3. Asymmetric Encryption

#### Asymmetric Encryption

* Purpose: Secure key exchange and authentication
* Common algorithms (RSA, ECC, DH)
* How TLS uses asymmetric crypto for:
  * Initial handshake
  * Key exchange
  * Digital signatures
  * Server authentication



### Key takeaways <a href="#key-takeaways" id="key-takeaways"></a>

• Understand why hashing acts as a foundational layer for securing web traffic\
• In SSL/TLS, a combination of hashing and asymmetric encryption secures websites, APIs, and online transactions

### References

Ed Harmoush. (n.d.). How SSL & TLS use Cryptographic tools to secure your data - Practical TLS. Practical Networking. https://www.youtube.com/watch?v=aCDgFH1i2B0
