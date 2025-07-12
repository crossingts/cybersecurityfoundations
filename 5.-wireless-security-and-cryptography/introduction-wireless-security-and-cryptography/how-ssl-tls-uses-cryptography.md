---
hidden: true
---

# How SSL/TLS uses Cryptography

## Learning objectives

• Understand why hashing acts as a foundational layer for securing web traffic\
• How in SSL/TLS a combination of hashing and asymmetric encryption secures websites, APIs, and online transactions

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

**Hashing role in TLS handshake:**

1. **Digital Signatures (asymmetric encryption + hashing): Authenticates server identity (ensures the server is trusted, preventing MITM attacks). Example Algorithms: RSA + SHA-256, ECDSA.**

* **When does this occur?**
  * **During the handshake**, in two distinct phases:
    1. **Certificate Verification**:
       * The server sends its **certificate** (signed by a CA using RSA+SHA-256 or ECDSA).
       * The client verifies the CA's signature on the certificate to authenticate the server's identity (preventing MITM).
       * Hashing role: The CA’s signature includes a hash (e.g., SHA-256) of the certificate data.
       * _This happens **before** key exchange._
    2. **Key Exchange (e.g., RSA or ECDHE)**:
       * **In RSA** key exchange (deprecated in TLS 1.3), the client encrypts the "pre-master secret" with the server's public key.
       * **Server authentication (optional):** In TLS 1.2, the server may send a `CertificateVerify` message (signed with RSA+hash) to prove it owns the private key.
       * The "pre-master secret" is combined with nonces to derive the "master secret" (session key). Hashing role: SHA-256 is used in the PRF (Pseudo-Random Function) to derive master secret (e.g., combining pre-master secret + nonces).&#x20;
       * **In ECDHE**, the server signs its ephemeral public key (e.g., using ECDSA+SHA-256 or RSA-PSS+SHA-256) to prove it owns the certificate. Hashing role: The signature includes a hash (e.g., SHA-256) of the handshake messages (for integrity).
       * The "pre-master secret" is combined with nonces to derive the "master secret" (session key). Hashing role: SHA-256 is used in the PRF (Pseudo-Random Function) to derive master secret (e.g., combining pre-master secret + nonces).&#x20;

2. **Integrity Checks: Verifies data integrity (prevents data alteration in transit). Example Algorithms: SHA-256, HMAC.**

**Hashing for Integrity Checks (e.g., SHA-256, HMAC)**

* **After symmetric key negotiation.** Once the TLS handshake establishes a shared session key (the "master secret"), hashing (often via HMAC or AEAD ciphers like AES-GCM) is used to verify message integrity **during the encrypted application data exchange** (not during the handshake itself).
* **Example:** In TLS 1.2, HMAC-SHA256 is used with the session key to generate MACs for each encrypted record. In TLS 1.3, AEAD (e.g., AES-GCM) combines encryption and integrity checks.

**Note-**

In RSA (TLS 1.2) , the `CertificateVerify` message (sent after the server's certificate) is used to prove ownership of the private key by signing a hash of the handshake messages.&#x20;

In RSA (TLS 1.2) the server may send the client a `CertificateVerify` message which is a **signed hash of the handshake messages** (up to that point) using the private key of the server, proving (to the client) the server’s ownership of the private key (authentication).

* The server computes a hash (e.g., SHA-256) of all previous handshake messages.
* It signs this hash with its **private RSA key** (e.g., using `RSA-PSS` or `RSA-PKCS#1`).
* The client verifies the signature using the server’s **public key** (from the certificate).

#### **When Hashing is Used in the TLS protocol**

<table data-header-hidden><thead><tr><th width="165.58941650390625"></th><th width="186.0572509765625"></th><th></th><th></th></tr></thead><tbody><tr><td><strong>Key Exchange Type</strong></td><td><strong>Hashing in Key Exchange Itself?</strong></td><td><strong>Where Hashing is Used</strong></td><td><strong>Explicit Authentication (CertificateVerify)?</strong></td></tr><tr><td><strong>RSA</strong> (TLS 1.2)</td><td>✗ No (raw RSA encryption for key transport)</td><td>✔ <strong>Certificate signatures</strong> (e.g., SHA-256).<br>✔ <strong>PRF</strong> (HMAC-SHA256 for key derivation).</td><td><strong>Optional but recommended</strong>:<br>Server sends <code>CertificateVerify</code> (signed hash of handshake) to prove private key ownership.</td></tr><tr><td><strong>ECDHE</strong> (TLS 1.2/1.3)</td><td>✔ Yes (hash used to sign ephemeral ECDHE public key)</td><td>✔ <strong>ServerKeyExchange signature in TLS 1.2</strong> (e.g., ECDSA-SHA256) or <strong>ServerHello signature in TLS 1.3</strong>.<br>✔ <strong>PRF</strong> (HMAC-SHA256) for key derivation.</td><td><strong>Not needed</strong>:<br>Authentication is implicit in the ECDHE signature (no <code>CertificateVerify</code> required).</td></tr></tbody></table>

**Hashing for signing handshake messages happens in both TLS 1.2 and 1.3.**

* **In TLS 1.3**:
  * Occurs in the **`CertificateVerify`** step, **after** `ServerHello`/`KeyShare` but **before** deriving the session key.
  * **Trigger**: The server signs a SHA-256 hash of all prior handshake messages to prove private key ownership.
* **In TLS 1.2**:
  * Occurs in the **`ServerKeyExchange`** message (for ECDHE cipher suites) or is **omitted** (for static RSA key exchange).
  * **Trigger**: The server signs its ephemeral ECDHE public key + handshake hash (e.g., SHA-256) to prove authenticity.
  * _Note_: Static RSA key exchange (deprecated in TLS 1.3) does **not** sign handshake messages.

#### **Detailed Breakdown (TLS 1.3 Handshake)**

1. **ClientHello** → **ServerHello**
   * Agree on cipher suite (e.g., `ECDHE_RSA_WITH_AES_128_GCM_SHA256`).
2. **Key Exchange (`ServerHello` + `KeyShare`)**
   * Server sends its ephemeral **ECDHE public key** (no signing yet).
3. **Server Authentication Phase**
   * **Certificate**: Server sends its cert (signed by CA using RSA+SHA-256/ECDSA).
   * **CertificateVerify**:
     * **Hashing role**: The server hashes **all previous handshake messages** (up to this point) with SHA-256.
     * **Signing**: Signs this hash with its **private key** (RSA/ECDSA) to prove ownership.
     * _This is the explicit "signing of handshake messages" step._
4. **Final Key Derivation**
   * Client and server derive the session key (`master secret`) using:
     * ECDHE shared secret + nonces + **PRF (SHA-256)**.
5. **Encrypted Data Exchange (Integrity via AEAD)**
   * TLS 1.3 uses AEAD (e.g., AES-GCM), which handles encryption + integrity **without separate hashing**.

#### **Visual TLS 1.3 Handshake Snippet**

```
ClientHello  
  ↓  
ServerHello + KeyShare (ECDHE pubkey)  
  ↓  
Certificate               // CA’s signature (RSA+SHA-256)  
  ↓  
CertificateVerify         // Server signs handshake hash (SHA-256 + RSA/ECDSA)  
  ↓  
Finished (encrypted)      // Session key active  
```

***

The **TLS 1.2 Handshake Snippet** with key hashing actions highlighted:

***

**Visual TLS 1.2 Handshake Snippet**

plaintext

```
ClientHello  
  ↓  
ServerHello  
  ↓  
Certificate               // CA’s signature (RSA+SHA-256/ECDSA)  
  ↓  
ServerKeyExchange        // ⭐ Only for ECDHE: Signed ECDHE pubkey + SHA-256 hash of handshake  
  ↓  
ServerHelloDone  
  ↓  
ClientKeyExchange        // Pre-master secret (RSA-encrypted or ECDHE shared secret)  
  ↓  
ChangeCipherSpec         // Switch to encrypted mode  
  ↓  
Finished (HMAC-SHA-256)  // First encrypted message, verifies handshake integrity  
```

***

**Key Differences from TLS 1.3**

1. **`ServerKeyExchange`** (TLS 1.2):
   * **ECDHE Only**: Signs ephemeral public key + SHA-256 hash of handshake messages.
   * **RSA Key Exchange**: _Omits this step entirely_ (no handshake signing).
2. **No `CertificateVerify`**:
   * TLS 1.2 relies on `ServerKeyExchange` (for ECDHE) or implicit RSA encryption (no explicit signing).
3. **`Finished` Uses HMAC-SHA-256**:
   * TLS 1.2 always uses HMAC for the `Finished` message, while TLS 1.3 uses AEAD.



**TLS 1.2 vs. TLS 1.3: Key Differences in Hashing and Handshake Signing (**&#x43;omparing handshake message signing, key exchange, and integrity mechanisms):

| **Step**              | **TLS 1.2**                                       | **TLS 1.3**                          |
| --------------------- | ------------------------------------------------- | ------------------------------------ |
| **Key Exchange**      | `ServerKeyExchange` (ECDHE only) or RSA-encrypted | `KeyShare` (ECDHE always, no RSA)    |
| **Handshake Signing** | ECDHE signs in `ServerKeyExchange`                | Always signs in `CertificateVerify`  |
| **Integrity Check**   | HMAC-SHA-256 in `Finished`                        | AEAD (e.g., AES-GCM) in all messages |

\--

**All hashing roles (signing, PRF, integrity) for both versions**&#x20;

| **Action**                                 | **TLS 1.2**                                                                                                                                                                               | **TLS 1.3**                                                                    |
| ------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------ |
| **Hashing for Signing Handshake Messages** | <p>✔️ <strong>ECDHE only</strong>: In <code>ServerKeyExchange</code> (signs ECDHE pubkey + handshake hash).<br>❌ <strong>RSA key exchange</strong>: No signing of handshake messages.</p> | ✔️ Always in `CertificateVerify` (signs hash of all prior handshake messages). |
| **Hashing for Key Derivation (PRF)**       | ✔️ SHA-256 (or negotiated hash) for deriving `master_secret`.                                                                                                                             | ✔️ SHA-256 (or HKDF) for deriving `master_secret`.                             |
| **Hashing for Data Integrity**             | ✔️ HMAC-SHA-256 (for cipher suites without AEAD).                                                                                                                                         | ✔️ AEAD (e.g., AES-GCM) handles integrity **without explicit hashing**.        |

\--

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

Public key certificates (e.g., server’s cert) are hashed to produce fingerprints. Who hashes them?

#### **Who Hashes the Certificate to Produce Fingerprints?**

1. **Certificate Authority (CA)**
   * When a CA issues a certificate, it **digitally signs** the certificate (which involves hashing the cert’s contents and encrypting the hash with the CA’s private key).
   * The **fingerprint** (a hash of the entire certificate) is not directly generated by the CA but can be computed by anyone who has the certificate.
2. **Clients (Browsers, OS, or Applications)**
   * During TLS handshakes, clients **compute the fingerprint** by hashing (e.g., SHA-256) the server’s certificate.
   * This fingerprint is compared against:
     * **Trusted fingerprints** (pre-stored in the client’s CA bundle).
     * **Pinned fingerprints** (if the app uses Certificate Pinning).
3. **Developers/System Admins**
   * For manual verification (e.g., SSH keys, GPG), admins may hash a cert/key to get its fingerprint and compare it with a known-good value.

#### **How Fingerprints Are Generated (Example)**

*   A command like OpenSSL can generate a cert’s fingerprint:

    sh

    ```
    openssl x509 -noout -fingerprint -sha256 -in server.crt
    ```

    Output:

    text

    ```
    SHA256 Fingerprint=3A:1B:...:9F
    ```
* **Browsers** display fingerprints in certificate details (Chrome/Firefox show SHA-1 and SHA-256 hashes).

#### **Why Hashing is Used for Fingerprints**

* **Unique identifier**: A hash (like SHA-256) condenses the cert into a fixed-length, unique value.
* **Tamper detection**: Any change in the cert alters the fingerprint drastically.
* **Efficiency**: Comparing hashes is faster than comparing entire certs.

#### **Key Clarifications**

* The **CA doesn’t explicitly create the fingerprint**—it’s derived from the cert’s data by whoever checks it.
* **Digital signatures ≠ fingerprints**:
  * A **signature** is the CA’s encrypted hash (for validation).
  * A **fingerprint** is just a hash of the cert (for quick identification).

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
