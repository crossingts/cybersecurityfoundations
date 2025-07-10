---
hidden: true
---

# How SSL/TLS uses Cryptography

## Learning objectives

• Understand why hashing acts as a foundational layer for securing web traffic\
• In SSL/TLS, a combination of hashing and asymmetric encryption secures websites, APIs, and online transactions

This section explains how cryptographic tools (symmetric/asymmetric encryption, and hashing) secure Internet communications via SSL/TLS.

## Topics covered in this section

* **Point 1**
*

### Point 1

SSL/TLS are cryptographic protocols that provide **encryption, authentication, and data integrity** for secure communication over a network. For example, HTTPS ensures that data exchanged between a client (e.g., a web browser) and a server (e.g., a website) is private and tamper-proof.

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

Here’s a table correlating data integrity, authentication, and non-repudiation with how TLS uses hashing for fingerprint verification, MACs, and digital signatures:

| **TLS Hashing Application**            | **Security Parameter** | **Explanation**                                                                                                                                                            |
| -------------------------------------- | ---------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Fingerprint Verification**           | **Authentication**     | Public key certificates (e.g., server’s cert) are hashed to produce fingerprints. Clients verify these against trusted stores to authenticate the server.                  |
| **Message Authentication Codes (MAC)** | **Data Integrity**     | TLS uses hash-based MACs (HMAC) or authenticated encryption (AEAD) to ensure transmitted data is unaltered. The hash ensures any tampering is detectable.                  |
| **Digital Signatures**                 | **Non-Repudiation**    | TLS uses hashing (e.g., SHA-256) in digital signatures (e.g., RSA/ECDSA). The sender signs a hash of the message, proving their identity and preventing denial of sending. |

#### **Clarifying Comments:**

1. **Fingerprint Verification**
   * Digital certificates, which are issued by a Certificate Authority (CA), are hashed (e.g., using SHA-256) to produce a digest (fingerprint). Clients compare the fingerprint with trusted values to ensure they’re connecting to the legitimate server.
   * Example: Browser checks a cert’s fingerprint against Certificate Authorities (CAs).
2. **Message Authentication Codes (MAC)**
   * TLS 1.2 uses HMAC (Hash-based MAC) to verify message integrity. The sender and receiver compute a hash of the data + shared secret; mismatches indicate tampering.
   * TLS 1.3 replaces HMAC with **AEAD** (e.g., AES-GCM), which integrates encryption + integrity checks.
3. **Digital Signatures**
   * Used in TLS handshakes (e.g., server’s CertificateVerify message). The sender hashes the handshake messages, then signs the hash with their private key.
   * Ensures **non-repudiation**: The sender cannot later deny sending the message, as only they possess the private key.

#### **Summary:**

* **Hashing** underpins all three mechanisms:
  * **Fingerprints** (authentication) rely on irreversible hashes of certificates.
  * **MACs** (integrity) use hashing (+ secret keys) to detect tampering.
  * **Digital signatures** (non-repudiation) sign hashes to bind messages to identities.



#### **1. Role of Hashing in Digital Signatures**

A digital signature is created using a combination of **hashing + asymmetric encryption**. The process involves:

**Step 1: Hashing the Data**

* The sender (e.g., a website) generates a **hash** of the message/data using a **cryptographic hash function** (e.g., SHA-256).
* This hash acts as a unique "fingerprint" of the data.

**Step 2: Encrypting the Hash with a Private Key**

* The sender **encrypts** this hash using their **private key** (asymmetric encryption, e.g., RSA or ECDSA).
* The encrypted hash becomes the **digital signature**.

**Step 3: Verification by the Receiver**

* The receiver decrypts the signature using the sender’s **public key**, retrieving the original hash.
* They independently compute the hash of the received data.
* If the two hashes match, the data is **authentic and unaltered**.

**2. Why Hashing is Essential in SSL/TLS**

In **SSL/TLS** (used for HTTPS), digital signatures are used for:

**A. Certificate Verification**

* Websites present an **SSL certificate** signed by a Certificate Authority (CA).
* The CA signs the certificate’s hash with its private key.
* Your browser verifies it by checking the signature against the CA’s public key.

**B. Key Exchange (TLS Handshake)**

* In **TLS 1.2/1.3**, hashing ensures integrity during key exchange (e.g., verifying `ServerKeyExchange` messages).
* Example: **RSA-PSS** (Probabilistic Signature Scheme) uses hashing for secure signing.

**C. Message Authentication (HMAC)**

* **HMAC** (Hash-based Message Authentication Code) ensures that TLS records aren’t tampered with in transit.
* Uses hashes (SHA-256, SHA-384) combined with a secret key.

***

### 2. Symmetric Encryption

**Data transmission:** When sending confidential information over unsecure networks like the Internet, encryption protects it from eavesdropping. For example, HTTPS protocol uses encryption to secure online transactions and communication.

***

### 3. Asymmetric Encryption





### Key takeaways <a href="#key-takeaways" id="key-takeaways"></a>

• Understand why hashing acts as a foundational layer for securing web traffic\
• In SSL/TLS, a combination of hashing and asymmetric encryption secures websites, APIs, and online transactions

### References

Ed Harmoush. (n.d.). How SSL & TLS use Cryptographic tools to secure your data - Practical TLS. Practical Networking. https://www.youtube.com/watch?v=aCDgFH1i2B0
