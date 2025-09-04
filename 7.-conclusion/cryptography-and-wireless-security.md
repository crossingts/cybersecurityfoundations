# Cryptography and wireless security

## Chapter 5: Cryptography and wireless security <a href="#chapter-5-wireless-security-and-cryptography" id="chapter-5-wireless-security-and-cryptography"></a>

This chapter covers how SSL/TLS uses cryptographic tools to secure data, and how the IEEE 802.11 wireless standard enforces security through authentication, encryption, and integrity mechanisms

This chapter covers how SSL/TLS uses cryptographic tools (symmetric encryption, asymmetric encryption, and hashing) to secure data over the Internet, and how the IEEE 802.11 wireless standard enforces security through authentication, encryption, and integrity mechanisms.

***

SSL/TLS (Secure Sockets Layer/Transport Layer Security) uses a combination of cryptographic tools to secure data transmitted over the internet. Here are the main points regarding how each tool is utilized:

#### **1. Asymmetric Encryption (Public-Key Cryptography)**

* Used for **key exchange** and **authentication**.
* The server (and optionally the client) has a **public-private key pair**.
* The public key is shared openly, while the private key is kept secret.
* **TLS Handshake**: Asymmetric encryption is used to:
  * Verify the server’s identity via **digital certificates** (issued by a Certificate Authority).
  * Securely exchange a **pre-master secret**, which is used to derive symmetric keys.
* Common algorithms: **RSA, Diffie-Hellman (DH), Elliptic Curve Cryptography (ECC)**.

#### **2. Symmetric Encryption**

* Used for **bulk data encryption** after the handshake.
* Both client and server use the same shared key to encrypt/decrypt data.
* Faster than asymmetric encryption, making it ideal for securing large amounts of data.
* The symmetric key is derived from the **pre-master secret** (agreed upon during the handshake).
* Common algorithms: **AES (Advanced Encryption Standard), ChaCha20, 3DES (legacy)**.

#### **3. Hashing (Integrity Protection)**

* Ensures **data integrity**—detects tampering during transmission.
* **Hash functions** generate a fixed-size digest (e.g., SHA-256) of the data.
* Used in:
  * **Message Authentication Code (HMAC)** to verify message integrity.
  * **Digital signatures** (in certificates) to authenticate the sender.
* Common hash functions: **SHA-256, SHA-384, SHA-3**.

#### **How SSL/TLS Combines These Tools**

1. **Handshake Phase (Asymmetric Encryption)**
   * Client and server agree on encryption protocols.
   * Server sends its certificate (containing its public key).
   * A shared **pre-master secret** is exchanged securely (using RSA or Diffie-Hellman).
   * Both sides derive the same **symmetric session keys**.
2. **Secure Data Transfer (Symmetric Encryption)**
   * All further communication is encrypted using the symmetric key.
3. **Integrity Check (Hashing)**
   * Each message includes a **MAC (Message Authentication Code)** to ensure it wasn’t altered.

#### **Summary Table**

| **Cryptographic Tool**    | **Purpose in SSL/TLS**              | **Examples**     |
| ------------------------- | ----------------------------------- | ---------------- |
| **Asymmetric Encryption** | Key exchange, authentication        | RSA, ECDH, ECDSA |
| **Symmetric Encryption**  | Encrypting application data         | AES, ChaCha20    |
| **Hashing**               | Data integrity, certificate signing | SHA-256, HMAC    |

This combination ensures **confidentiality** (via encryption), **authentication** (via certificates), and **integrity** (via hashing) for secure internet communication.&#x20;

A simplified **TLS 1.3 handshake** (modern standard):

1. **Client Hello** → Supported cipher suites, TLS version.
2. **Server Hello** → Chooses cipher, sends certificate.
3. **Key Exchange** → Ephemeral keys (ECDHE, etc.).
4. **Finished** → Encrypted communication begins.

### Integrity in SSL

**TLS ensures message integrity in two phases:**

* **Before session keys:** Integrity is checked via digital signatures (handshake).
* **After session keys:** Integrity is checked via HMAC (TLS 1.2) or AEAD (TLS 1.3).

1. **Handshake Phase (handshake integrity and authentication):**
   * The server’s certificate is verified using CA signatures.
   * Hashed handshake messages may be signed (e.g., `CertificateVerify` in TLS 1.3).
   * **Not HMAC/AEAD yet**—these are for encrypted data only.
2. **Encrypted Data Phase (post-handshake data integrity):**
   * **TLS 1.2:** Uses HMAC (e.g., HMAC-SHA256) to verify each encrypted record.
   * **TLS 1.3:** Uses AEAD (e.g., AES-GCM) for built-in encryption + integrity.

This ensures **both the handshake and application data** are protected against tampering.

### Authentication in SSL

TLS ensures the identity of communicating parties in two primary ways:\
**Server Authentication:** This is mandatory and fundamental to the protocol.\
**Client Authentication:** This is optional and used for higher-security scenarios.

**Handshake Phase (Establishing Identity):**

* The server presents its digital certificate, which is verified using trusted Certificate Authority (CA) signatures.
* The server proves possession of the private key corresponding to its certificate by signing a handshake message (e.g., ServerKeyExchange in TLS 1.2, CertificateVerify in TLS 1.3).
* For client authentication, the client similarly sends a certificate and a signature (CertificateVerify).

**Encrypted Data Phase (Continuous Authentication):**

* While not a re-authentication of identity, all subsequent application data is encrypted and integrity-protected with keys derived from the authenticated handshake.
* This ensures that data is exchanged only with the previously authenticated party for the duration of the session.

This process guarantees that clients are communicating with the legitimate owner of a domain, not an impostor, and optionally verifies the client's identity to the server.

### Privacy in SSL

TLS ensures data privacy by preventing eavesdropping through encryption, which is applied in two stages:\
**Before session keys:** Handshake messages are in plaintext, except for secrets protected by asymmetric encryption.\
**After session keys:** All application data is encrypted with strong symmetric ciphers.

**Handshake Phase (Key Establishment):**

* A pre-master secret is generated by the client and encrypted with the server's public key (from its certificate) or via a Diffie-Hellman key exchange.
* This secret is used by both parties to independently derive identical symmetric session keys. The handshake itself is not encrypted but is integrity-protected.

**Encrypted Data Phase (Application Data Protection):**

* TLS 1.2: Uses symmetric encryption algorithms (e.g., AES, ChaCha20) to encrypt the payload of each record.
* TLS 1.3: Uses Authenticated Encryption with Associated Data (AEAD) algorithms (e.g., AES-GCM) which provide both confidentiality and integrity in a single operation.

This ensures that all application data (e.g., HTTP, emails, messages) remains confidential and unreadable to any third party observing the network traffic.
