---
description: >-
  This section explains how hashing, asymmetric encryption, and symmetric
  encryption secure Internet communications via SSL/TLS
---

# How SSL/TLS uses cryptography

## Learning objectives

* Identify the wide range of applications beyond HTTPS that rely on SSL/TLS for secure communication
* Understand how SSL/TLS uses a combination of hashing and cryptographic encryption to secure data transmission on the Internet
* Distinguish the unique role each cryptographic tool (hashing, symmetric encryption, and asymmetric encryption) plays in achieving security goals such as confidentiality, integrity, and authentication
* Understand the role of hashing in providing data integrity, authentication, and non-repudiation through fingerprint verification, MACs, and digital signatures
* Distinguish between the integrity mechanisms used in TLS 1.2 (HMAC) and TLS 1.3 (AEAD ciphers like AES-GCM)
* Explain how asymmetric encryption establishes a secure, authenticated key exchange during the handshake
* Contrast the use of asymmetric encryption in TLS 1.2 with its mandatory use for authentication in TLS 1.3
* Articulate why symmetric encryption is used for bulk data encryption, highlighting its performance advantages over asymmetric encryption

This section explains how cryptographic tools (hashing, asymmetric encryption, and symmetric encryption) secure Internet communications via SSL/TLS. The section begins by establishing the critical role of SSL/TLS as the backbone for securing not just web traffic, but also email, VPNs, APIs, and much more. It then deconstruct the TLS protocol to see how its security is built upon a foundation of three cryptographic tools: hashing, asymmetric encryption, and symmetric encryption. This section first explores how hashing creates digital fingerprints for certificates and ensures data integrity. Next, it details how asymmetric encryption enables secure key exchange and server authentication during the handshake. Finally, it examines the TLS protocol's shift to high-performance symmetric encryption for safeguarding application data, a process that incorporates integrity checks through modern authenticated encryption.

## Topics covered in this section

* **SSL/TLS use cases**
* **How SSL/TLS uses hashing**
* **How SSL/TLS uses asymmetric cryptography**
* **How SSL/TLS uses symmetric cryptography**

<figure><img src="https://dti-techs.gitbook.io/practical-foundations-in-cybersecurity/~gitbook/image?url=https%3A%2F%2F3800590736-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252Fbt139QivYIJ8rAS9v8zR%252Fuploads%252FhZsS8unR9Da3FYTqM2Ji%252Fimage.png%3Falt%3Dmedia%26token%3D7de125b0-7e26-486d-860d-412d0fd55ee9&width=768&dpr=2&quality=100&sign=ad4f0ed3&sv=2" alt="How-SSL-TLS-uses-Cryptography"><figcaption><p>How SSL/TLS uses cryptographic tools to secure data transmission (image courtesy of Ed Harmoush, Practical Networking)</p></figcaption></figure>

### SSL/TLS use cases

SSL/TLS are cryptographic protocols that provide **encryption, authentication, and data integrity** for secure communication over a network. For example, the HTTPS protocol ensures that data exchanged between a client (e.g., a web browser) and a server (e.g., a website) is private and tamper-proof.

**How HTTP and TLS combine to form HTTPS**

HTTPS (Hypertext Transfer Protocol Secure) is the standard HTTP protocol, but it is sent over a connection that has been secured by TLS. Here’s how it works in a typical web browsing session:

1. **Client Hello:** You type `https://www.example.com` into your browser. Your browser connects to the server on port 443 (the default port for HTTPS, unlike HTTP's port 80).
2. **TLS Handshake:** Before any HTTP data is exchanged, the browser and the server perform the TLS handshake. They agree on encryption protocols, the server proves its identity with its SSL/TLS certificate, and they generate session keys for encryption.
3. **Secure Tunnel Established:** A secure, encrypted tunnel is now active.
4. **HTTP Over the Tunnel:** Now, and only now, the normal HTTP request is sent. But because it's traveling through the encrypted TLS tunnel, it's secure. The request for the webpage, the HTML that is returned, the images, your login credentials—all of it is encrypted.
5. **You see the padlock:** Your browser shows the padlock icon (🔒) in the address bar, indicating the connection is secure.

**HTTP vs HTTPS**

| Feature                 | HTTP                                                      | HTTPS                                                 |
| ----------------------- | --------------------------------------------------------- | ----------------------------------------------------- |
| **Protocol**            | Hypertext Transfer Protocol                               | Hypertext Transfer Protocol Secure                    |
| **Underlying Security** | None                                                      | SSL/TLS Protocol                                      |
| **Default Port**        | 80                                                        | 443                                                   |
| **Data Encryption**     | No. Data is sent in plain text.                           | Yes. Data is encrypted.                               |
| **Authentication**      | No identity verification.                                 | Yes, verifies server identity with a certificate.     |
| **Data Integrity**      | No protection from tampering.                             | Data is protected from modification in transit.       |

While commonly associated with HTTPS (securing web traffic), SSL/TLS is widely used in many other applications, including:

* **Email (SMTPS, IMAPS, POP3S)** – Secures email transmission (sending/receiving) and prevents eavesdropping.
* **VPNs (e.g., OpenVPN)** – Encrypts all traffic between a client and a private network.
* **File transfers (FTPS)** – Protects file transfers (different from SFTP, which uses SSH).
* **Databases (MySQL, PostgreSQL, MongoDB with TLS)** – Encrypts queries and prevents unauthorized access to sensitive data.
* **Directory services (LDAPS)** – Secures authentication and queries in systems like Active Directory.
* **VoIP and messaging (SIP over TLS, XMPP)** – Encrypts call setup (VoIP) and instant messages.
* **IoT and APIs** – Ensures secure firmware updates and encrypted API communications (e.g., payment processing).
* **DNS security (DNS over TLS)** – Prevents tampering or spying on domain name lookups.
* **Remote desktop (RDP with TLS)** – Secures remote access to workstations/servers.

SSL/TLS is used almost anywhere secure communication is needed—not just for websites. If an application transmits sensitive data over a network, there’s a good chance TLS is involved.

### How SSL/TLS uses hashing

SSL/TLS uses hashing for fingerprint verification, Message Authentication Codes (MAC), and digital signatures, thus ensuring **data integrity, authentication, and non-repudiation** in encrypted communications.

**Hashing's role in the TLS handshake:**

1\. Digital signatures (asymmetric encryption + hashing): Authenticating the server's identity (ensuring the server is trusted). Examples of algorithm combinations used to create digital signatures include RSA + SHA-256, and ECDSA + SHA-256. The process of using digital signatures for server authentication occurs during the TLS handshake in two distinct phases:

**A. Certificate Verification (TLS 1.2 and TLS 1.3)**:

* The server sends its certificate (signed by a CA using RSA+SHA-256 or ECDSA).
* The client verifies the CA's signature on the certificate to authenticate the server's identity (the authentication chain is: I trust the CA -> the CA vouches for this server -> therefore, I can trust this server).
* Hashing's role: The CA’s signature includes a hash (e.g., SHA-256) of the certificate data.
* This happens before the key exchange.

**B. Key Exchange (e.g., RSA or ECDHE)**:

* In RSA key exchange (deprecated in TLS 1.3), the client encrypts the pre-master secret with the server's public key.

Explicit server authentication is optional in TLS 1.2: The server may send a `CertificateVerify` message (signed with RSA+hash) to prove it owns the private key.

Both the client and the server independently combine the pre-master secret with the exchanged nonces (client random and server random) to derive a master secret. Hashing's role in this process: both parties use a Pseudo-Random Function (PRF) built on a hash algorithm like SHA-256. This function actively expands the pre-master secret by mixing it with the nonces to generate the unique master secret.

To derive the actual session keys (for encryption and integrity checking) from the master secret, both parties perform a process called key expansion. They again use the PRF, but this time they use the master secret as the seed and mix it with the same handshake transcript (a record of all messages sent and received) to generate a block of key material. This block is then split into the specific symmetric session keys.

* In ECDHE (TLS 1.2), the server signs its ephemeral public key (e.g., using ECDSA+SHA-256 or RSA-PSS+SHA-256) to prove it owns the certificate.&#x20;

Hashing's role: The signature includes a hash (e.g., SHA-256) of the handshake messages (for integrity). The pre-master secret is combined with nonces to derive the master secret (then session key). Hashing's role: SHA-256 is used in the PRF (Pseudo-Random Function) to derive master secret (e.g., combining pre-master secret + nonces).&#x20;

2\. Integrity checks: Verifying data integrity (preventing data alteration in transit). Examples of algorithms used to verify data integrity include SHA-256 and HMAC.

**Hashing for Integrity Checks**

After symmetric key negotiation: Once the TLS handshake establishes a shared session key, hashing (often via HMAC or AEAD ciphers like AES-GCM) is used to verify message integrity during the encrypted application data exchange (not during the handshake itself). For example, in TLS 1.2, HMAC-SHA256 is used with the session key to generate MACs for each encrypted record. In TLS 1.3, AEAD (e.g., AES-GCM) combines encryption and integrity checks.

Note - In RSA (TLS 1.2) , the `CertificateVerify` message (sent after the server's certificate) is used to prove ownership of the private key by signing a hash of the handshake messages. In RSA (TLS 1.2) the server may send the client a `CertificateVerify` message which is a signed hash of the handshake messages (up to that point) using the private key of the server, proving (to the client) the server’s ownership of the private key (authentication).

* The server computes a hash (e.g., SHA-256) of all previous handshake messages.
* It signs this hash with its private RSA key (e.g., using `RSA-PSS` or `RSA-PKCS#1`).
* The client verifies the signature using the server’s public key (from the certificate).

**When Hashing is Used in the TLS protocol (TLS Key Exchange and Hashing)**

| **Key Exchange Type** | **Hashing in Key Exchange Itself?**                  | **Where Hashing is Used**                                                                                                                                                                                                             | **Explicit Authentication (`CertificateVerify`)?**                                                                                                          |
| --------------------- | ---------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **RSA (TLS 1.2)**     | ✗ No (raw RSA encryption for key transport)          | <p>✔ <strong>Certificate signatures</strong> (e.g., RSA-SHA256).<br>✔ <strong>PRF</strong> (HMAC-SHA256 for key derivation).<br>✔ <strong>Optional:</strong> <code>CertificateVerify</code> signs handshake hash (SHA-256 + RSA).</p> | <p><strong>Optional but recommended</strong>:<br>Server sends <code>CertificateVerify</code> (signed hash of handshake) to prove private key ownership.</p> |
| **ECDHE (TLS 1.2)**   | ✔ Yes (hash used to sign ephemeral ECDHE public key) | <p>✔ <strong>ServerKeyExchange signature</strong> (e.g., ECDSA-SHA256).<br>✔ <strong>PRF</strong> (HMAC-SHA256 for keys).</p>                                                                                                         | <p><strong>Not required</strong>.<br>Server’s signature on ECDHE params provides implicit authentication.</p>                                               |
| **ECDHE (TLS 1.3)**   | ✔ Yes (hash used in handshake signature)             | <p>✔ <strong>ServerHello signature</strong> (covers entire handshake context).<br>✔ <strong>HKDF</strong> (SHA-256/384 for key derivation).</p>                                                                                       | <p><strong>Mandatory</strong>.<br><code>CertificateVerify</code> signs all handshake messages (SHA-256 + RSA/ECDSA).</p>                                    |

**Hashing for signing handshake messages happens in both TLS 1.2 and TLS 1.3.**

**In TLS 1.2**:

* Occurs in the `ServerKeyExchange` message (for ECDHE cipher suites) or is omitted (for static RSA key exchange).
* Trigger: The server signs its ephemeral ECDHE public key + handshake hash (e.g., RSA in TLS 1.2 using SHA-256) to prove authenticity.

**In TLS 1.3**:

* Occurs in the `CertificateVerify` step, after `ServerHello`/`KeyShare` but before deriving the session key.
* Trigger: The server signs a SHA-256 hash of all prior handshake messages to prove private key ownership.

**Visual TLS 1.2 Handshake Snippet with key hashing actions highlighted**

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

**Key Differences from TLS 1.3**

1. **`ServerKeyExchange`** (TLS 1.2):
   * RSA Key Exchange: Omits this step entirely (no handshake signing).
   * ECDHE Only: Signs ephemeral public key + SHA-256 hash of handshake messages.
2. **`CertificateVerify`**:
   * TLS 1.2 relies on `ServerKeyExchange` (for ECDHE) or implicit RSA encryption (no explicit signing).
3. **`Finished` Uses HMAC-SHA-256**:
   * TLS 1.2 always uses HMAC for the `Finished` message, while TLS 1.3 uses AEAD.

#### **Detailed Breakdown (TLS 1.3 Handshake)**

1. **ClientHello and ServerHello Exchange**
   * During the initial phase of the handshake, the client initiates the connection by sending a ClientHello message, listing its supported cryptographic options. The server then responds with a ServerHello message, selecting a specific cipher suite from the client's list, for example, ECDHE\_RSA\_WITH\_AES\_128\_GCM\_SHA256.
2. **Key Exchange (`ServerHello` + `KeyShare`)**
   * Server sends its ephemeral ECDHE public key (no signing yet).
3. **Server Authentication Phase**
   * **Certificate**: Server sends its digital certificate (signed by CA using RSA+SHA-256/ECDSA).
   * **CertificateVerify**:
     * **Hashing's role**: The server hashes all previous handshake messages (up to this point) with SHA-256.
     * **Signing**: Signs this hash with its private key (RSA/ECDSA) to prove ownership.
     * This is the explicit "signing of handshake messages" step.
4. **Final Key Derivation**
   * Client and server derive the session key (`master secret`) using:
     * ECDHE shared secret + nonces + PRF (SHA-256).
5. **Encrypted Data Exchange (Integrity via AEAD)**
   * TLS 1.3 uses AEAD (e.g., AES-GCM), which handles encryption + integrity without separate hashing.

#### **Visual TLS 1.3 Handshake (Simplified)**

```
ClientHello  
  ↓ (Includes KeyShare: Client’s ECDHE pubkey + supported groups)  
ServerHello + KeyShare (Server’s ECDHE pubkey)  
  ↓ (Negotiated cipher suite + "hello" messages hashed for keys)  
EncryptedExtensions  
  ↓ (Optional server config, e.g., ALPN)  
Certificate  
  ↓ (Server’s cert, signed by CA with RSA/ECDSA + SHA-256)  
CertificateVerify  
  ↓ (Server signs hash of handshake with its private key)  
Finished (encrypted)  
  ↓ (HMAC over handshake transcript, using derived key)  
[Application Data]  
```

The following table summarizes the key differences between TLS 1.2 and TLS 1.3 regarding key exchange, handshake message signing, and integrity check mechanisms.

**TLS 1.2 vs TLS 1.3: Key Differences in Hashing and Handshake Signing**

| **Step**              | **TLS 1.2**                                       | **TLS 1.3**                          |
| --------------------- | ------------------------------------------------- | ------------------------------------ |
| **Key Exchange**      | `ServerKeyExchange` (ECDHE only) or RSA-encrypted | `KeyShare` (ECDHE always, no RSA)    |
| **Handshake Signing** | ECDHE signs in `ServerKeyExchange`                | Always signs in `CertificateVerify`  |
| **Integrity Check**   | HMAC-SHA-256 in `Finished`                        | AEAD (e.g., AES-GCM) in all messages |

**TLS 1.2 vs TLS 1.3: All Hashing Roles (Signing, PRF, Integrity)**

| **Action**                                 | **TLS 1.2**                                                                                                                                                                          | **TLS 1.3**                                                                    |
| ------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------ |
| **Hashing for Signing Handshake Messages** | <p>✔️ ECDHE only: In <code>ServerKeyExchange</code> (signs ECDHE pubkey + handshake hash).<br>❌ RSA key exchange: No signing of handshake messages (optional CertificateVerify).</p> | ✔️ Always in `CertificateVerify` (signs hash of all prior handshake messages). |
| **Hashing for Key Derivation (PRF)**       | ✔️ SHA-256 (or negotiated hash) for deriving `master_secret`.                                                                                                                        | ✔️ SHA-256 (or HKDF) for deriving `master_secret`.                             |
| **Hashing for Data Integrity**             | ✔️ HMAC-SHA-256 (for cipher suites without AEAD).                                                                                                                                    | ✔️ AEAD (e.g., AES-GCM) handles integrity without explicit hashing.            |

The following table summarizes how TLS uses hashing for fingerprint verification, MACs, and digital signatures (providing authentication, integrity, and non-repudiation).

**How TLS uses Hashing for Authentication, Integrity, and Non-Repudiation**

| **TLS Hashing Application**            | **Security Parameter** | **Explanation**                                                                                                                                                               |
| -------------------------------------- | ---------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Fingerprint Verification**           | **Authentication**     | Public key certificates (e.g., server’s certificate) are hashed to produce fingerprints. Clients verify these fingerprints against trusted stores to authenticate the server. |
| **Message Authentication Codes (MAC)** | **Data Integrity**     | TLS uses hash-based MACs (HMAC) or authenticated encryption (AEAD) to ensure transmitted data is unaltered. The hash ensures any tampering is detectable.                     |
| **Digital Signatures**                 | **Non-Repudiation**    | TLS uses hashing (e.g., SHA-256) in digital signatures (e.g., RSA/ECDSA). The sender signs a hash of the message, proving their identity and preventing denial of sending.    |

#### I. Fingerprint Verification

**How the server authentication works in TLS:**

1. **Certificate Issuance (Pre-TLS Handshake):**
   * The server's operator generates a key pair (public + private key) and submits a Certificate Signing Request (CSR) to a Certificate Authority (CA).
   * The CA validates the server's identity (e.g., verifying domain ownership for HTTPS).
   * The CA creates the server's certificate, which includes:
     * Server's public key
     * Server's identity (e.g., domain name)
     * Issuer (CA) information
     * Validity period
     * Other metadata (extensions, e.g., Subject Alternative Name for multiple domains)
   * The CA hashes the certificate's contents using an algorithm like SHA-256 to produce a unique fingerprint.
   * The CA encrypts this fingerprint with its own private key to create the digital signature.
   * The signature is appended to the certificate, which is now "signed" and sent to the server.
2. **During TLS Handshake (Authentication):**
   * The server sends its signed certificate to the client in the `Server Hello`.
   * The client:\
     a. **Validates the certificate chain**: Checks if the certificate is issued by a trusted CA (traversing the chain up to a root CA in its trust store).\
     b. **Decrypts the signature:** Uses the CA's public key (from the CA's own certificate) to decrypt the signature, obtaining the original fingerprint.\
     c. **Recomputes the fingerprint**: Hashes the certificate's contents (excluding the signature) using the same hash algorithm the CA used.\
     d. **Compares fingerprints**: Checks if the decrypted fingerprint matches the recomputed fingerprint.
3. **Authentication Outcomes:**
   * **Match**: The certificate is authentic (not tampered with) and was signed by the trusted CA.
     * The client now trusts the server's public key in the certificate.
     * The client proceeds with key exchange (e.g., generating a pre-master secret encrypted with the server's public key).
   * **Mismatch**: The certificate is invalid (possibly tampered with or corrupted): the handshake fails.
4. **Additional Checks (Beyond the Signature):**
   * The client also verifies:
     * The certificate's validity period (not expired/not yet valid).
     * The server's identity (e.g., domain name matches the certificate's `Subject` or `SAN`).
     * The certificate hasn't been revoked (via CRL or OCSP, though modern TLS often uses OCSP stapling).

The mechanism of using a CA's digital signature to authenticate a server fulfils its purpose for the following reasons:

* **Integrity**: If an attacker altered the certificate (e.g., changed the public key), the recomputed fingerprint wouldn't match the decrypted one.
* **Authenticity**: Only the CA could have created a valid signature (requires the CA's private key, which is kept secret).
* **Trust**: The client implicitly trusts CAs in its trust store. If the CA is compromised, authentication fails.

#### **How Fingerprints Are Generated (Example)**

*   A command like OpenSSL can generate a certificate's fingerprint:

    sh

    ```
    openssl x509 -noout -fingerprint -sha256 -in server.crt
    ```

    Output:

    text

    ```
    SHA256 Fingerprint=3A:1B:...:9F
    ```
* Browsers display fingerprints in certificate details (Chrome/Firefox show SHA-1 and SHA-256 hashes).

#### **Why Hashing is Used for Fingerprints**

* **Unique identifier**: A hash (like SHA-256) condenses the certificate into a fixed-length, unique value.
* **Tamper detection**: Any change in the certificate alters the fingerprint drastically.
* **Efficiency**: Comparing hashes is faster than comparing entire certificates.

#### II. Message Authentication Codes (MAC)

TLS provides integrity protection at two distinct layers of the protocol—during the TLS handshake (authentication and key exchange) and during encrypted data exchange—each employing a different cryptographic mechanism.

**First, during the handshake phase**, which handles authentication and key exchange, integrity is ensured through digital signatures like RSA or ECDSA. The primary purpose of this is to verify the server's identity and guarantee that the critical handshake messages themselves have not been tampered with. This works through several steps: the server's certificate, signed by a Certificate Authority (CA), is validated; for certain cipher suites, the `ServerKeyExchange` message is signed; and in TLS 1.3, a `CertificateVerify` message is always signed to provide explicit proof that the server possesses the private key. It is important to note that the mechanisms for encrypted data exchange, HMAC or AEAD, are not used during this initial phase.

**Second, during the encrypted data exchange phase (record layer integrity):** TLS ensures the integrity of encrypted data through Message Authentication Codes (MACs), though the specific mechanism depends on the version.&#x20;

**HMAC in TLS 1.2 (Legacy Approach)**

TLS 1.2 ensures the integrity of encrypted data using a Hash-Based MAC (HMAC). For every block of data, the sender computes an HMAC—which combines a cryptographic hash function like SHA-256 with a session-specific secret key—and appends this value to the encrypted message. The receiver independently performs the same calculation; if the computed HMAC does not match the one that was sent, it indicates the data was tampered with in transit and the connection is terminated.&#x20;

* **How it works:**
  * After the handshake, both client and server derive session keys (e.g., `client_write_MAC_key`, `server_write_MAC_key`).
  * For each encrypted record (e.g., an HTTPS request), the sender:
    1. Computes `HMAC(message, MAC_key)` using SHA-256/SHA-384.
    2. Appends the MAC to the encrypted data.
  * The receiver recomputes the HMAC and checks for a match.
* **Why HMAC?**
  * Prevents tampering even if encryption is broken (e.g., if an attacker flips ciphertext bits, the HMAC won’t match).

**Example (TLS 1.2):**

```
Encrypted_Record = AES-CBC(plaintext) + HMAC-SHA256(plaintext, MAC_key)
```

**AEAD in TLS 1.3 (Modern Approach)**

TLS 1.3 ensures the integrity of encrypted data using a modernized approach which replaces the separate HMAC function with Authenticated Encryption with Associated Data (AEAD) ciphers such as AES-GCM. AEAD algorithms integrate encryption and integrity protection into a single, efficient operation, generating a built-in authentication tag during encryption that is verified upon decryption.

* **How it works:**
  * AEAD (e.g., AES-GCM, ChaCha20-Poly1305) combines encryption + integrity in one step.
  * Instead of HMAC, the cipher itself generates an authentication tag (like a built-in MAC).
  * The receiver decrypts and checks the tag in a single operation.
* **Why AEAD?**
  * More efficient (no separate MAC computation).
  * Stronger security (resistant to certain attacks like padding oracle exploits).

**Example (TLS 1.3):**

```
Encrypted_Record = AES-GCM(plaintext)  # Includes auth tag
```

The purpose of this layer is solely to ensure that the encrypted data (e.g., web traffic) has not been altered in transit between the client and server.

**Key Differences Summarized**

| Feature                 | TLS 1.2 (HMAC)                              | TLS 1.3 (AEAD)                                    |
| ----------------------- | ------------------------------------------- | ------------------------------------------------- |
| **Integrity Mechanism** | HMAC (SHA-256, etc.) appended to ciphertext | Built-in authentication tag (e.g., GCM tag)       |
| **Encryption**          | Separate (e.g., AES-CBC) + HMAC             | Combined (e.g., AES-GCM encrypts + authenticates) |
| **Performance**         | Slightly slower (extra MAC step)            | Faster (single cryptographic operation)           |
| **Security**            | Good, but vulnerable to padding attacks     | Stronger (resists more attacks)                   |

#### III. Digital Signatures

Digital signatures are a critical component of the TLS handshake, used in messages like the server's `CertificateVerify`. The process involves a sender first generating a cryptographic hash of the handshake messages and then encrypting that hash with their private key to create a unique signature. This mechanism provides both integrity, by proving the messages were not altered, and authentication, by verifying the sender's identity. Furthermore, this process ensures non-repudiation. This means the sender cannot later deny having sent the message, as the valid signature could only have been produced by someone in possession of their unique private key.

**Summary:**

* **Hashing** underpins all three mechanisms:
  * **Fingerprints** (authentication) rely on irreversible hashes of certificates.
  * **MACs** (integrity) use hashing (+ secret keys) to detect tampering.
  * **Digital signatures** (non-repudiation) sign hashes to bind messages to identities.

***

### How SSL/TLS uses asymmetric cryptography

SSL/TLS uses asymmetric encryption (public-key cryptography) for secure key generation, digital signatures, and certificate authentication. During the initial handshake, the server provides its public key to the client within a digital certificate. The client then authenticates this certificate by verifying the signature of a trusted Certificate Authority (CA), ensuring the server's identity is legitimate.

**Key Exchange (TLS 1.2 vs. TLS 1.3)**

The use of asymmetric cryptography in key generation differs significantly between TLS 1.2 and TLS 1.3. In TLS 1.2, asymmetric encryption is used in two primary methods. The first is a direct RSA-based key exchange, where the client encrypts a pre-master secret with the server’s public key, which only the corresponding private key can decrypt. While functional, this method lacks forward secrecy, making it vulnerable if the server's private key is ever compromised. The second method uses ephemeral Diffie-Hellman (DHE or ECDHE), where asymmetric cryptography is only employed for authentication via digital signatures, while the actual key generation is performed using temporary parameters, thus ensuring forward secrecy. In contrast, TLS 1.3 mandates forward secrecy by allowing only ephemeral Diffie-Hellman (ECDHE). The server’s public key is used solely to sign the key exchange parameters rather than to encrypt them, resulting in a more efficient handshake with fewer rounds of computationally expensive asymmetric operations. This key difference—TLS 1.2’s support for both RSA and ephemeral key exchange versus TLS 1.3’s exclusive use of authenticated ephemeral key exchange—makes TLS 1.3 both more secure and faster.

In **TLS 1.2**, asymmetric encryption is used in two ways for key exchange:

1. **Direct Key Exchange (RSA-based)**
   * The client encrypts a **pre-master secret** with the server’s public key (from its certificate).
   * Only the server (with its private key) can decrypt it.
   * Used in **RSA key exchange**, but vulnerable if the server’s private key is compromised (no **forward secrecy**).
2. **Ephemeral Diffie-Hellman (DHE/ECDHE)**
   * Asymmetric cryptography is used only for **authentication** (via digital signatures).
   * The actual key exchange happens via **ephemeral (temporary) DH/ECDH**, ensuring **forward secrecy**.

In **TLS 1.3**, asymmetric encryption is used more efficiently:

* **Only Ephemeral Diffie-Hellman (ECDHE)** is allowed (forward secrecy is mandatory).
* The server’s public key (from its certificate) is used just to **sign the DH parameters** (not encrypt them).
* The handshake is faster because fewer steps rely on asymmetric crypto.

**Key Difference:**

* **TLS 1.2:** Supports both RSA key exchange (no forward secrecy) and ephemeral DH.
* **TLS 1.3:** Only ephemeral DH, with asymmetric cryptography limited to authentication (signatures).

This makes TLS 1.3 both **more secure** (always forward-secret) and **faster** (fewer round trips).

**Digital Signatures**

Asymmetric cryptography is fundamental to digital signatures, which verify the integrity and authenticity of handshake data. In this process, the server signs a critical piece of data, such as a handshake message, with its private key. The recipient then uses the sender’s public key to verify that the message was not altered and indeed originated from the claimed source. For example, in ECDHE key exchange, the server signs the ServerKeyExchange message to prove ownership of the private key associated with its certified public key.

* **Purpose:** Verify the integrity and authenticity of data.
* **How it works in SSL/TLS:**
  * The server (and optionally the client) signs a piece of data (e.g., a handshake message) with its **private key**.
  * The recipient verifies the signature using the sender’s **public key** to ensure the message was not tampered with and truly came from the claimed sender.
* **Example:** During the TLS handshake, the server signs the `ServerKeyExchange` message (in some key exchange methods like ECDHE) to prove it owns the private key matching its certificate.

**Certificate Authentication**

Asymmetric cryptography is the basis for certificate authentication, which binds a public key to a specific entity like a web server. A trusted Certificate Authority (CA) uses its own private key to digitally sign the server’s certificate, which contains the server's public key. During a connection, the client uses the CA’s public key, stored in its trust store, to validate the certificate’s signature. This process, such as when a browser connects to `https://example.com`, confirms that the certificate is authentic and has not been tampered with, establishing a chain of trust.

* **Purpose:** Bind an entity (e.g., a server) to its public key, verified by a trusted third party (CA).
* **How it works in SSL/TLS:**
  * A **Certificate Authority (CA)** signs the server’s certificate (which contains the server’s public key) using the CA’s private key.
  * The client checks the certificate’s signature against the CA’s public key (from its trust store) to ensure the certificate is valid and unaltered.
* **Example:** When you connect to `https://example.com`, your browser checks if the server’s certificate was issued and signed by a trusted CA.

**Key Differences: Digital Signatures and Certificate Authentication**

| Feature             | Digital Signatures                               | Certificate Authentication                       |
| ------------------- | ------------------------------------------------ | ------------------------------------------------ |
| **Purpose**         | Verify message integrity and sender authenticity | Verify server identity and public key binding    |
| **Signed Data**     | Handshake messages (e.g., `ServerKeyExchange`)   | The server’s certificate (public key + metadata) |
| **Signer**          | Server (or client)                               | Certificate Authority (CA)                       |
| **Verification By** | Peer (client/server)                             | Client (via CA’s public key)                     |

Why Both Are Needed:

* **Certificate Authentication** ensures you’re talking to the right entity (e.g., `example.com` and not an impostor).
* **Digital Signatures** ensure that the handshake messages exchanged weren’t modified in transit.

Analogy:

* **Certificate Auth** = Checking a government-issued ID to confirm someone’s identity.
* **Digital Signature** = That person signing a document in front of you to prove they’re the one acting.

***

### How SSL/TLS uses symmetric cryptography

Asymmetric encryption is computationally expensive, so it is only used for initial setup before switching to symmetric encryption for bulk data transfer. Once the handshake is complete, SSL/TLS switches to symmetric encryption (e.g., AES or ChaCha20) for encrypting actual application data. Symmetric encryption is used to encrypt the actual data transmitted between a client (e.g., a web browser) and a server (e.g., a website). Both parties derive the same session keys from the pre-master secret to encrypt and decrypt transmitted data efficiently. Symmetric encryption is faster than asymmetric encryption and provides confidentiality for the bulk of the communication. The keys are ephemeral, generated per session, and never reused, mitigating risks from key compromise. Integrity is further enforced using HMAC or AEAD (Authenticated Encryption with Additional Data) modes like AES-GCM.

#### Role of Symmetric Encryption in SSL/TLS

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
     * 100-1,000x faster than asymmetric cryptography for data transfer
     * Enables high-speed secure communication (e.g., video streaming, large downloads)
  4. **Cipher Modes**:
     * Authenticated Encryption (AEAD): Combines encryption + integrity (e.g., AES-GCM)
     * CBC mode (older TLS versions) with HMAC for integrity
* Key characteristics:
  * Fast processing (optimized for hardware/software)
  * Suitable for large amounts of data
  * Minimal latency impact on user experience
  * Perfect for protecting the actual content of communications

### Key takeaways <a href="#key-takeaways" id="key-takeaways"></a>

* SSL/TLS are cryptographic protocols that provide encryption, authentication, and data integrity for secure communication over a network.
  * The SSL/TLS protocols establish a secure tunnel between a client and server through an encrypted handshake.
  * The use of SSL/TLS extends far beyond HTTPS to secure email, VPNs, database connections, API communications, and much more.
  * SSL/TLS achieves the three core cryptographic security goals: Confidentiality (via encryption), Authentication (via certificates and signatures), and Integrity (via hashing and MACs).
* SSL/TLS uses hashing for fingerprint verification, Message Authentication Codes (MAC), and digital signatures.
  * Fingerprint Verification: A CA hashes a server's certificate to create a unique fingerprint, which it signs to create a trusted digital identity for authentication.
  * Message Authentication Codes (MAC): Hashing combined with a secret key (e.g., in HMAC) is used to verify that encrypted application data was not altered in transit.
  * Digital Signatures: The process of signing a hash of handshake messages provides authentication, integrity, and non-repudiation, proving a message came from the holder of the private key.
  * The specific integrity mechanism evolved from HMAC in TLS 1.2 to integrated AEAD ciphers in TLS 1.3.
* SSL/TLS uses asymmetric encryption for secure key generation, digital signatures, and certificate authentication.
  * Certificate Authentication: The client uses a CA's public key to verify the digital signature on a server's certificate, authenticating the server's identity.
  * Key Exchange: In TLS 1.2, asymmetric encryption was used either to encrypt a pre-master secret directly (RSA) or to authenticate ephemeral Diffie-Hellman parameters (DHE/ECDHE). TLS 1.3 only uses it for authentication, mandating forward-secure key exchange.
  * Digital Signatures: Asymmetric cryptography is used to sign handshake messages, proving ownership of the private key and ensuring the handshake's integrity.
* SSL/TLS uses symmetric encryption to encrypt the actual data transmitted between a client and a server.
  * Symmetric encryption is used for bulk data encryption because it is 100-1000x faster than asymmetric encryption.
  * Unique, ephemeral session keys are generated for each connection during the handshake and are never reused.
  * Modern TLS (1.3) uses Authenticated Encryption with Associated Data (AEAD) ciphers like AES-GCM, which perform encryption and integrity checking in a single, efficient operation.

### References

Ed Harmoush. (n.d.). How SSL & TLS use Cryptographic tools to secure your data - Practical TLS. Practical Networking. https://www.youtube.com/watch?v=aCDgFH1i2B0

Ferguson, N., Schneier, B., & Kohno, T. (2010). Cryptography engineering: Design principles and practical applications. Wiley.

Kaufman, C., Perlman, R., & Speciner, M. (2002). Network security: Private communication in a public world (2nd ed.). Prentice Hall.

Rescorla, E. (2018). SSL and TLS: Designing and building secure systems. Addison-Wesley Professional.

Sheffer, Y., Saint-Andre, P., & Fossati, T. (2022). RFC 9325: Recommendations for secure use of transport layer security (TLS) and datagram transport layer security (DTLS). IETF.
