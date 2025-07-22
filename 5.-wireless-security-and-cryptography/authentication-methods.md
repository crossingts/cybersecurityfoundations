---
description: >-
  This section discusses three common methods of authentication: username and
  password, Pre-Shared Keys (PSKs), and digital certificates
---

# Authentication methods

This section discusses three common methods of authentication: username and password, and two other common [cryptographic authentication methods](https://www.bu.edu/tech/about/security-resources/bestpractice/auth/), Pre-Shared Keys (PSKs) and digital certificates.

* **Username and password**
* **Pre-Shared Key (PSK)**
* **Digital certificates**

### Username and password

Authentication refers to the idea of verifying an identity. You can authenticate an identity with:

1\) Something you know, for example, a password/user name combination.

2\) Something you have, for example, an ATM card or an employee badge. For example, many websites send a random code to your phone via SMS when you are trying to log in, forcing you to have possession of your phone to log in. This is also the same concept behind the various authentication tokens. If you can provide the code the server is expecting, then you must have had the token.

3\) Something you are. This category refers to various types of bio-metric identification technologies, such as fingerprint scanners, retina scanners, hand-print scanners, facial recognition, and voice recognition technologies.

Commonly, a username and password are used to authenticate a user to a server. A user of an app/service creates a unique username and password to access a service from a server.

The password can be scrambled (hashed) either on the users’ device or on the server they are connecting to. The hashing process can happen in two places: on the client (e.g., a smartphone) or on a server (e.g., an Amazon AWS server).

The process of password hashing on a server entails:

* The user enters their username and password into the website’s login form.
* The website sends the username and password to the server.
* The server hashes the password using a secure hashing algorithm.
* The server stores the hash of the password in its database.
* When the user logs in again, the website sends the username and password to the server.
* The server hashes the password that the user entered and compares it to the hash that is stored in its database. If the hashes match, the user is logged in.

This process ensures that the server never knows the user’s plain text password. Even if an attacker were to steal the database, they would not be able to use the passwords. The password itself is never stored, only the digest of the password, which is impossible to decrypt.

The process of password hashing on the client side entails:

* User Input – The user enters their password on the device (e.g., smartphone, laptop).
* Client-Side Hashing – The device hashes the password using a secure algorithm (e.g., bcrypt, Argon2, SHA-256).
* Salt Addition (Optional) – A unique salt may be added to the password before hashing to prevent rainbow table attacks.
* Transmission – The hashed password (not the plaintext) is sent over a secure connection (HTTPS) to the server.
* Server Storage – The server stores the hashed password (or may perform additional hashing if needed).

This way of hashing ensures the plaintext password never leaves the device, which reduces the risk of exposure in transit or server breaches. Note that the server may still perform additional hashing for extra security.

**Two-factor authentication (2FA)**

The user is identified by using (combining) two authentication methods from the noted three methods (something you know, something you have, and something you are). A common 2FA combination is a password and an authentication code via SMS.

### Pre-Shared Key (PSK)

A PSK is a shared secret that is used to authenticate two parties. It is used in a variety of applications, such as wireless networks, VPNs, and file encryption.

In a PSK-based system, PSKs must be initially shared out-of-band. The two parties must share the same PSK. This can be done manually, such as by exchanging the PSK over a secure channel, or it can be done automatically, such as by using a secure network configuration protocol.

Once the two parties have shared the PSK, they can use it to encrypt and decrypt messages. This is done by using a symmetric encryption algorithm, such as AES or DES.

PSKs are a simple and effective way to authenticate two parties. However, they have some drawbacks. One drawback is that the PSK must be kept secret. If the PSK is compromised, then the two parties’ communications can be decrypted by an attacker.

For better security, the PSK can be used to derive short-lived session keys. The client and server each generate and exchange a random number ("nonce") and each use each other's nonce to independently derive the session key using a key derivation function. All communication in this session uses that key. After the session ends, the key is thrown away. Thus each session has its unique key. If both client and server correctly derive the same session key, then each had the same PSK. If either side fails to generate the correct key, authentication fails.

In IPsec, for example, both parties generate random nonces and exchange them during the handshake. Since both parties use the same inputs (PSK + nonce₁ + nonce₂), they will compute identical session keys. This allows mutual authentication—if the server’s derived key matches the client’s, both parties confirm they share the same PSK without ever transmitting it directly.

Because each session uses fresh nonces, an attacker who intercepts a token cannot reuse it in future sessions. Even with a captured token, they cannot reverse-engineer the PSK or spoof authentication.

### Digital certificates

Digital certificates are a critical security technology that is used to protect communications over the Internet. Digital certificates are the primary method of identification on the Internet. A digital certificate is an electronic document that binds a public key to an identity, such as a company or a server. A digital certificate is used to verify the identity of the holder of the public key (e.g., a server) and optionally the client, to encrypt communications by facilitating secure key exchange (e.g., via the TLS handshake), and to ensure data integrity (through digital signatures).

Digital certificates are used in a variety of applications, including:

* Secure sockets layer (SSL) and transport layer security (TLS): Digital certificates are used in the TLS handshake, helping to secure web traffic by authenticating servers, encrypting data, and protecting data integrity.
* User Authentication: Client certificates authenticate users (e.g., logging into secure systems).
* Email Security (S/MIME): Digital certificates can be used to authenticate email senders and to encrypt email messages.
* File encryption: Digital certificates can be used to encrypt files and to sign digital documents, ensuring their authenticity and integrity.
* Software distribution: Digital certificates can be used to verify the authenticity of software downloads.

**Benefits of using digital certificates:**

* **Authentication/Trust**: Confirms the identity of websites, software, or users.
* **Encryption**: Protects data in transit (e.g., HTTPS, email).
* **Integrity**: Ensures files or messages are unaltered (via digital signatures).

The digital certificate is issued by a trusted Certificate Authority (CA) after verifying ownership of a domain. A digital certificate is a file that contains information about a website’s identity (e.g., domain name, and optionally organization details), a public key tied to the identity of the domain name holder of an asymmetric key pair (used for encryption, e.g., in key exchange, and for verifying signatures, to prove the digital certificate holder controls the corresponding private key), the CA’s digital signature (created by hashing the certificate data and encrypting the hash with the CA’s private key), and a validity period (expiration date).

#### The TLS handshake and its purposes

The **TLS handshake** is a process that establishes a secure, encrypted connection between a client (e.g., a web browser) and a server (e.g., a website). Its primary purposes are:

1. **Authentication** – Verifies the server’s identity (and optionally the client’s) using **digital certificates**.
2. **Key Exchange** – Securely negotiates a **shared session key** for symmetric encryption of communications using **digital certificates**.
3. **Cipher Suite Agreement** – Determines the encryption algorithms (e.g., AES, ChaCha20) and hash functions (e.g., SHA-256) to be used.
4. **Secure Session Establishment** – Ensures all further communication is encrypted and tamper-proof.

After the handshake, both the client and server use the derived symmetric session key to encrypt all transmitted data and to verify integrity using HMAC or AEAD modes like AES-GCMP.

#### Simplified Steps in a TLS Handshake

1. **Client Hello** – The client sends supported TLS versions, cipher suites, and a random number (nonce).
2. **Server Hello** – The server responds with its chosen cipher suite, a random number (nonce), and its **digital certificate** (containing its public key).
3. **Key Exchange** – The client verifies the certificate against trusted CAs, then generates a **pre-master secret (PMS)**. The client computes a symmetric key using the pre-master secret, its random number, and the server's random number. The client sends the server the pre-master secret encrypted with the server’s public key
4. **Session Key Generation** – Both sides compute the same **symmetric session key** using the random numbers and pre-master secret.
5. **Secure Communication** – All further data is encrypted with the shared/computed session key.

The symmetric session key (derived during the handshake) is used alongside a symmetric encryption algorithm (e.g., AES-256, ChaCha20) to encrypt the actual application data (e.g., HTTP requests, form submissions).

In the PSK handshake, instead of a PMS, the client and server start with a pre-shared key.

#### **Key Exchange (Establishing a Session Key) in the TLS Handshake**

The public key in the certificate is used in one of two ways, depending on the **key exchange algorithm**:

**A. RSA Key Exchange (Older, no forward secrecy)**

1. The client generates a **pre-master secret** (a random symmetric key).
2. The client encrypts it with the **server’s public key** (from the certificate).
3. The server decrypts it using its **private key** (only the server has this).
4. Both sides derive the same **session key** from the pre-master secret.

**B. Ephemeral Diffie-Hellman (Modern: ECDHE or DHE)**

1. The server’s certificate is still used to **authenticate** the server.
2. Instead of encrypting the pre-master secret directly, **Diffie-Hellman (DH)** is used:
   * The server sends its **DH parameters** (signed by its private key for authenticity).
   * The client and server exchange **ephemeral (temporary) DH keys**.
   * They compute the same **shared secret** independently (never transmitted).
3. This provides **forward secrecy** (even if the server’s private key is later compromised, past sessions remain secure).

#### **Why the TLS Handshake Matters**

* Prevents **eavesdropping** (via encryption).
* Stops **man-in-the-middle (MITM) attacks** (via certificate verification).
* Ensures **data integrity** (no tampering in transit).

**How Digital Certificates Work in HTTPS**

HTTPS uses SSL/TLS protocols to secure browsing sessions. When you visit `https://example.com`, the TLS handshake happens before any data is sent, securing your login or payment details.

When you visit a website that uses HTTPS, your browser will first verify the identity of the website by checking the digital certificate that is presented by the website server. If the certificate is valid, if a trusted Certificate Authority (CA) issued it, your browser will use the **public key** in the certificate to establish an encrypted connection to encrypt all of the communications between your computer and the website.&#x20;

**Role of Certificate Authorities (CAs)**

* CAs verify domain ownership before issuing certificates.
* Examples: DigiCert, Let’s Encrypt, Sectigo.
* Browsers and operating systems maintain a **list of trusted CAs**.

**Role of Digital Certificates in the SSL/TLS Handshake**

Digital certificates serve three main purposes in the SSL/TLS handshake process:

**A. Authentication (Identity Verification)**

* A digital certificate (also called an **SSL/TLS certificate**) is issued by a trusted **Certificate Authority (CA)** (e.g., DigiCert, Let’s Encrypt).
* It binds a **public key** to an entity (e.g., a domain name, company, or server), proving that the server is legitimate.
* When a client connects to a server, the server presents its certificate, and the client verifies it against trusted CAs.

**B. Key Exchange (Secure Encryption Setup)**

* The certificate contains a **public key** used in the **TLS handshake** to establish an encrypted session.
* The client uses this public key to:
  * Encrypt a **pre-master secret** (in RSA-based key exchange).
  * Verify the server’s identity (in **ECDHE** key exchange).
* This ensures that only the legitimate server (with the matching private key) can decrypt the data.

**C. Trust Establishment**

* Certificates are signed by CAs, which act as **trusted third parties**.
* Browsers and operating systems come with a **pre-installed list of trusted root certificates**.
* If the certificate is valid and trusted, the SSL/TLS connection proceeds securely.

#### **Types of SSL/TLS Certificates**

* **Domain Validated (DV)** – Basic encryption, checks domain ownership.
* **Organization Validated (OV)** – Verifies business identity.
* **Extended Validation (EV)** – Highest trust, shows company name in the browser.
* **Wildcard & Multi-Domain** – Covers multiple subdomains or domains.

#### **How SSL/TLS Uses Digital Certificates**

1. **Handshake Phase**:
   * Client sends a `ClientHello`.
   * Server responds with its **digital certificate** + public key.
   * Client verifies the certificate (checks CA, expiry, domain match).
2. **Key Exchange**:
   * Client generates a session key, encrypts it with the server’s public key.
   * Server decrypts it with its **private key** (only the server has this).
3. **Secure Session**:
   * Symmetric encryption (AES) is used for fast, secure data transfer.

**Without a Certificate?**

* No authentication → Risk of **man-in-the-middle (MITM) attacks**.
* Browsers show **"Not Secure"** warnings (e.g., self-signed certs).

**The mechanisms of action of authentication methods**

A digital certificate can only be considered proof of someone’s identity if they can provide the matching private key. There are two ways this can be verified.

Alice is presenting a digital certificate to Bob. Let’s look at two methods Alice can use to provide evidence that she is in possession of the private key and so is the true owner of the digital certificate (we are authenticating Alice).

These two methods are the basis for how authentication works with digital signatures.

1\) If Alice presents Bob with her certificate, Bob can generate a random value and encrypt it with Alice’s public key. Alice should be the only person with the correlating private key, and therefore, Alice should be the only person that can extract the random value. If she can then prove to Bob that she extracted the correct value, then Bob can be assured that Alice is indeed the true owner of the certificate.

2\) Alice can encrypt a value known to both parties with her private key, and send the resulting cipher text to Bob. If Bob can decrypt it with Alice’s public key, it proves Alice must have had the correlating private key.

### References

[Ed Harmoush. (October 12, 2021). Authentication. Practical Networking.](https://www.practicalnetworking.net/series/cryptography/authentication/)
