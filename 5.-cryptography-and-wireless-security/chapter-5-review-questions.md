# Chapter 5 review questions

### Hashing algorithms and message integrity

**1. Explain the critical security flaw in using only a basic hash digest (e.g., SHA-256) to verify message integrity against an active attacker.**\
**Answer:** A basic hash cannot prevent malicious tampering. An active attacker (e.g., a man-in-the-middle) can modify the message, calculate a new hash of the altered message, and send both to the receiver. The receiver's verification will succeed because the new hash matches the modified message, falsely confirming integrity.

**2. What are the two specific security properties provided by an HMAC that a basic hash alone cannot provide, and what additional cryptographic element makes this possible?**\
**Answer:** HMAC provides both message integrity (assurance the message was not altered) and authenticity (assurance it came from a party possessing the shared secret key). The element that makes this possible is a cryptographic secret key, which is mixed with the message by the HMAC algorithm.

**3. Beyond the use of a shared secret key in HMAC, what is the other primary method mentioned for ensuring message integrity and authenticity, and what is its fundamental cryptographic difference?**\
**Answer:** The other method is a digital signature (e.g., using RSA or ECDSA). The fundamental difference is that digital signatures use asymmetric cryptography (a public/private key pair) instead of a single shared secret key, which also provides non-repudiation.

**4. Describe the purpose of the avalanche effect in a cryptographic hash function and why it is a necessary characteristic.**\
**Answer:** The avalanche effect ensures that any minor change to the input (even a single bit) results in a drastic, unpredictable change in the output hash. This is necessary to prevent an attacker from making calculated changes to the message that result in an identical hash, thereby hiding their tampering.

**5. A receiver needs to verify an HMAC tag attached to a message. What three specific pieces of information must they have to perform this verification?**\
**Answer:** The receiver must have: (1) the original message that was sent, (2) the exact HMAC tag that was received with it, and (3) a copy of the same shared secret key that was used by the sender to generate the tag.

### Cryptographic encryption and confidentiality

**1. List the two main components of a cryptographic encryption cipher and briefly explain the role of each.**\
**Answer:** 1) Algorithm: The set of mathematical rules and instructions used to transform the plaintext into ciphertext (e.g., the steps for "shifting letters"). 2) Key: The secret parameter that personalizes the encryption process. It ensures that even if the algorithm is known, the data cannot be decrypted without the specific key (e.g., the number of positions to shift).

**2. Describe the key difference between Data Integrity and Data Confidentiality. Name a cryptographic tool used to achieve each one.**\
**Answer:** 1) Data Confidentiality ensures that data is kept private and secret from unauthorized access. Encryption (e.g., AES) is used to achieve confidentiality. 2) Data Integrity ensures that data has not been altered or tampered with. Hash functions (e.g., SHA-256) or HMACs are used to verify integrity.

**3. What is the "key exchange problem" in symmetric encryption?**\
**Answer:** The key exchange problem is the challenge of securely transmitting the shared secret key to the intended recipient over an insecure network without it being intercepted by an attacker.

**4. In a hybrid encryption model, what is encrypted using asymmetric encryption, and what is encrypted using symmetric encryption?**\
**Answer:** 1) Asymmetric encryption is used to encrypt the randomly generated symmetric session key. 2) Symmetric encryption is used to encrypt the actual bulk data/message.

**5. Briefly explain the difference between a public key and a private key in an asymmetric cryptosystem.**\
**Answer:** 1) Public Key: Can be freely shared with anyone and is used to encrypt data or verify a digital signature. 2) Private Key: Must be kept secret by the owner and is used to decrypt data encrypted with the corresponding public key or to create a digital signature.

### Message signing using asymmetric keys

**1. The text states that message signing provides non-repudiation. What is the fundamental assumption that the property of non-repudiation relies upon?**\
**Answer:**\
Non-repudiation relies on the fundamental assumption that the sender's private key has been kept secure and is solely in the possession of the sender. If the private key is compromised or shared, the sender could legitimately deny having signed the message, as someone else could have used the key.

**2. The lesson explains that the process of creating a digital signature involves a hashing step. Why is the message hashed first, rather than signing the entire message directly with the private key?**\
**Answer:**\
Hashing the message first is done for three primary reasons: 1) Performance: Asymmetric encryption operations are computationally slow, and hashing is very fast. Signing a small, fixed-length hash is much more efficient than signing a large message. 2) Security: Some asymmetric algorithms have input size limits. 3) Compatibility: The resulting signature is a predictable, manageable size regardless of the original message's length.

**3. Differentiate between the purposes of message encryption and message signing within asymmetric cryptography.**\
**Answer:**

* Message encryption is used to provide confidentiality. It ensures that only the intended recipient can read the message by encrypting it with the recipient's public key, so that only the holder of the corresponding private key can decrypt it.
* Message signing is used to provide authentication, integrity, and non-repudiation. It proves the message came from a specific sender and was not altered by signing a hash of the message with the sender's private key, so that anyone with the sender's public key can verify it.

**4. According to the lesson, what critical problem does a Public Key Infrastructure (PKI) solve in the process of message signing?**\
**Answer:**\
PKI solves the problem of trust and secure key distribution. It answers the question: "How does the verifier (Bob) obtain the sender's (Alice's) public key with confidence that it is genuine and not a forgery from an attacker?" PKI uses digital certificates, issued by a trusted Certificate Authority (CA), to bind a public key to an identity, allowing a verifier to trust the public key they are using.

**5. The text lists common algorithms like RSA-PSS and ECDSA. What is a key practical advantage of using elliptic curve-based algorithms (like ECDSA or EdDSA) over RSA for signing?**\
**Answer:**\
A key practical advantage of elliptic curve-based algorithms (ECDSA, EdDSA) over RSA is that they provide equivalent security with significantly smaller key sizes. For example, a 256-bit ECC key provides security comparable to a 3072-bit RSA key. This leads to smaller signatures, less bandwidth usage, and faster computational performance, making them more efficient for many applications.

### Cryptographic authentication methods

**1. The text explains that a username and password combination is a form of authentication based on "something you know." Describe the process and cryptographic purpose of the server hashing the password upon account creation.**\
**Answer:**\
When a user creates an account, the server takes the plaintext password and processes it through a cryptographic hashing algorithm. This generates a unique, fixed-length string of characters (a hash digest). The server then stores only this hash in its database, not the plaintext password. The purpose is to ensure that even if the password database is stolen, an attacker cannot easily obtain the original passwords, as hashing is a one-way function that is computationally infeasible to reverse.

**2. The lesson states that a Pre-Shared Key (PSK) must be initially shared "out-of-band." What does this mean, and why is this step critical for security?**\
**Answer:**\
"Out-of-band" means the PSK is shared through a communication channel separate from the one it will be used to secure. For example, a Wi-Fi password might be told to a guest in person or printed on a receipt, not sent over the unsecured Wi-Fi network itself. This is critical because it prevents an eavesdropper from intercepting the key during the initial exchange. If the key were shared "in-band" over the untrusted network, an attacker could capture it and immediately compromise all future communications.

**3. The text outlines two methods where digital signatures can be used for authentication. Briefly describe the "challenge-response" method where Bob verifies that Alice possesses the private key for her digital certificate.**\
**Answer:**\
In this challenge-response method:

1. Bob generates a random, unique value (a "nonce" or challenge).
2. Bob encrypts this challenge using Alice's public key (from her certificate) and sends it to her.
3. Alice, who possesses the corresponding private key, decrypts the message to reveal the original challenge value.
4. Alice sends the decrypted value back to Bob.
5. Bob verifies that the value he received from Alice matches the original challenge he sent. If it matches, it cryptographically proves that Alice is the only one who could have decrypted it, thus proving her identity.

**4. Differentiate between the two primary integrity mechanisms used in a TLS 1.2 connection: one used during the handshake and one used for securing application data after the handshake.**\
**Answer:**\
The two integrity mechanisms are:

* **During the Handshake (Digital Signatures):** Integrity is provided by digital signatures. The server uses its private key to sign a hash of the handshake messages (e.g., its key exchange parameters). The client verifies this signature with the server's public key to ensure the handshake itself was not tampered with and to authenticate the server.
* **After the Handshake (HMAC or AEAD):** Integrity for the encrypted application data (e.g., web traffic) is provided by either an HMAC (a separate cryptographic checksum calculated on the ciphertext) or an AEAD cipher mode (like AES-GCM), which seamlessly combines encryption and integrity protection into a single step using the derived symmetric session key.

**5. The text explains that in a PSK system, the shared secret can be used to derive short-lived session keys. Explain the security benefit of this approach compared to using the PSK directly for encryption.**\
**Answer:**\
The key benefit is compartmentalization and forward secrecy. Using the PSK only for authentication and to derive a unique session key for each connection means that if a single session key is ever compromised, only the data from that specific session is exposed. All past and future sessions remain secure. If the long-term PSK were used directly for encryption, compromising it would allow an attacker to decrypt all past and future communications that used that key.

### The SSL/TLS handshake

**1. Explain the critical security weakness of the TLS 1.2 RSA key exchange method that led to its removal in TLS 1.3.**\
**Answer:** The RSA key exchange method lacks Perfect Forward Secrecy (PFS). If the server's long-term private RSA key is ever compromised in the future, an attacker can use it to decrypt all past recorded communications that used that key to exchange the session secret.

**2. What are the two distinct cryptographic purposes of a server's digital certificate in a TLS handshake, and how does their usage differ between TLS 1.2 (using RSA key exchange) and TLS 1.3?**\
**Answer:** The two purposes are **authentication** (proving the server's identity) and **key exchange** (securely establishing a shared secret). In TLS 1.2 with RSA, the certificate's public key is used for both purposes. In TLS 1.3, the certificate's public key is used **only for authentication** (via the `CertificateVerify` signature); key exchange is handled separately by a mandatory (EC)DHE exchange.

**3. Beyond agreeing on a TLS version, what is the most critical item negotiated in the `ClientHello` and `ServerHello` exchange, and what four algorithmic components does it define?**\
**Answer:** The most critical item negotiated is the **cipher suite**. It defines the: 1) Key exchange algorithm, 2) Authentication algorithm, 3) Bulk encryption algorithm, and 4) Message Authentication Code (MAC) algorithm.

**4. What specific handshake message in TLS 1.3 cryptographically binds the server's identity to the ephemeral key exchange, and what security threat does this prevent?**\
**Answer:** The **`CertificateVerify`** message does this. The server signs a hash of the handshake transcript (which includes the key shares) with its private key. This prevents man-in-the-middle attacks by proving that the entity that performed the key exchange is the same entity that owns the authenticated certificate.

**5. What is the primary cryptographic reason that TLS uses symmetric encryption (like AES) to encrypt application data, rather than the asymmetric encryption (like RSA) used during the handshake?**\
**Answer:** Symmetric encryption is orders of magnitude **faster and more computationally efficient** for encrypting and decrypting large volumes of data than asymmetric encryption. The handshake uses asymmetric crypto for its secure key agreement properties, but then switches to symmetric crypto for performance once the session keys are established.

### How SSL/TLS uses cryptography

**1. The text states that the TLS handshake achieves three crucial security goals. What are these three goals and what does each one provide?**\
**Answer:**\
The three security goals are:

* **Authentication:** Verifies the identity of the communicating parties, ensuring you are communicating with the legitimate server and not an impostor.
* **Encryption:** Scrambles the data exchanged between the client and server, providing confidentiality and making it unreadable to eavesdroppers.
* **Integrity:** Ensures that the data sent is the data received and has not been altered or corrupted in transit.

**2. The text explains that TLS uses hashing for three distinct mechanisms. What are these three mechanisms and what is the primary security purpose of each?**\
**Answer:**\
The three mechanisms are:

* **Fingerprint Verification:** Its primary purpose is **authentication**, using a hash of a certificate to verify the server's identity.
* **Message Authentication Codes (MAC):** Its primary purpose is **data integrity**, using a keyed hash to detect if transmitted data has been tampered with.
* **Digital Signatures:** Its primary purpose is **non-repudiation and authentication**, using an encrypted hash to bind a message to a specific sender who cannot later deny sending it.

**3. The text contrasts the integrity mechanisms in TLS 1.2 and TLS 1.3. What are the two different mechanisms used and what is a key advantage of the method used in TLS 1.3?**\
**Answer:**

* **TLS 1.2** primarily uses **HMAC** (Hash-based Message Authentication Code) for integrity, which is a separate calculation appended to the encrypted data.
* **TLS 1.3** uses **AEAD** ciphers (Authenticated Encryption with Associated Data) like AES-GCM.
* A key advantage of AEAD is that it **combines encryption and integrity checking into a single, more efficient operation** that is also resistant to certain attacks (like padding oracles) that HMAC-based constructions can be vulnerable to.

**4. The text describes a major security improvement in TLS 1.3: mandatory forward secrecy. What is forward secrecy and how is it achieved in TLS 1.3?**\
**Answer:**

* **Forward secrecy** is a property that ensures a session key remains secure even if the server's long-term private key is compromised in the future.
* In TLS 1.3, it is achieved by **allowing only ephemeral key exchange methods** (like ECDHE). The server's long-term private key is used only to sign the handshake for authentication, not to encrypt the key exchange secrets. Since the ephemeral keys are temporary and discarded after the handshake, they cannot be recovered to decrypt past sessions.

**5. The text explains that TLS switches from asymmetric to symmetric encryption after the handshake. Why is symmetric encryption used for the bulk of the communication?**\
**Answer:**\
Symmetric encryption is used because it is **computationally much faster and more efficient** (often 100-1000x faster) than asymmetric encryption. This performance advantage is critical for encrypting large volumes of application data (like web pages, videos, or file transfers) with minimal latency impact on the user experience.

### Replay attacks and anti-replay methods

**1. The text describes sequence number windowing as a core anti-replay method. What is the purpose of the receiver's "sliding window" and how does it detect a replayed packet?**\
**Answer:**\
The sliding window is a range of expected sequence numbers the receiver is willing to accept. It detects a replayed packet by checking if an incoming packet's sequence number is already marked as received within the current window. If it has already been received, the packet is identified as a duplicate and dropped.

**2. The text explains that rotating secret keys is an effective anti-replay method. How does changing the key prevent a previously captured packet from being successfully replayed?**\
**Answer:**\
Rotating the secret key changes the expected cryptographic hash (e.g., HMAC) value for all messages. A packet captured and encrypted with an old key will produce an incorrect hash value when the receiver validates it with the new, current key. This mismatch causes the replayed packet to be rejected.

**3. The text states that TLS 1.3 uses one-time-use session tickets. How does this mechanism prevent an attacker from resuming a session by replaying a captured session ticket?**\
**Answer:**\
A one-time-use session ticket can only be used for a single session resumption. If an attacker replays a captured ticket, the server will reject it because it has already been marked as used. This forces a full new handshake, preventing the attacker from resuming the old session.

**4. The text identifies that a replayed HTTPS request (like `POST /transfer?amount=1000`) threatens data integrity. Why doesn't TLS itself inherently prevent this type of replay?**\
**Answer:**\
TLS ensures the data is not modified in transit (integrity) but does not inherently add "freshness" to the application data it carries. From TLS's perspective, a perfectly replayed, unmodified request is a valid retransmission. Preventing the duplicate execution of the action (like a transfer) requires application-layer defenses.

**5. The text explains that nonces are used as an anti-replay method. What is a nonce and what property does it provide to a message to make it replay-resistant?**\
**Answer:**\
A nonce is a random number used only once. It provides the property of freshness to a message. The receiver tracks received nonces and will discard any message containing a duplicate nonce, ensuring each message is unique and not a replay of an old one.

### Wireless client authentication methods

**1. The original IEEE 802.11 standard defined Open System authentication. Describe the purpose of this method and what critical security function it lacks.**  
**Answer:** Open System authentication only validates that a client device is a valid IEEE 802.11 device capable of communicating with the protocol. It lacks any mechanism to authenticate the user's identity or verify that the client is authorized to join the network, leaving those functions to higher-layer security methods.

**2. A network administrator is explaining why WPA2-Personal is more secure than WEP, even though both use a pre-shared secret. Describe the fundamental difference in how each protocol uses its secret key.**  
**Answer:** WEP uses the static pre-shared key directly to encrypt all data packets. In contrast, WPA2-Personal uses the Pre-Shared Key (PSK) only as a starting point for the 4-Way Handshake, which generates unique, temporary session keys for encryption, keeping the master secret secure.

**3. The Wi-Fi Alliance introduced WPA in 2003 before the IEEE 802.11i amendment was finalized. Describe the specific purpose of WPA as an interim standard and the key security mechanisms it implemented from the draft 802.11i specification.**  
**Answer:** WPA served as a pre-standard stopgap to address the critical vulnerabilities of WEP immediately. It implemented the Temporal Key Integrity Protocol (TKIP) for dynamic encryption and the Michael message integrity check from the draft 802.11i specification.

**4. A technician is configuring a WPA3-Enterprise network for a government agency. To meet the highest security requirements, they must enable the 192-bit mode. Name the two specific cryptographic components this mode mandates.**  
**Answer:** The 192-bit mode mandates the use of (1) AES-256-GCMP for encryption and (2) the 256-bit GMAC for integrity protection.

**5. When configuring EAP-TLS authentication, an administrator must deploy digital certificates to both the client devices and the authentication server. Explain why this requirement for mutual certificate-based authentication is more secure than a method like PEAP that only uses a server-side certificate.**  
**Answer:** EAP-TLS requires mutual authentication, meaning both the server proves its identity to the client and the client proves its identity to the server using certificates. This is more secure than PEAP, where only the server is authenticated with a certificate, and the client authenticates with a less secure method like a username and password inside the tunnel, which can still be phished or stolen.

### Wireless privacy and integrity methods

**1. TKIP was designed as an interim solution to replace WEP. What was the single most important design constraint that shaped its development, and what specific cipher did it reuse as a result?**
**Answer:** The most important constraint was the need to function on legacy WEP hardware. As a result, TKIP continued to use the RC4 stream cipher.

**2. The text states that a simple cryptographic hash is insufficient for protecting against a malicious attacker. What specific capability does a keyed Message Authentication Code (MAC) provide that a hash alone does not?**
**Answer:** A MAC requires a secret key to generate the integrity value. This prevents a malicious attacker from forging a valid integrity check after tampering with the data, as they do not possess the key.

**3. The Counter Mode with Cipher Block Chaining Message Authentication Code Protocol (CCMP) consists of two algorithms. Name the core encryption standard it uses and the specific algorithm it employs for the Message Integrity Check (MIC).**
 **Answer:** CCMP uses the Advanced Encryption Standard (AES) for encryption and the Cipher Block Chaining Message Authentication Code (CBC-MAC) for the MIC.

**4. The Michael MIC used in WPA was an improvement over WEP's integrity check but was still vulnerable. Identify one of the key reasons why it was considered a weak Message Authentication Code (MAC).**
**Answer:** Michael was considered weak because it was vulnerable to forgery attacks. It was designed to be computationally simple enough to run on older hardware, which inherently limited its cryptographic strength.

**5. The transition from WPA2 to WPA3 introduced a new protocol for authenticated encryption. Name this protocol and state one of its cited advantages over the CCMP protocol used in WPA2.**
 **Answer:** The protocol is AES-GCMP (Galois/Counter Mode Protocol). One of its advantages is that it is more efficient (faster) than CCMP while also being considered more secure.
