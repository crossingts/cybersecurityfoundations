# SSL/TLS handshake introduction/background

#### **"SSL/TLS Handshake" vs "TLS Handshake" - Are They Synonyms?**

Yes, in most modern contexts, they refer to the same process. However, there are historical and technical distinctions:

* **SSL (Secure Sockets Layer)** was the original protocol developed by Netscape in the 1990s (SSL 1.0, 2.0, 3.0).
* **TLS (Transport Layer Security)** is the standardized, more secure successor (TLS 1.0, 1.1, 1.2, 1.3).
* Today, **TLS is the actual protocol in use**, but due to SSL's historical dominance, people still say **"SSL/TLS"** out of habit.

#### **Why Are They Often Coupled as "SSL/TLS"?**

1. **Branding & Familiarity** – "SSL" became a household term (e.g., "SSL certificates"), even though TLS replaced it.
2. **Backward Compatibility** – Some systems/interfaces still refer to SSL for legacy support (though TLS is enforced).
3. **Marketing & Documentation** – Many vendors and guides use "SSL/TLS" to avoid confusion, even when discussing modern TLS.

#### **What is SSL?**

* Developed by Netscape in the mid-1990s.
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

#### **Should You Say "SSL" or "TLS"?**

* **Technically**: Use "TLS" (since SSL is obsolete).
* **Practically**: "SSL/TLS" is fine for broad discussions (e.g., certificates, libraries like OpenSSL).
* **For security**: Disable SSL entirely and enforce **TLS 1.2+**.

#### **The Handshake (TLS Example)**

A simplified **TLS 1.3 handshake** (modern standard):

1. **Client Hello** → Supported cipher suites, TLS version.
2. **Server Hello** → Chooses cipher, sends certificate.
3. **Key Exchange** → Ephemeral keys (ECDHE, etc.).
4. **Finished** → Encrypted communication begins.

(SSL handshakes were similar but less efficient and secure.)

#### **Conclusion**

* **TLS is the current protocol**; SSL is deprecated.
* **"SSL/TLS" persists due to legacy terminology**, but always aim for **TLS 1.2 or 1.3** in practice.
* When discussing handshakes, **"TLS handshake" is more accurate**, but "SSL/TLS handshake" is widely understood.

***

#### **TLS 1.3 Handshake Explained (Simplified & Secure)**

Below is a step-by-step breakdown of the TLS 1.3 handshake with a **simplified workflow**.

SSL/TLS secures web traffic between a client and a server through a process called the TLS handshake. Here’s a breakdown of the key steps in TLS 1.3:

***

#### **Step-by-Step TLS 1.3 Handshake**

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

#### **TLS 1.3 vs. TLS 1.2 Key Differences**

| Feature                | TLS 1.2                            | TLS 1.3                            |
| ---------------------- | ---------------------------------- | ---------------------------------- |
| **RTTs (Round Trips)** | 2                                  | 1 (0 with 0-RTT\*)                 |
| **Key Exchange**       | Multiple steps (ServerKeyExchange) | Built into Client/Server Hello     |
| **Forward Secrecy**    | Optional                           | Always On                          |
| **Encryption Start**   | After handshake                    | Partially encrypted early          |
| **Obsolete Ciphers**   | Supports weak ones (RSA, RC4)      | Removed (only modern AEAD ciphers) |

📌 \*0-RTT (Zero Round Trip Time Resumption): Allows instant reconnection for returning clients (but risks replay attacks).\*

***

#### **TLS 1.3 Handshake Workflow (Diagram)**

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

#### **Why TLS 1.3 is Better**

✅ **1-RTT Handshake** (vs. 2 in TLS 1.2).\
✅ **Stronger Security** (no RSA key exchange, only forward-secure methods).\
✅ **Simpler & Faster** (removes obsolete features).\
⚠️ **0-RTT tradeoff**: Faster but vulnerable to replay attacks (mitigated by limiting 0-RTT data).

***

#### **Final Notes**

* TLS 1.3 is now the **default in modern browsers & servers**.
* Most free certificates (Let’s Encrypt) support TLS 1.3.
* Wireshark/`openssl s_client` can help debug handshakes.
