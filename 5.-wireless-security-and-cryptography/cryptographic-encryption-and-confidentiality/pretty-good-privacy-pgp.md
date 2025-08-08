---
hidden: true
---

# Pretty Good Privacy (PGP)

## How to encrypt your communications using PGP (GPG)

Pretty Good Privacy (PGP) is an encryption program that provides cryptographic privacy and authentication for data communication. This discussion shows you how to start exchanging encrypted messages using PGP to safeguard your privacy.

* **Introduction: PGP is darn good privacy**
* **The PGP encryption and decryption process**
* **Ensure GPG is installed**
* **Generating a new key pair**
* **Share your public key so others can encrypt emails to you**
* **Test your PGP key with encryption/decryption**
* **How to send me encrypted emails using PGP (GPG)**
* **How to send me an authenticated message**

### Introduction: PGP is darn good privacy <a href="#ember614" id="ember614"></a>

PGP (Pretty Good Privacy) is one of the most secure and widely trusted encryption systems when used correctly. First, PGP provides strong encryption via a combination of symmetric key encryption (e.g., AES, CAST5) and asymmetric encryption (e.g., RSA, ECC). Messages are encrypted with a one-time session key, which is itself encrypted with the recipient's public key. This hybrid approach is highly secure against brute-force attacks if strong algorithms (e.g., AES-256, RSA-4096) are used. Second, PGP provides message integrity (via hashing) and sender verification (via digital signatures). Finally, unlike many modern messaging apps, PGP does not rely on centralized servers that could be compromised - only the intended recipient (with the private key) can decrypt the message.

The OpenPGP standard (RFC 4880) is an open standard for encrypting and decrypting data. GnuPG (GNU Privacy Guard) or GPG is the most widely used free and open-source implementation of OpenPGP and alternative to Symantec's cryptographic software suite PGP.

### The PGP encryption and decryption process <a href="#ember617" id="ember617"></a>

User A wants to send User B an encrypted email.
