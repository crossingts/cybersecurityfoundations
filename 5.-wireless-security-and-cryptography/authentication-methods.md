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

Digital certificates are the primary method of identification in use on the Internet. A digital certificate is an electronic document that binds a public key to an identity, such as a person or server. A digital certificate is used to verify the identity of the holder of the public key and to encrypt communications.

Digital certificates are used in a variety of applications, including:

* Secure sockets layer (SSL) and transport layer security (TLS): These protocols are used to secure communications over the Internet.
* Email: Digital certificates can be used to authenticate email senders and to encrypt email messages.
* File encryption: Digital certificates can be used to encrypt files and to verify the integrity of files.
* Software distribution: Digital certificates can be used to verify the authenticity of software downloads.

Digital certificates are a critical security technology that is used to protect communications over the Internet. Digital certificates are a key component of HTTPS and other security protocols.

HTTPS websites use SSL/TLS protocols to secure browsing sessions, and these protocols make heavy use of digital certificates. SSL and TLS use digital certificates to authenticate the server and to encrypt the communications.

When you visit a website that uses HTTPS, your browser will first verify the identity of the website by checking the digital certificate that is presented by the website. If the certificate is valid, your browser will then encrypt all of the communications between your computer and the website. This ensures that your communications are secure and that they cannot be intercepted by an attacker.

Digital certificates are mainly, but not exclusively, used for websites to verify that the website being accessed is legitimate. A digital certificate is a file that contains information about the website’s identity and a public key used to encrypt communication. The digital certificate is issued by a trusted Certificate Authority (CA) after verifying ownership of the domain.

While digital certificates are primarily used for websites, they also authenticate email senders (S/MIME), software publishers (code signing), and users (client certificates).

Here are some of the benefits of using digital certificates:

* They provide a secure way to verify the identity of a website or server.
* They encrypt communications, making them secure from eavesdropping.
* They can be used to sign digital documents, ensuring their authenticity and integrity.
* They can be used to authenticate users, such as when logging into a website or application.

Inside a digital certificate is a public key of an asymmetric key pair. This key is used to verify that the entity which presents the certificate is the true owner of the certificate.

A digital certificate can only be considered proof of someone’s identity if they can provide the matching private key. There are two ways this can be verified.

Alice is presenting a digital certificate to Bob. Let’s look at two methods Alice can use to provide evidence that she is in possession of the private key and so is the true owner of the digital certificate (we are authenticating Alice).

These two methods are the basis for how authentication works with digital signatures.

1\) If Alice presents Bob with her certificate, Bob can generate a random value and encrypt it with Alice’s public key. Alice should be the only person with the correlating private key, and therefore, Alice should be the only person that can extract the random value. If she can then prove to Bob that she extracted the correct value, then Bob can be assured that Alice is indeed the true owner of the certificate.

2\) Alice can encrypt a value known to both parties with her private key, and send the resulting cipher text to Bob. If Bob can decrypt it with Alice’s public key, it proves Alice must have had the correlating private key.

### References

[Ed Harmoush. (October 12, 2021). Authentication. Practical Networking.](https://www.practicalnetworking.net/series/cryptography/authentication/)
