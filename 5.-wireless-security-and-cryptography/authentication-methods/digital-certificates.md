# Digital certificates

Digital certificates are used to prove the identity of the holder of the certificate. Digital certificates are mainly, but not exclusively, used for websites to verify that the website being accessed is legitimate. Entities that want a certificate, for example a company with a website, send a CSR (certificate signing request) to a CA (certificate authority) which will generate and sign the certificate.

While digital certificates are primarily used for websites, they also authenticate email senders (S/MIME), software publishers (code signing), and users (client certificates).

It is not uncommon for website hosting platforms to offer free SSL certificates to their clients. By offering “free SSL”, a hosting platform likely refers to providing free digital certificates and the associated encryption of a website traffic.

* Digital Certificate: A file containing information about the website’s identity and a public key used to encrypt communication. The digital certificate is issued by a trusted Certificate Authority (CA) after verifying ownership of the domain.
* SSL/TLS Encryption: This protocol uses the public key from the digital certificate to encrypt data sent between the website and visitors’ browsers. This ensures confidentiality and integrity of the information exchanged.

SSL/TLS secures web traffic between a client and a server through a process called the TLS handshake. Here’s a breakdown of the key steps in TLS 1.2:

* Initiation: The client initiates the handshake by sending a “Client Hello” message to the server. This message specifies the supported TLS versions and encryption algorithms (cipher suites).
* Server Response: The server replies with a “Server Hello” message containing its chosen TLS version, cipher suite, and a digital certificate. This certificate holds the server’s public key and identifies a trusted Certificate Authority (CA) that issued it.
* Client Verification: The client verifies the certificate by checking its validity period, CA authenticity, and domain name match. If everything checks out, the client trusts the server’s identity.
* RSA-Based Key Exchange: Both sides create a secret session key. The client generates a random secret value that will act as the basis for the session key. The client encrypts this random secret value using the server’s public key obtained from the certificate. Only the server possesses the corresponding private key for its public key. The server uses this private key to decrypt the message from the client, revealing the random secret value. Both the client and server use the same random secret value to derive the final secret session key.
* Secure Connection and Data Exchange: With the shared session key, both client and server can now encrypt all transmitted data using symmetric encryption (faster than asymmetric encryption used for key exchange). This ensures data confidentiality – even if intercepted, it appears scrambled.

Modern TLS 1.3 simplifies the TLS handshake process by reducing round trips and eliminating some steps (e.g., certificate-based key exchange is more direct), offering faster, more secure connections.

When a hosting platform offers free SSL, it is essentially saying it will generate and install a free digital certificate for the domain, and configure the server to use SSL/TLS encryption with the certificate.

When you access a website, modern browsers display a lock key symbol usually to the left of the url field to indicate that the website is secure and has a valid certificate. You should be able to inspect the certificate if you click on the symbol.
