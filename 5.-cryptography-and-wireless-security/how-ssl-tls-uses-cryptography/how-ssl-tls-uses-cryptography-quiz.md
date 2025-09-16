# How SSL/TLS uses cryptography — Quiz

### How SSL/TLS uses cryptography

**1. During the TLS handshake, what is the primary purpose of the client using the Certificate Authority's (CA) public key? (Choose one answer)**\
a) To encrypt the pre-master secret before sending it to the server\
**b) To decrypt the CA's signature on the server's certificate and verify its authenticity, thus verifying the identity of the sever, i.e., authenticating the serve**\
c) To sign a hash of the handshake messages for the server to verify\
d) To generate the session keys for symmetric encryption

**2. A key security improvement in TLS 1.3 over TLS 1.2 is the mandatory use of forward secrecy. How is this achieved? (Choose one answer)**\
a) By using longer RSA keys for encrypting the pre-master secret\
b) By requiring the client to authenticate itself with a certificate in every handshake\
**c) By allowing only ephemeral key exchange methods (like ECDHE) and using asymmetric cryptography only for authentication of the server (and optionally the client)**\
d) By using HMAC-SHA384 instead of HMAC-SHA256 for integrity protection

**3. What is the fundamental reason TLS switches from asymmetric encryption to symmetric encryption after the handshake? (Choose one answer)**\
a) Symmetric encryption provides stronger authentication than asymmetric encryption\
b) Symmetric encryption algorithms are less likely to have cryptographic vulnerabilities\
**c) Symmetric encryption is significantly faster and more efficient for encrypting large volumes of data**\
d) Symmetric encryption is necessary for creating digital signatures

**4. How does the role of hashing differ between a digital signature in the handshake and an HMAC in the TLS 1.2 record layer? (Choose one answer)**\
a) There is no difference; both use SHA-256 to ensure integrity\
b) Digital signatures use hashing for speed, while HMAC uses it for encryption\
**c) Digital signatures use a hashed value that is then encrypted with a private key for non-repudiation, while HMAC uses a hash combined with a secret key for integrity without non-repudiation**\
d) HMAC provides authentication for the server, while digital signatures provide integrity for application data

**5. What is a major advantage of using an AEAD cipher like AES-GCM (as in TLS 1.3) over the HMAC method used in TLS 1.2? (Choose one answer)**\
a) AEAD ciphers allow for the use of static RSA key exchange\
**b) AEAD combines encryption and integrity into a single, more efficient operation that is resistant to padding oracle attacks**\
c) AEAD ciphers eliminate the need for any hashing algorithms during the handshake\
d) AEAD requires more round trips between the client and server to establish a connection
