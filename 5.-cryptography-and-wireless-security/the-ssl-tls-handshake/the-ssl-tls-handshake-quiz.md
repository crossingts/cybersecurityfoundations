# The SSL/TLS handshake — Quiz

### The SSL/TLS handshake

**1. What is the ultimate goal of the TLS handshake process? (Choose one answer)**\
a) To exchange digital certificates between the client and server\
**b) To establish a shared symmetric session key for encrypting application data**\
c) To validate the Certificate Authority's root certificate on the client machine\
d) To determine the strongest possible cipher suite supported by the client

**2. In TLS 1.3, how is the key exchange fundamentally different from the RSA method in TLS 1.2? (Choose one answer)**\
a) TLS 1.3 uses a longer RSA key for improved security\
b) TLS 1.3 uses the server's certificate public key to encrypt the pre-master secret\
**c) TLS 1.3 mandates an ephemeral Diffie-Hellman exchange, making Perfect Forward Secrecy mandatory**\
d) TLS 1.3 performs the key exchange after all authentication is complete

**3. Which TLS 1.3 handshake message does the server use to cryptographically prove it possesses the private key corresponding to its certificate? (Choose one answer)**\
a) ServerHello\
b) Certificate\
**c) CertificateVerify**\
d) Finished

**4. Why was the RSA key exchange method (where the client encrypts a secret with the server's public key) removed from TLS 1.3? (Choose one answer)**\
a) It was too slow compared to Diffie-Hellman\
b) It did not support client authentication\
**c) It lacked Perfect Forward Secrecy**\
d) It was incompatible with modern cipher suites

**5. What is a major performance benefit of the TLS 1.3 handshake compared to a full TLS 1.2 handshake? (Choose one answer)**\
a) It uses less computationally intensive algorithms\
**b) It requires only one round trip (1-RTT) to establish a secure connection**\
c) It eliminates the need for digital certificates\
d) It uses smaller key sizes for the same level of security
