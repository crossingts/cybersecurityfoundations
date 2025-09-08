# Cryptographic authentication methods — Quiz

### Cryptographic authentication methods

**1. What is the primary cryptographic purpose of salting and hashing a password on the server? (Choose one answer)**\
a) To make the password longer and more complex for the user\
**b) To prevent an attacker who steals the password database from easily recovering the plaintext passwords**\
c) To encrypt the communication channel between the client and server\
d) To ensure the server administrators can never access the user's password

**2. During a TLS handshake using Ephemeral Diffie-Hellman (e.g., ECDHE), what is the specific function of the server's private key? (Choose one answer)**\
a) It directly encrypts the pre-master secret sent by the client\
b) It is used to decrypt the symmetric session key\
**c) It signs the server's Diffie-Hellman parameters to prove their authenticity**\
d) It generates the client's random nonce

**3. A major security limitation of using a static Pre-Shared Key (PSK) is that if it is compromised, an attacker can decrypt all communications. How do modern implementations like WPA3 mitigate this risk? (Choose one answer)**\
a) By frequently requiring users to manually change the PSK\
b) By using the PSK only for authentication, not encryption\
**c) By using the PSK to cryptographically derive unique session keys for each communication session**\
d) By transmitting the PSK over a separate, encrypted channel each time

**4. Which of the following best describes the role of a Certificate Authority (CA) in the digital certificate ecosystem? (Choose one answer)**\
a) It generates the public/private key pair for every web server\
**b) It acts as a trusted third party that cryptographically signs and vouches for the binding between a public key and a server's identity**\
c) It provides the encryption algorithms used in the TLS handshake\
d) It hosts the website whose certificate is being verified

**5. Two-Factor Authentication (2FA) requires two distinct forms of evidence from different categories. Which of the following pairs is a valid example of 2FA? (Choose one answer)**\
a) A password and the answer to a security question (both something you know)\
b) A fingerprint scan and a facial recognition scan (both something you are)\
**c) A smart card (something you have) and a PIN (something you know)**\
d) A username and a password (both something you know)
