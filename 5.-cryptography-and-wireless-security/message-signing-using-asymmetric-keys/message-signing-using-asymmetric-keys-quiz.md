# Message signing using asymmetric keys — Quiz

### Message signing using asymmetric keys

**1. What is the primary cryptographic function used to ensure that a message has not been altered before it is signed? (Choose one answer)**\
a) Encryption with the sender's public key\
b) **Generation of a cryptographic hash**\
c) Encryption with the recipient's private key\
d) Decryption with the sender's public key

**2. For message signing, which key does the sender use to create the digital signature? (Choose one answer)**\
a) The recipient's public key\
b) The recipient's private key\
c) **The sender's private key**\
d) The sender's public key

**3. If Bob successfully verifies a message signature using Alice's public key, which of the following security properties is NOT guaranteed? (Choose one answer)**\
a) Message Integrity\
b) Authentication of the sender\
c) **Confidentiality of the message**\
d) Non-repudiation

**4. The lesson states that the process of "encrypting the hash" is technically not classic encryption. Why is this distinction important? (Choose one answer)**\
a) Because it uses a different mathematical operation that is impossible to reverse.\
b) **Because the goals of signing (authentication/integrity) are different from the goals of encryption (confidentiality).**\
c) Because only hashing algorithms are used, not encryption algorithms.\
d) Because it requires the use of a symmetric key instead of an asymmetric key.

**5. Which of the following algorithms is explicitly mentioned in the lesson as being deprecated and should be considered legacy? (Choose one answer)**\
a) RSA-PSS\
b) ECDSA\
c) EdDSA\
**d) DSA**
