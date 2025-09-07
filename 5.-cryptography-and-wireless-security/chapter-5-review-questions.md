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
