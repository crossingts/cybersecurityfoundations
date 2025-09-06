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
