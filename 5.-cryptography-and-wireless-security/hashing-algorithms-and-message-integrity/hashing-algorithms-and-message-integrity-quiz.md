# Hashing algorithms and message integrity — Quiz

### Hashing algorithms and message integrity

**1. What is the primary purpose of a hashing algorithm in the context of message integrity? (Choose one answer)**\
a) To encrypt the message so it cannot be read\
**b) To generate a fixed-size fingerprint that uniquely represents the message**\
c) To compress the message for faster transmission\
d) To authenticate the identity of the sender

**2. Which characteristic of an industry-grade hashing algorithm ensures that even a tiny change in the input (e.g., changing one bit) produces a completely different hash output? (Choose one answer)**\
a) Fixed-length output\
b) Pre-image resistance\
**c) The avalanche effect**\
d) Collision resistance

**3. Why is a basic hash digest (e.g., a SHA-256 hash sent alongside a message) alone insufficient for ensuring integrity against a malicious attacker? (Choose one answer)**\
a) The hash is always the same length, which reveals the message size\
b) An attacker can reverse the hash to discover the original message\
**c) An attacker can modify the message and generate a new valid hash for it**\
d) The hash algorithm might produce collisions too easily

**4. HMAC provides which two security properties that a basic hash does not? (Choose one answer)**\
a) Encryption and non-repudiation\
b) Confidentiality and availability\
**c) Integrity and authenticity**\
d) Compression and speed

**5. What is the fundamental cryptographic difference between HMAC and a digital signature? (Choose one answer)**\
a) HMAC is faster, but digital signatures are slower\
**b) HMAC uses a shared secret key, while digital signatures use public/private key pairs**\
c) HMAC provides encryption, while digital signatures only provide authentication\
d) HMAC is broken, while digital signatures are secure
