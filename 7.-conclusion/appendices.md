# Appendices

### Key network security terms

**Attacks vs. Threat Vectors**:

* **Attack**: A specific malicious action (e.g., ICMP flooding).
* **Threat Vector**: The _method_ used to deliver the attack (e.g., phishing emails for credential theft).
* _Overlap_: Some terms (e.g., DNS spoofing) describe both an attack and a vector.

### Essential cryptography terms

**Encryption** is a process of transforming simple text/data, called plaintext, into unintelligible form, named as ciphertext. Decryption is the inverse process of encryption.&#x20;

A **key** is a secret string of characters or symbols that is used for the encryption/decryption of plaintext/ciphertext.&#x20;

**Cipher** is an algorithm that performs encryption/decryption. Sometimes, the term **cryptosystem** is used instead of cipher. There are two types of ciphers depending on the use of keys: symmetric and asymmetric.

**Symmetric ciphers**, also referred as secret-key ciphers, use the same key for encryption and decryption. Symmetric cryptosystems are divided into two groups: block and stream ciphers. In block ciphers, operations of encryption/decryption are performed on blocks of bits or bytes, whereas stream ciphers operate on individual bits/bytes.&#x20;

**Asymmetric ciphers**, alternatively named public-key ciphers, use two keys, one for encryption and other for decryption.&#x20;

**Cryptanalysis** is a study of techniques for “cracking” encryption ciphers, i.e., attacks on cryptosystems.

**Hashing algorithms** involves taking an input of any length and outputting a fixed-length string, called a hash. Which can be used, for example, as signatures or for data-integrity purposes.
