---
description: This section looks at how asymmetric keys can be used for message signing
---

# Message signing using asymmetric keys

This section discusses [how asymmetric keys are used](https://en.wikipedia.org/wiki/Public-key_cryptography) to perform two separate cryptographic operations: message confidentiality and message signing. We look at two real world applications involving the asymmetric key pair: real world encryption and real world signatures.

* **Confidentiality via asymmetric encryption**
* **Message signing**
* **Real world encryption**
* **Real world signatures**

### Confidentiality via asymmetric encryption

In asymmetric encryption, each user has a pair of keys: a public key (distributed openly) and a private key (kept secret). To send a secure message, you use the recipient’s public key to encrypt the message. Anyone can encrypt with a public key, making it widely accessible.

Only the recipient’s private key can decrypt the message. This ensures that only the intended recipient can read the message.

Bob wants to send an encrypted message to Alice. Bob uses Alice’s public key to encrypt the message. Bob sends the message to Alice. And Alice uses her private key to decrypt the message.

This exchange establishes confidentiality: the only possible key that could extract the message is Alice’s private key. And since Alice never shared her key (the private key is never shared), Bob knows that only Alice was able to read the message.

### Message signing

Alice wants to send a message to Bob. Alice wants Bob to know beyond a shadow of a doubt that it was her that sent the message.

Alice uses her own private key to encrypt the message. The only key that can decrypt the message is Alice’s public key which Bob has access to of course. So Bob uses Alice’s public key to decrypt the message. If Bob succeeds in decrypting the message using Alice’s public key, Bob knows for sure the message was encrypted using Alice’s private key, and so Bob know that Alice had sent the message.

This process is known as message signing. Message signing is a form of non-repudiation. It is a process of adding a digital signature to a message, which can be used to verify the sender’s identity and ensure that the message has not been tampered with.

### Real world encryption

As explained in Cryptographic encryption and confidentiality (section 2 of this chapter), asymmetric encryption is not ideal for bulk encryption. Symmetric encryption is more suited for bulk encryption but we have to find a solution to the key exchange problem.

Hybrid encryption is a solution to the key exchange problem that entails combining the strengths of both symmetric and asymmetric encryption while avoiding all their weaknesses.

Bob wants to send an encrypted message to Alice. Bob starts by randomly generating a symmetric secret key. Bob then uses Alice’s public key to encrypt the symmetric secret key. This encrypted symmetric key is sent across the wire to Alice.

Alice then uses her private key to extract the symmetric secret key that Bob sent. At this point, both Bob and Alice have an identical symmetric secret key that can be used to symmetrically encrypt as much data as they need.

Thus Bob and Alice are benefiting from the security of asymmetric encryption, with the speed and efficiency of symmetric encryption.

### Real world signatures

A hashing algorithm can be used to reduce a message of variable length to a constant, more manageable representational value.

Alice wants to sign a message to Bob. Alice runs her message through a hashing algorithm, and then encrypts the resulting digest with her own private key. Alice then sends the encrypted digest to Bob, along with the original message.

Bob then uses Alice’s public key to decrypt the digest, then he independently calculates the hash of the original message using the same hashing algorithm that Alice used to encrypt the message. Bob then compares the digests.

If they match, Bob knows that Alice must have sent the original message. Bob also knows that the message has not changed (message integrity was preserved).

For a deeper understanding of how an asymmetric algorithm works, an exploration of the math behind the RSA algorithm is discussed in the section Generating and applying an RSA key.

### References

[Ed Harmoush. (December 8, 2021). Using Asymmetric Keys. Practical Networking.](https://www.practicalnetworking.net/series/cryptography/using-asymmetric-keys/)
