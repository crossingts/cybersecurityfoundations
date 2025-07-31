---
description: >-
  This sections discusses how symmetric encryption (e.g., AES) and asymmetric
  encryption (e.g., RSA) can be used to protect the confidentiality of data
---

# Cryptographic encryption and confidentiality

## Learning objectives

* Develop a foundational understanding of how cryptographic encryption works
* Understand why symmetric encryption is a preferred choice for bulk data encryption

This section sheds light on how cryptographic encryption can be used to achieve data confidentiality. This discussion looks at how symmetric encryption and asymmetric encryption work—how scrambling plain text according to some mathematical logic encrypts text into cipher.

## Topics covered in this section

* **Confidentiality**
* **Symmetric encryption**
* **Asymmetric encryption**
* **Symmetric encryption vs asymmetric encryption**

### Confidentiality

Confidentiality refers to the idea of keeping data private and viewable by authorized users only. Encryption is commonly used to enforce data confidentiality.&#x20;

Plain text or clear text is data before it is encrypted. Encrypted data is called cipher text. Plain text is converted to cipher text using encryption algorithms.

hello –— encryption algorithm → lohel (cipher text)

In this example the encryption algorithm shifted the letters forward twice.

hello → ohell → lohel

This type of encryption works by scrambling the text cipher according to some mathematical function – e.g., shifting the letters forward.

In cryptographic encryption you need both an algorithm and a key.

* Algorithms provide the instructions and mathematical operations used to transform plain text into cipher text (the scrambled form). Different algorithms offer varying levels of security and are suited for different purposes. Some popular examples include AES and RSA.
* Keys act as the secret ingredients that personalize the encryption process. The algorithm uses the key to manipulate the data in a specific way, making it unreadable without the same key. Strong keys with sufficient length and randomness are crucial for resisting brute-force attacks.

In this overly simplified example (hello → lohel), “shifting the letters forward” represents the algorithm and “twice” or “two” represents the key used for that particular transformation.

A publicly known encryption algorithm (e.g., AES and RSA) is combined with a secret key to ensure strong encryption. Publicly known encryption algorithms, such as AES and RSA, are used because they have stood the test of time in terms of strength and usability. The secret key can be a randomly generated set of characters.

Industry grade encryption algorithms must be unbreakable, even with the most powerful computers. The cipher text should be completely opaque and should not provide any clues about the plain text. Only authorized/intended recipients who have the right key should have the ability to decrypt the cipher text and retrieve the original text.

Hash functions are algorithms used to generate a unique “fingerprint” of a block of data. While they scramble the data like encryption, they do not use a key for decryption. Their primary purpose is to verify data integrity, not confidentiality.

There are two types of cryptographic encryption: symmetric encryption and asymmetric encryption. Symmetric encryption uses a single shared key for both encryption and decryption. Both message sender and receiver must securely keep this key secret.

Asymmetric encryption uses two different keys for the encryption and decryption of data: a public key and a private key. Anyone can use the public key to encrypt data. However, only the private key can decrypt it. This offers enhanced security as the private key remains confidential.

Encryption finds its application in various scenarios, ensuring data confidentiality:

* **Data storage:** Sensitive data like financial records and medical information are often stored encrypted on personal devices and servers. Even if attackers access storage, they’ll only see scrambled gibberish without the decryption key.
* **Data transmission:** When sending confidential information over unsecure networks like the Internet, encryption protects it from eavesdropping. For example, HTTPS protocol uses encryption to secure online transactions and communication.
* **Email and messaging:** Secure email and messaging services encrypt messages during transmission (and sometimes during storage), guaranteeing confidentiality even if intercepted.
* **Cloud storage:** Cloud storage providers often offer encryption options to protect data uploaded to their servers.

Benefits of data confidentiality through encryption:

* **Prevents unauthorized access:** Only authorized individuals with the key can decrypt and access the data, mitigating unauthorized data breaches and leaks.
* **Improves data privacy:** Encrypted data remains private even if exposed, protecting sensitive information from prying eyes.
* **Boosts trust and security:** Using encryption demonstrates a commitment to data security, building trust with users and partners.

### Symmetric encryption

Symmetric encryption is an encryption scheme that encrypts and decrypts using the same secret key. Here is a simple example of symmetric encryption.

hello → khoor

Using a rudimentary symmetric encryption algorithm of “pushing letters forward” and a secret key of 3, we converted the plain text hello to the cipher text khoor.

If we know the encryption algorithm and secret key used in the encryption process, we can apply them in reverse to decrypt khoor back to hello.

khoor → hello

Here is another example.

66 → 462 (66 x 7)

Here, a symmetric encryption algorithm of multiplication and a secret key of 7 were used. To decipher the text, we inverse the operation. We divide 462 by 7. The key point here is that we used the same secret key to encrypt and decrypt the text.

The encryption algorithm is typically and ideally publicly known. So the strength of the encryption practically rests on the strength of the secret key. Longer and more random keys are considered more secure.

**Common symmetric encryption algorithms:**

| **Algorithm** | **Key size** |
| ------------- | ------------ |
| DES           | 56 bits      |
| 3DES          | 168 bits     |
| AES           | 128 bits     |
| AES192        | 192 bits     |
| AES256        | 256 bits     |

2^bits value (key size) gives us the maximum possible combination of numbers for a given key. For example, 2^56 gives us 72,057,594,037,927,936 or 72 quadrillion different combinations. A 128 bit key gives us 340,282,366,920,938,463,463,374,607,431,768,211,456 different possible values (340 undecillion).

### Asymmetric encryption

Asymmetric encryption uses different keys to encrypt and decrypt data. Here is a simple example of asymmetric encryption.

hello –— asymmetric encryption (key = 5) → mjqqt

The plain text hello was encrypted with an asymmetric encryption algorithm of pushing letters forward and a secret key of 5.

To decrypt mjqqt, we push the letters forward 21 more times (let’s pretend there are only lower case letters in the alphabet, for a total of 26 possible characters).

mjqqt –— asymmetric decryption (key = 21) → hello

This just demonstrates the basic idea of asymmetric encryption, that two different keys are used in encryption and decryption. In this example, moving letters backwards by 5 would decrypt the message, but in real asymmetric encryption attempting to reuse the secret key (applying it backward or forward) would only further scramble the message.

That said, our example invokes an important concept in asymmetric encryption: asymmetric keys are mathematically linked. What one key encrypts, only the other key can decrypt. In our example, if we used key 21 to encrypt hello, we can decrypt the cipher with a key of 5.

One of the key pair is private, never shared with anyone else. This is the private key. The other key is the public key, and it is public. Each key can be used in different ways to achieve different security features.

#### Confidentiality via asymmetric encryption

In asymmetric encryption, you use the recipient’s public key to encrypt a message to them. Anyone can encrypt with a public key. Only the recipient’s private key can decrypt the message. This ensures that only the intended recipient can read the message.

Bob wants to send an encrypted message to Alice. Bob uses Alice’s public key to encrypt the message. Bob sends the message to Alice. And Alice uses her private key to decrypt the message.

This exchange establishes confidentiality: the only possible key that could extract the message is Alice’s private key. And since Alice never shared her key (the private key is never shared), Bob knows that only Alice was able to read the message.

### Symmetric encryption vs asymmetric encryption

Why symmetric encryption is a preferred choice for bulk data encryption:

* In symmetric encryption, the cipher text is the same size as the plain text (original data).
* The math involved in symmetric encryption is relatively simpler and less CPU resource intensive. So more data can be encrypted in less time with less CPU usage.

On the downside, symmetric encryption presents a “key exchange problem”, as the secret key must exist in two places, with the sender and with the receiver. Several solutions exist to the key exchange problem (how do we get the key securely from one party to the other?).

Symmetric encryption is sometimes considered less secure than asymmetric encryption because of a higher exposure risk. The most significant benefit to using asymmetric encryption is that the private key never needs to be shared. Hence asymmetric encryption can be regarded as more secure than symmetric encryption.

**Hybrid encryption**

As noted, asymmetric encryption is not ideal for bulk encryption. Symmetric encryption is more suited for bulk encryption but we have to find a solution to the key exchange problem. **Hybrid encryption** is a solution to the **key exchange problem** that entails combining the strengths of both symmetric and asymmetric encryption while avoiding all their weaknesses.

Bob wants to send an encrypted message to Alice. Bob starts by randomly generating a symmetric secret key. Bob then uses Alice’s public key to encrypt the symmetric secret key. This encrypted symmetric key is sent across the wire to Alice. Alice then uses her private key to extract the symmetric secret key that Bob sent. At this point, both Bob and Alice have an identical symmetric secret key that can be used to symmetrically encrypt as much data as they need.

Thus Bob and Alice are benefiting from the security of asymmetric encryption, with the speed and efficiency of symmetric encryption.

### Key takeaways

* Symmetric encryption uses a single shared key for both encryption and decryption
* Asymmetric encryption uses two different keys for the encryption and decryption
* In asymmetric encryption, you use the recipient’s public key to encrypt a message to them. Only the recipient’s private key can decrypt the message
* Symmetric encryption is a preferred choice for bulk data encryption
* Hybrid encryption is a solution to the key exchange problem

### References

[Ed Harmoush. (October 12, 2021). Confidentiality. Practical Networking.](https://www.practicalnetworking.net/series/cryptography/confidentiality/)

[Ed Harmoush. (October 12, 2021). Asymmetric Encryption. Practical Networking.](https://www.practicalnetworking.net/series/cryptography/asymmetric-encryption/)

[Ed Harmoush. (December 15, 2015). Symmetric Encryption. Practical Networking.](https://www.practicalnetworking.net/series/cryptography/symmetric-encryption/)
