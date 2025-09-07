---
description: >-
  This sections discusses how symmetric encryption (e.g., AES) and asymmetric
  encryption (e.g., RSA) can be used to protect the confidentiality of data
---

# Cryptographic encryption and confidentiality

## Learning objectives

* Develop a foundational understanding of how cryptographic encryption works
* Understand why symmetric encryption is a preferred choice for bulk data encryption

This section sheds light on how cryptographic encryption can be used to achieve data confidentiality. This discussion looks at how scrambling plain text according to some mathematical logic encrypts plain text into cipher text. We will dissect the core principles, algorithms, and practical applications of both symmetric encryption (e.g., AES) and asymmetric encryption (e.g., RSA). The lesson will compare their strengths and weaknesses, explain why symmetric encryption is favored for bulk data processing, and introduce hybrid encryption as a solution to the key exchange problem, combining the best attributes of both cryptographic systems.

## Topics covered in this section

* **Encryption algorithms**
* **Symmetric encryption**
* **Asymmetric encryption**
* **Symmetric encryption vs asymmetric encryption**

### Encryption algorithms

There are two types of cryptographic encryption: symmetric encryption and asymmetric encryption. Symmetric encryption uses a single shared key for both encryption and decryption. Both message sender and receiver must securely keep this key secret. Asymmetric encryption uses two different keys for the encryption and decryption of data: a public key and a private key. Anyone can use the public key to encrypt data. However, only the private key can decrypt it. This offers enhanced security as the private key remains confidential.

Encryption is commonly used to enforce data confidentiality. Confidentiality refers to the idea of keeping data private and viewable by authorized users only. Encryption finds its application in various scenarios:

* **Data storage:** Sensitive data like financial records and medical information are often stored encrypted on personal devices and servers. Even if attackers access storage, they’ll only see scrambled gibberish without the decryption key.
* **Data transmission:** When sending confidential information over unsecure networks like the Internet, encryption protects it from eavesdropping. For example, HTTPS protocol uses encryption to secure online transactions and communication.
* **Email and messaging:** Secure email and messaging services encrypt messages during transmission (and sometimes during storage), guaranteeing confidentiality even if intercepted.
* **Cloud storage:** Cloud storage providers often offer encryption options to protect data uploaded to their servers.

Benefits of data confidentiality through encryption:

* **Prevents unauthorized access:** Only authorized individuals with the key can decrypt and access the data, mitigating unauthorized data breaches and leaks.
* **Improves data privacy:** Encrypted data remains private even if exposed, protecting sensitive information from prying eyes.
* **Boosts trust and security:** Using encryption demonstrates a commitment to data security, building trust with users and partners.

#### A simplified explanation of encryption

Plain text or clear text is data before it is encrypted. Encrypted data is called cipher text. Plain text is converted to cipher text using encryption algorithms.

hello –— encryption algorithm → lohel (cipher text)

In this example the encryption algorithm shifted the letters of the plain text forward twice.

hello —x1→ ohell —x1→ lohel

This type of encryption works by scrambling the plain text according to some mathematical function — shifting the letters forward, in this example. In cryptographic encryption, you need both an algorithm and a key.

* Encryption algorithms (such as AES or RSA) provide the instructions and mathematical operations used to transform plain text into cipher text (the scrambled form). Different algorithms offer varying levels of security and are suited for different purposes.&#x20;
* Keys act as the secret ingredients that personalize the encryption process. The algorithm uses the key to manipulate the data in a specific way, making it unreadable without the same key. The secret key can be a randomly generated set of characters. Strong keys with sufficient length and randomness are crucial for resisting brute-force attacks.

In the overly simplified example hello → lohel, “shifting the letters forward” represents the algorithm and "twice" or "two times" represents the key used for that particular transformation.

Industry grade encryption algorithms must be unbreakable, even with the most powerful computers. The cipher text should be completely opaque and should not provide any clues about the input plain text. Only authorized/intended recipients who have the right key should have the ability to decrypt the cipher text and retrieve the original text.

Hash functions (such as MD5, SHA-1, SHA-256, and SHA-3) are algorithms used to generate a unique fingerprint of a block of data. While they scramble the data like encryption, they do not use a key for decryption. Their primary purpose is to verify data integrity, not confidentiality. A fingerprint is a a fixed-size hash of the whole input, generated by one of many possible mathematical functions (such as MD5, SHA-1, SHA-256, and SHA-3). An HMAC is a fixed-size digest of the whole input mixed with a secret key, also generated by running the input and secret key through a mathematical function.

**Comparison: Hash Fingerprint vs HMAC**

| Feature       | Basic Hash (The "Fingerprint")              | HMAC                                                                       |
| ------------- | ------------------------------------------- | -------------------------------------------------------------------------- |
| **Input**     | The **whole** data message.                 | The **whole** data message **+ a secret key**.                             |
| **Purpose**   | Data **Integrity** (Is the data unchanged?) | Data **Integrity & Authenticity** (Is the data unchanged AND who sent it?) |
| **Key Used?** | No.                                         | Yes, a **secret** key is required.                                         |
| **Example**   | `sha256("hello")`                           | `hmac_sha256("hello", "secret_key")`                                       |

### Symmetric encryption

Symmetric encryption is an encryption scheme that encrypts and decrypts using the same secret key. Here is a simple example of symmetric encryption.

hello —encryption→ khoor

Using a rudimentary symmetric encryption algorithm of “pushing letters forward” and a secret key of 3, we converted the plain text hello to the cipher text khoor.

If we know the encryption algorithm and secret key used in the encryption process, we can apply them in reverse to decrypt khoor back to hello.

khoor —decryption→ hello

Here is another example. A symmetric encryption algorithm of multiplication and a secret key of 7 are used.&#x20;

66 —x7→ 462

To decipher the text, we inverse the operation. We divide 462 by 7. The key point here is that we use the same secret key to encrypt and decrypt the text.

The encryption algorithm is typically standardized and publicly known. So the strength of the encryption practically rests on the strength of the secret key. Longer and more random keys are considered more secure.

**Common Symmetric Encryption Algorithms**

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

The plain text hello was encrypted with an asymmetric encryption algorithm of pushing letters forward and a secret key of 5. To decrypt mjqqt, we push the letters forward 21 more times (let’s pretend there are only lower case letters in the alphabet, for a total of 26 possible characters).

mjqqt –— asymmetric decryption (key = 21) → hello

This just demonstrates the basic idea of asymmetric encryption, that two different keys are used in encryption and decryption. In this example, moving letters backwards by 5 would decrypt the message, but in real asymmetric encryption attempting to reuse the secret key (applying it backward or forward) would only further scramble the message.

That said, our example invokes an important concept in asymmetric encryption: asymmetric keys are mathematically linked. What one key encrypts, only the other key can decrypt. In our example, if we used key 21 to encrypt hello, we can decrypt the cipher with a key of 5.

#### Confidentiality via asymmetric encryption

In asymmetric encryption, one of the key pair is private, never shared with anyone else. This is the private key. The other key is the public key, and it is public. You use the recipient’s public key to encrypt a message to them. Anyone can encrypt with a public key. Only the recipient’s private key can decrypt the message. This ensures that only the intended recipient can read the message.

Bob wants to send an encrypted message to Alice. Bob uses Alice’s public key to encrypt the message. Bob sends the message to Alice. And Alice uses her private key to decrypt the message. This exchange establishes confidentiality: the only possible key that could extract the message is Alice’s private key. And since Alice never shared her key (the private key is never shared), Bob knows that only Alice was able to read the message.

### Symmetric encryption vs asymmetric encryption

Symmetric encryption is a preferred choice for bulk data encryption because:

* In symmetric encryption, the cipher text is the same size as the plain text (input data).
* The math involved in symmetric encryption is relatively simpler and less CPU resource intensive. So more data can be encrypted in less time with less CPU usage.

On the downside, symmetric encryption presents a “key exchange problem”, as the secret key must exist in two places, with the sender and with the receiver. Several solutions exist to the key exchange problem (how do we get the key securely from one party to the other?).

Symmetric encryption is sometimes considered less secure than asymmetric encryption because of a higher exposure risk. The most significant benefit to using asymmetric encryption is that the private key never needs to be shared. Hence asymmetric encryption can be regarded as more secure than symmetric encryption.

**Hybrid encryption**

As noted, asymmetric encryption is not ideal for bulk encryption. Symmetric encryption is more suited for bulk encryption but we have to find a solution for the key exchange problem. **Hybrid encryption** is a solution for the **key exchange problem** that entails combining the strengths of both symmetric and asymmetric encryption.

Bob wants to send an encrypted message to Alice. Bob starts by randomly generating a symmetric secret key. Bob then uses Alice’s public key to encrypt the symmetric secret key. This encrypted symmetric key is sent across the wire to Alice. Alice then uses her private key to extract the symmetric secret key that Bob sent. At this point, both Bob and Alice have an identical symmetric secret key that can be used to symmetrically encrypt communications between them. Thus Bob and Alice are benefiting from the security of asymmetric encryption, with the speed and efficiency of symmetric encryption.

### Key takeaways

* Encryption is vital for ensuring confidentiality across various domains, including secure data storage (e.g., encrypted hard drives), data transmission (e.g., HTTPS), and secure messaging, preventing unauthorized access to sensitive information.
* Symmetric Encryption relies on a single, shared secret key for both the encryption and decryption processes. Its efficiency makes it the preferred method for encrypting large volumes of data, though it requires a secure method to distribute the shared key.
* Asymmetric Encryption uses a mathematically linked pair of keys: a public key for encryption and a private key for decryption. This eliminates the key distribution issue, as the public key can be freely shared, while the private key is kept secret. A message encrypted with a recipient's public key can only be decrypted by their corresponding private key, ensuring confidentiality.
* The strengths of both systems are combined in Hybrid Encryption. This approach uses asymmetric encryption to securely exchange a randomly generated symmetric session key. The bulk of the data is then encrypted efficiently using this symmetric key, solving the key exchange problem while maintaining high performance.

### References

Ferguson, N., Schneier, B., & Kohno, T. (2010). Cryptography Engineering: Design Principles and Practical Applications. Wiley.

Stallings, W. (2017). Cryptography and Network Security: Principles and Practice (7th ed.). Pearson.
