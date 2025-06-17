# Other information security concepts and practices

### The AAA framework&#x20;

AAA stands for Authentication, Authorization, and Accounting. It’s a framework for controlling and monitoring users of a computer system such as a network.

Authentication is how you control access to your network and prevent intrusions, data loss, and unauthorized users.

### Foundational cryptography concepts

#### The primary goals of cryptography

The primary goals of cryptography are confidentiality, authentication, data integrity, and non-repudiation.

• Confidentiality protects information from unauthorized access.

• Authentication verifies the identity of users and the authenticity of data.

• Data integrity guarantees that information remains unaltered by unauthorized parties, ensuring its accuracy.

• Non-repudiation ensures that a party cannot later deny having performed an action (such as sending a message or approving a transaction). It provides irrefutable proof—through digital signatures, timestamps, or audit logs—that a specific user took a particular action, preventing false denials and holding parties accountable.

#### Essential cryptography terms&#x20;

<**Encryption** is a process of transforming simple text/data, called plaintext, into unintelligible form, named as ciphertext. Decryption is the inverse process of encryption. **Cipher** is an algorithm that performs encryption/decryption. A **key** is a secret string of characters or symbols that is used for the encryption/decryption of plaintext/ciphertext. Sometimes, the term **cryptosystem** is used instead of cipher. There are two types of ciphers depending on the use of keys: symmetric and asymmetric.\
**Symmetric ciphers**, also referred as secret-key ciphers, use the same key for encryption and decryption. Symmetric cryptosystems are divided into two groups: block and stream ciphers. In block ciphers, operations of encryption/decryption are performed on blocks of bits or bytes, whereas stream ciphers operate on individual bits/bytes. **Asymmetric ciphers**, alternatively named public-key ciphers, use two keys, one for encryption and other for decryption. **Cryptanalysis** is a study of techniques for “cracking” encryption ciphers, i.e., attacks on cryptosystems. And chances are you’ve heard about **hashing algorithms**, which involves taking an input of any length and outputting a fixed-length string, called a hash. Which can be used, for example, as signatures or for data-integrity purposes.>

### References

Shamil Alifov. (2016). How to get started in cryptography (Ch. 5). In _Beginner’s Guide To Information Security_ (pp. 27-31). Peerlyst. Retrieved from https://www.peerlyst.com/posts/peerlyst-announcing-its-first-community-ebook-the-beginner-s-guide-to-information-security-limor-elbaz
