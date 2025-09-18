---
description: >-
  This section discusses the steps involved in generating an RSA key and
  applying the key to a plain text to see how RSA encryption works
---

# Generating and applying an RSA key

## Learning objectives

* Understand the key mathematical concepts underlying the functionality of RSA
* Become familiar with the main steps involved in generating an RSA key
* Develop a foundational understanding of how an RSA key can be applied to encrypt plain text

This section presents a [working example of RSA’s key generation](https://www.youtube.com/watch?v=Pq8gNbvfaoM), encryption, and signing capabilities. This section explores the math behind the RSA algorithm. The discussion covers the steps involved in generating an RSA key, and then applies the key to a plain text to see how RSA encryption works.

## Topics covered in this section

* **Rivest–Shamir–Adleman (RSA) introduction**
* **Four key concepts**
* **RSA key generation (5 steps)**
* **Message encryption**
* **Message signing**

### Rivest–Shamir–Adleman (RSA) introduction

The initialism "RSA" comes from the surnames of Ron Rivest, Adi Shamir, and Leonard Adleman, who publicly described their public key cryptosystem in 1977. RSA is a widely used public-key encryption algorithm that enables secure data transmission over insecure channels like the Internet. RSA is the most common encryption algorithm used by SSL/TLS.

Asymmetric encryption uses a key pair comprised of one public key used to encrypt a text and one private key used to decrypt the cipher. Both keys are mathematically linked, what one key encrypts only the other decrypts.&#x20;

**Common RSA applications:**

* Secure web browsing (HTTPS)
* Secure email (S/MIME)
* Virtual private networks (VPNs)
* Digital signatures
* Software licensing
* Data protection

**Important considerations:**

* Key length is crucial for security. Longer keys are more secure but slower to process.
* RSA can be vulnerable to certain attacks, so proper implementation and key management are essential.
* Hybrid encryption systems often combine RSA with symmetric encryption for better efficiency.

### Four key concepts

We will go over the steps involved in generating an RSA key, then we will apply the key to a plain text to see how RSA encryption works. First, we need to clarify four concepts.

* Prime numbers: Natural numbers greater than 1 that are divisible by only two positive integers: 1 and themselves, for example, 2, 3, 5, 7, 11, 13, etc.
* Factor: A number you can multiply to get another number, for example, the factors of 12 are 1, 2, 3, 4, 6, and 12.
* Semi-prime: A natural number that has only prime factors (excluding 1 and itself), e.g., 21 (3×7). A semi-prime number is a product of two prime numbers.
* Modulus: A mathematical operation that returns the remainder of a division. It is often abbreviated as MOD. For example, 11 MOD 4 = 3 because 11 divided by 4 has a quotient of 2 and a remainder of 3.

### RSA key generation (5 steps)

1\) Select two prime numbers: P and Q

P = 7

Q = 19

2\) Calculate N, whereby N = P\*Q

7 \* 19 = 133 →semi-prime

Note, modern RSA best practice is to use a key size of 2048 bits. This correlates to the N (modulus) value.  The two primes used in modern RSA must result in a product that is 2048 bits.

To achieve a 2048-bit key, the prime numbers P and Q (used to calculate N) must be large enough to produce a modulus N that is also 2048 bits long.

3\) Calculate the Totient (T) of N: (P-1)\*(Q-1)

(7-1)\*(19-1) = 6 \* 18 = 108

4\) Select a public key (E)

The value of the public key must match three requirements:

* It must be Prime
* It must be less than T
* It must not be a factor of the T

Next, we select a prime number that is less than 108 and whose values are not factors of 108.

Let’s go with 29.

5\) Select a private key (D)

The product of the public key and the private key when divided by the Totient must result in a remainder of 1, i.e., the following formula must be true:

(D\*E) MOD T = 1

Let’s go with 41 as our private key. Let’s confirm if 41 qualifies as a private key:

(41\*29) MOD 108

\= 1189 MOD 108

1189/108 = 11.00926; 0.00926×108 = 1

Yes, 41 is fine.

Here are the values from the five steps:

<figure><img src="https://professionaludev.wordpress.com/wp-content/uploads/2023/12/riveste28093shamire28093adleman-pracnet-example.webp?w=1024" alt="Rivest–Shamir–Adleman-PracNet-example" height="241" width="1024"><figcaption><p>Image courtesy of Practical Networking (PracNet)</p></figcaption></figure>

### Message encryption

Let’s go over the encryption process using the key pair we generated. We will use 99 as our plain text message (M).

The formula to Encrypt with RSA keys is:

Cipher text = M^E MOD N

If we plug the numbers:

99^29 MOD 133 = 92

Our key pair was 29 (E = public) and 41 (D = private).&#x20;

We should be able to extract the original message (M = 99) using our private key:

The formula to decrypt with RSA keys is:

Plain text (original message M) = cipher text^D MOD N

M = 92^41 MOD 133 = 99

### Message signing

We can use the key pair to verify a message’s signature. This time we’re going to encrypt with the private key and see if we can decrypt with the public key.

To encrypt, signature = M^D MOD N

If we plug that into a calculator, we get:

99^41 MOD 133 = 36

36 is the signature of the message. If the correlating public key can decrypt this cipher, then we know that only whoever had the original private key could have generated a signature of 36.

To decrypt, original message (M) = cipher text^E MOD N

If we plug that into a calculator, we get:

36^29 MOD 133 = 99

### Key takeaways

* The first step in RSA key generation is selecting two prime numbers: P and Q.
* The second step in RSA key generation is calculating N, whereby N = P\*Q.
* The third step in RSA key generation is calculating the Totient (T) of N: (P-1)\*(Q-1).
* The fourth step in RSA key generation is selecting a public key (E).
* The fifth step in RSA key generation is selecting a private key (D).

### References

[Ed Harmoush. (December 8, 2021). RSA Example. Practical Networking.](https://www.practicalnetworking.net/series/cryptography/rsa-example/)
