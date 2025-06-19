---
description: >-
  This section explores how hashing algorithms (SHA-256) can be used to ensure
  the integrity of messages exchanged between hosts
---

# Hashing algorithms and message integrity

This section discusses [hashing algorithms and message integrity](https://builtin.com/cybersecurity/what-is-hashing). This section explains the key qualities (characteristics) of a hashing algorithm. This discussion also explains how hashing algorithms can be used to ensure the integrity of messages exchanged between a client/sender and server/receiver.

* **Hashing algorithms**
* **Message integrity**

### Hashing algorithms

A hashing algorithm is a mathematical function that takes an input (data) of arbitrary size and produces a fixed-size output, a representational sample of the original data called a hash value or hash.

Hashing algorithms are used in a variety of applications, including data integrity, password hashing, file indexing, and data duplication.

A basic hashing algorithm can be converting letters to numbers (a = 1, b = 2, c = 3, etc.):

hello (message) –— hashing algorithm (8+5+12+12+15) → 52 (message digest)

The result of a hashing algorithm is called a message digest (or sometimes checksum, or fingerprint).

If someone changed the h (in hello) to c,

cello → 47 (message digest)

Comparing the message digests shows the original message has changed.

But this hashing algorithm is terrible. If the original message was changed to celt, running the message through the hashing algorithm would produce the same hash value of 52.

A hashing algorithm must maintain four qualities before it is approved for industry usage:

1\. It is mathematically impossible to extract the original message from the digest. You should not be able to reverse engineer the hashing algorithm to know the original message by just inspecting the hash value. Hashing is a one-way function, meaning that it is computationally infeasible to reverse the hash function to find the original input. Hashing is sometimes referred to as one-way encryption – you can only encrypt the message but not decrypt it.

2\. A slight change to the original message causes a drastic change in the resulting digest. A minor modification to the original message should greatly alter the computed digest (the avalanche effect). An industry approved hashing algorithm is not simply one calculation. A hashing algorithm is a series of calculations done iteratively. As a result, a small change in the beginning creates an exponentially bigger change in the resulting digest.

3\. The result of the hashing algorithm is always the same length. The resulting digest cannot provide any hints or clues about the original message, including its length. A digest should not increase in size as the length of the message increases.

4\. It is infeasible to construct a message which generates a given digest. In our example, it would not be overly difficult to generate a list of words that can produce a digest of 52 (one of which might have been the original message). In a proper hashing algorithm, this should be infeasible.

There are many different hashing algorithms available, each with its own strengths and weaknesses. Hashing algorithms examples include MD5, SHA-1, and SHA-2.

Digest lengths of some common hashing algorithms:

MD5 – 128 Bits

SHA or SHA1 – 160 Bits

SHA384 – 384 Bits

SHA256 – 256 Bits

A longer digest tends to be regarded as more secure.

### Message integrity

How can hashing algorithms be used to ensure the integrity of messages exchanged between a client/sender and server/receiver?

The sender calculates a hash on the message and includes the digest with the message sent to the receiver.

The receiver independently calculates the hash on the message using the same hashing algorithm used by the sender and compares the two digests. If the two digests match, this indicates that the message’s integrity has been preserved.

But if a man-in-the-middle intercepted the message on its way to the receiver, altered it, recalculated the hash, and then sent the modified message with the recalculated hash to the receiver, the receiver’s hash calculation would match the modified message. And the receiver would have no way of knowing the message was modified.

This problem can be solved by using a secret key. The secret key can be any series of characters or numbers.

The sender first adds a secret key known only to the sender and the receiver to the message, and calculates the hash of the message combined with the secret key. The sender then sends the resulting digest with the original message to the receiver.

When the receiver receives the message, the receiver calculates the hash on the message with their copy of the secret key. If the resulting digest matches the one sent with the message, then the receiver knows: 1) the message was not altered in transit, and 2) the message was sent by someone who had the secret key (which is a form of **authentication**).

A secret key used in conjunction with a message produces a digest known as the Message Authentication Code (MAC) used as a message integrity check (MIC or "Michael"). There are many different methods for creating a MAC, each combining the secret key with the message in different ways. The most prevalent MAC in use today is known as an Hash-based Message Authentication Code (HMAC).

Hashing Demonstration with Linux: [Run a hashing algorithm (md5sum or sha1sum) on a string of text in a Linux terminal.](https://www.practicalnetworking.net/series/cryptography/hashing-algorithm/)

### References

[Ed Harmoush. (December 15, 2021). Hashing Algorithm. Practical Networking.](https://www.practicalnetworking.net/series/cryptography/hashing-algorithm/)

[Ed Harmoush. (December 8, 2021). Message Integrity. Practical Networking.](https://www.practicalnetworking.net/series/cryptography/message-integrity/)
