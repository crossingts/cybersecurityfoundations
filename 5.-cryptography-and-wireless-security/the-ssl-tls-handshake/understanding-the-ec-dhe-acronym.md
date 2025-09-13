# Understanding the (EC)DHE acronym

(EC)DHE refers to the modern, secure versions of the Diffie-Hellman algorithm that provide Forward Secrecy. TLS 1.3 mandates the use of an ephemeral version, which is almost always ECDHE due to its superior performance.

(EC)DHE is an acronym that combines three main related concepts. (EC)DHE stands for:

* **(EC)** : **Elliptic Curve**
* **DH** : **Diffie-Hellman**
* **E** : **Ephemeral**

So, **(EC)DHE** means **"Elliptic Curve Diffie-Hellman Ephemeral"** or **"Diffie-Hellman Ephemeral"** with the option for Elliptic Curves.

Let's break down what each part means:

1. **Diffie-Hellman (DH):** This is the original key-exchange algorithm, invented by Whitfield Diffie and Martin Hellman. It allows two parties to create a shared secret over an insecure channel.
2. **Elliptic Curve (EC):** This is a modern, more efficient version of the Diffie-Hellman mathematics. Instead of using large prime numbers, it uses the mathematics of elliptic curves to achieve the same goal but with smaller key sizes and faster computation. ECDHE is generally preferred over plain DHE because it's more efficient.
3. **Ephemeral (E):** This is the most critical part for security. "Ephemeral" means temporary. It signifies that a new, temporary public key is generated for every single TLS session. After the key exchange is done, that key is discarded.
   * This is what provides **Forward Secrecy**. If an attacker records an encrypted conversation and later steals the server's long-term private key, they _still_ cannot decrypt the recording because the temporary (ephemeral) key used for that one session is long gone.
   * The opposite of "ephemeral" would be "static," where the same key is used repeatedly.

**In Simple Terms:**

| Acronym     | Stands For                              | What It Means                                                                                                                               |
| ----------- | --------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| **DH**      | Diffie-Hellman                          | The original method for agreeing on a secret key.                                                                                           |
| **DHE**     | Diffie-Hellman Ephemeral                | The original method, but using a temporary key for perfect forward secrecy.                                                                 |
| **ECDHE**   | Elliptic Curve Diffie-Hellman Ephemeral | A modern, faster, and more efficient version that also uses temporary keys for forward secrecy.                                             |
| **(EC)DHE** |                                         | The common way to write "DHE or ECDHE," acknowledging that both are ephemeral and which one is used depends on the negotiated cipher suite. |

***
