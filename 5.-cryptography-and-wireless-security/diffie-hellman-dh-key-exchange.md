---
hidden: true
---

# Diffie-Hellman (DH) key exchange

Diffie-Hellman (DH) is a method for two parties to securely generate a shared secret over an insecure channel such as the Internet without ever sending the secret itself. It's used in TLS 1.3 to establish encryption session keys.

#### **How Basic Diffie-Hellman Works:**

1. **Agree on Public Numbers**:
   * Both parties agree on a large prime number (**p**) and a base number (**g**). These are public and can be seen by anyone.
2. **Each Party Picks a Private Number**:
   * Alice picks a secret number (**a**).
   * Bob picks a secret number (**b**).
3. **Compute Public Values**:
   * Alice computes **A = gᵃ mod p** and sends **A** to Bob.
   * Bob computes **B = gᵇ mod p** and sends **B** to Alice.
4. **Compute Shared Secret**:
   * Alice computes **S = Bᵃ mod p** (which is **(gᵇ)ᵃ mod p**).
   * Bob computes **S = Aᵇ mod p** (which is **(gᵇ)ᵃ mod p**).
   * Both now have the same **S** (the shared secret), but an attacker can’t easily compute it because they don’t know **a** or **b**.

**Diffie-Hellman in TLS 1.3 Handshake:**

In **TLS 1.3**, DH is used to establish a secure session quickly. Here’s how it works:

1. **Client Hello**:
   * The client sends a list of supported DH groups (sets of **p** and **g**) and a random number.
2. **Server Hello**:
   * The server picks a DH group and sends:
     * Its own random number.
     * Its **public DH value (B = gᵇ mod p)**.
     * A digital signature to prove its identity (optional in some cases).
3. **Client Responds**:
   * The client sends its **public DH value (A = gᵃ mod p)**.
4. **Shared Secret Calculation**:
   * Both compute the shared secret **S = gᵃᵇ mod p** using the other party’s public value.
   * This **S** is then used to derive encryption keys for the session.
5. **Secure Communication**:
   * Now, all data is encrypted using keys derived from **S**.

**Why It’s Secure:**

* Even if an attacker sees **A** and **B**, they can’t easily compute **S** without knowing **a** or **b** (this is the **Discrete Logarithm Problem**).
* TLS 1.3 **removes weak DH groups** and only allows strong, modern cryptography.

***

#### **Simple Diffie-Hellman (DH) Explanation**

Imagine Alice and Bob want to agree on a secret color, but they can only send paint colors in public where eavesdroppers can see them.

1. **They start with the same public color (yellow).**
2. **Each mixes in their own secret color:**
   * Alice adds her **private red**, making **orange**.
   * Bob adds his **private blue**, making **green**.
3. **They swap their mixed colors:**
   * Alice sends **orange** to Bob.
   * Bob sends **green** to Alice.
4. **Each adds their own secret again:**
   * Alice mixes **green + her red** = **brown** (shared secret).
   * Bob mixes **orange + his blue** = **brown** (same secret!).

Now both have **brown**, but nobody else can figure it out because they don’t know the secret ingredients (**red** or **blue**).

**In TLS 1.3 (HTTPS Security):**

* Instead of colors, computers use **math (big numbers and exponents)**.
* They swap "mixed" numbers publicly.
* Each combines them with their **private number** to get the same secret key.
* That secret key encrypts your web traffic.

**Why it’s safe?**

* Even if hackers see the swapped numbers, they can’t reverse the math easily.

***

**A workflow of the paint color mixing analogy with the corresponding DH key exchange steps:**

Here's a step-by-step workflow diagram combining the **paint mixing analogy** with the actual **TLS 1.3 DH key exchange**, including server authentication and forward secrecy:

**1. Initial Setup (Public Colors = DH Parameters)**

* **Publicly Known:**
  * Base color: **Yellow** (like the DH group `g` and prime `p`).
* **Server’s Identity Proof:**
  * Server has a **certificate** (signed by a trusted authority).

#### **2. Key Exchange (Mixing Secret Colors = Ephemeral DH Keys)**

| Step | Paint Mixing Analogy                                                          | TLS 1.3 DH Exchange                                               |
| ---- | ----------------------------------------------------------------------------- | ----------------------------------------------------------------- |
| 1    | Alice & Bob start with **yellow** (public).                                   | Client & server agree on a DH group (`g`, `p`).                   |
| 2    | **Alice’s secret:** Red → mixes with yellow → **orange**.                     | **Client’s ephemeral secret:** `a` → computes `A = gᵃ mod p`.     |
| 3    | **Bob’s secret:** Blue → mixes with yellow → **green**.                       | **Server’s ephemeral secret:** `b` → computes `B = gᵇ mod p`.     |
| 4    | Alice sends **orange** to Bob.                                                | Client sends `A` to server.                                       |
| 5    | Bob sends **green** to Alice + **his signed certificate** (proof he’s legit). | Server sends `B` + **certificate (signed with its private key)**. |
| 6    | Alice mixes **green + her red (secret)** → **brown** (shared secret).         | Client computes `S = Bᵃ mod p` (shared secret).                   |
| 7    | Bob mixes **orange + his blue (secret)** → **brown** (same secret!).          | Server computes `S = Aᵇ mod p` (same shared secret).              |

#### **3. Secure Session (Deriving Encryption Keys)**

* **Shared secret (`S`)** is used to derive encryption keys (never sent over the network!).
* **Forward secrecy:** Ephemeral keys (`a`, `b`) are discarded after the session. Even if the server’s long-term private key is hacked later, past sessions stay secure.

#### **4. Diagram (Simplified Workflow)**

```
Client (Alice)               Server (Bob)
|--------Public Yellow (g, p)-------->|
|<----Server’s Green (B) + Signed Cert----|
|----Client’s Orange (A)-------------->|
|                                     |
| Both compute:                       |
| Brown = Green + Red (S = Bᵃ mod p)  |
| Brown = Orange + Blue (S = Aᵇ mod p)|
|                                     |
|--> Derive keys, encrypt traffic! <--|
```

#### **Key Takeaways:**

1. **Server Authentication:** The signed certificate proves the server’s identity (no imposters!).
2. **Ephemeral DH:** Temporary secrets (`a`, `b`) ensure forward secrecy.
3. **Shared Secret:** Computed independently, never transmitted.
