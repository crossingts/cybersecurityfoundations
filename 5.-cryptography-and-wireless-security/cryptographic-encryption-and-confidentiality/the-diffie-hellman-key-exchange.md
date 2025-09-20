# The Diffie-Hellman key exchange

Diffie-Hellman (DH) is a key-exchange protocol that allows two parties (e.g., a client and a server) to collaboratively but independently establish a shared secret over an insecure channel. In TLS, this shared secret is called the pre-master secret.

The most common and secure DH form used in modern TLS is Ephemeral Diffie-Hellman (DHE, ECDHE).&#x20;

The Ephemeral Diffie-Hellman key exchange process in a TLS handshake is as follows:

1. For each session, both parties generate a temporary ephemeral key pair.
2. They exchange their ephemeral public keys, with the server authenticating its key with a digital signature from its long-term certificate.
3. Each party combines its own ephemeral private key with the other's ephemeral public key to mathematically derive the same pre-master secret.
4. This pre-master secret is then used by a Key Derivation Function (KDF) to generate all symmetric session keys for encryption and integrity of transmitted data. The ephemeral keys are discarded after the session.

This ephemeral nature is crucial as it provides Forward Secrecy. In TLS 1.2, Ephemeral Diffie-Hellman was an optional key exchange method. In TLS 1.3, it is the only allowed method, making Forward Secrecy mandatory.

The following segment breaks down the fundamental mathematics behind the Diffie-Hellman key exchange and how it is specifically applied within the TLS 1.3 handshake.

#### How Basic Diffie-Hellman Works

1. **Agree on public parameters:**
   * Both parties agree on a large prime number (**p**) and a base number, generator (**g**). These are public and can be seen by anyone.&#x20;
2. **Generate private keys**:
   * Alice picks a secret number (**a**).&#x20;
   * Bob picks a secret number (**b**).
3. **Compute public keys**:
   * Alice computes her public key `A = gᵃ mod p` and sends it to Bob.&#x20;
   * Bob computes his public key `B = gᵇ mod p` and sends it to Alice.
4. **Compute shared secret**:
   * Alice computes the secret `S = Bᵃ mod p = (gᵇ)ᵃ mod p = gᵃᵇ mod p`.&#x20;
   * Bob computes the secret `S = Aᵇ mod p = (gᵃ)ᵇ mod p = gᵃᵇ mod p`.&#x20;
   * Both now have the same **S** (the shared secret), but an attacker can’t easily compute it because they don’t know **a** or **b**.

**Ephemeral Diffie-Hellman in TLS 1.3 Handshake:**

In TLS 1.3, the ephemeral form of DH (ECDHE) is used to establish a secure session. Here’s how it works:

1. Client Hello: The client sends a list of supported DH groups (sets of `p` and `g`) and a random value.
2. Server Hello: The server picks a DH group and sends back:
   * Its own random value.
   * Its ephemeral public DH value (`B = gᵇ mod p`).
   * A digital signature over the handshake transcript to prove its identity.
3. Client Response: The client sends its ephemeral public DH value (`A = gᵃ mod p`).
4. Shared secret calculation: Both parties compute the shared secret `S = gᵃᵇ mod p` (the pre-master secret). This value is then used with a Key Derivation Function (KDF) to derive the symmetric encryption keys for the session.
5. Secure communication: All subsequent application data is encrypted using the newly derived session keys.

**Why It’s Secure:**

* The security relies on the Discrete Logarithm Problem: it is computationally infeasible for an attacker who observes the public values `A` and `B` to calculate the private keys `a` or `b`, or the shared secret `S`.
* Because both parties use ephemeral key pairs, the shared secret is unique to each session, providing Forward Secrecy.
* TLS 1.3 mandates strong, modern DH parameters, removing historically weak options.

#### The paint color mixing analogy for the DH key exchange

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
