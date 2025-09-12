# The TLS handshake key exchange and derivation process

### Steps of the TLS handshake key exchange and derivation process&#x20;

1. **Key Exchange (Asymmetric Encryption):** The client and server use asymmetric encryption (e.g., RSA, ECC, DH/ECDH) to securely exchange a pre-master secret.&#x20;

* The client generates a **pre-master secret (PMS)** (a random 48-byte value in TLS 1.2).
* The client encrypts the PMS with the **server’s public key** (RSA) or computes it via **Diffie-Hellman (DH/ECDH)**.
* The client sends the encrypted PMS to the server, which decrypts it using its **private key**.
* **Now, both client and server have the same PMS.**

2. **Key Derivation (Hashing the PMS with Nonces):** The pre-master secret is hashed (using algorithms like SHA-256) along with random values to generate a **master secret**. The master secret is then used to derive symmetric session keys and MAC keys (for encryption and integrity checks).

* The PMS alone is **not used directly** as the session key. Instead, it is **hashed** along with:
  * **Client random** (nonce sent in `ClientHello`)
  * **Server random** (nonce sent in `ServerHello`)
* This is done using a **Pseudorandom Function (PRF)** (e.g., HMAC-SHA256 in TLS 1.2).
* The output is the **master secret**, which is then used to derive:
  * **Symmetric session keys** (e.g., AES-256 key for encryption)
  * **MAC keys** (for integrity, e.g., HMAC-SHA256)
  * **Initialization Vectors (IVs)** (if required by the cipher)
* **Both the client and server independently** compute the same symmetric session keys using:
  * The shared PMS
  * The exchanged `ClientRandom` and `ServerRandom`
  * The agreed PRF (e.g., HMAC-SHA256)

3. **Data Transmission (Symmetric Encryption)**:

* The symmetric session key (derived during the handshake) is used alongside a symmetric encryption algorithm (e.g., AES-256, ChaCha20) to encrypt the actual application data (e.g., HTTP requests, form submissions).
* Hashing (via HMAC) ensures **data integrity**, preventing tampering during transit.

**Step-by-Step Flow**

| **Step**                    | **Client Action**                                                                                | **Server Action**                                  | **Purpose**                                                        |
| --------------------------- | ------------------------------------------------------------------------------------------------ | -------------------------------------------------- | ------------------------------------------------------------------ |
| **1. Key Exchange**         | Generates PMS → Encrypts with server’s public key → Sends to server                              | Receives encrypted PMS → Decrypts with private key | Securely shares PMS without exposure                               |
| **2. Nonce Exchange**       | Sends `ClientHello` with `ClientRandom`                                                          | Responds with `ServerHello` and `ServerRandom`     | Ensures freshness (prevents replay attacks)                        |
| **3. Key Derivation**       | Uses PMS + `ClientRandom` + `ServerRandom` → Hashes (PRF) → Master Secret → Derives session keys | Does the same computation                          | Both sides independently generate identical symmetric session keys |
| **4. Secure Communication** | Encrypts data using symmetric key (AES) + MAC (HMAC)                                             | Decrypts using same symmetric key + verifies MAC   | Confidentiality + integrity                                        |

**Why Hashing is Necessary**

* **Prevents key reuse**: Even if the same PMS is used in another session, different `ClientRandom` and `ServerRandom` values ensure unique keys.
* **Strengthens security**: A direct PMS → session key mapping would be weaker; hashing adds entropy.
* **Supports forward secrecy**: In (EC)DHE key exchange, the PMS is ephemeral, and hashing ensures session keys can’t be retroactively computed.

This ensures **confidentiality (AES)**, **integrity (HMAC)**, and **authentication (PKI)** in SSL/TLS. **PKI (Public Key Infrastructure)** is a framework that enables **authentication** by verifying the identity of entities (such as servers or clients) using digital certificates and asymmetric cryptography.

#### SSL/TLS Key Exchange & Derivation Flow

Here’s a **simplified diagram** of the SSL/TLS key exchange and derivation process to visualize how symmetric keys are securely established:

_(Simplified for RSA Key Exchange, TLS 1.2)_

```
+-------------------+                       +-------------------+
|      Client       |                       |      Server        |
+-------------------+                       +-------------------+
          |                                         |
          | 1. ClientHello (ClientRandom)           |
          |---------------------------------------->|
          |                                         |
          | 2. ServerHello (ServerRandom)           |
          |         Server Certificate (PubKey)     |
          |<----------------------------------------|
          |                                         |
          | 3. Pre-Master Secret (PMS)              |
          |   - Client generates PMS (48 bytes)     |
          |   - Encrypts PMS with Server's PubKey    |
          |   - Sends to Server                      |
          |---------------------------------------->|
          |                                         |
          | 4. Decrypt PMS with Server's PrivKey     |
          |   (Now both have PMS + Randoms)          |
          |                                         |
          | 5. Key Derivation (PRF: e.g., HMAC-SHA256)|
          |   Inputs:                                |
          |   - PMS                                  |
          |   - ClientRandom + ServerRandom         |
          |   Output: Master Secret → Session Keys  |
          |   (Same keys computed independently)    |
          |                                         |
          | 6. Secure Data Transfer                 |
          |   - Symmetric Encryption (AES)           |
          |   - Integrity Checks (HMAC)              |
          |<------------------------------->|
          |                                         |
+-------------------+                       +-------------------+
```

**Key Steps Explained Visually**

1. **Handshake Initiation**
   * Client sends `ClientHello` with a random nonce (`ClientRandom`).
   * Server responds with `ServerHello` (and its `ServerRandom`) + its **public key certificate**.
2. **Pre-Master Secret (PMS) Exchange**
   * Client generates PMS → encrypts with server’s public key → sends to server.
   * Server decrypts PMS with its **private key**.
3. **Master Secret & Session Key Derivation**
   * Both client and server **hash** (`PRF`) the PMS + `ClientRandom` + `ServerRandom` to compute:
     * **Master Secret** → **Session Keys** (AES for encryption, HMAC for integrity).
4. **Secure Communication**
   * All further data is encrypted with the derived **symmetric keys**.

**Why This Matters**

* **Asymmetric Encryption (RSA/ECC)**: Securely exchanges the PMS _once_.
* **Symmetric Encryption (AES)**: Efficiently encrypts all subsequent data.
* **Hashing (PRF)**: Ensures keys are unique per session and tamper-proof.

#### **How Both Client and Server Derive the Same Symmetric Session Key from the Master Secret**

Once both sides compute the **master secret** (using `PMS + ClientRandom + ServerRandom`), **both the client and server independently derive the same symmetric session keys** using a **deterministic key derivation process**. Here’s how it works:

**Step-by-Step Key Derivation Process**

1. **Inputs for Key Expansion**\
   Both parties now have:
   * The same **master secret** (48 bytes in TLS 1.2).
   * The same **`ClientRandom`** (client’s nonce).
   * The same **`ServerRandom`** (server’s nonce).
   * The same **Pseudorandom Function (PRF)** (e.g., HMAC-SHA256).
2.  **Key Expansion Using PRF**\
    The master secret is fed into the PRF along with a **label** (e.g., `"key expansion"`) and the two nonces to generate a **key block**:

    ```
    key_block = PRF(MasterSecret, "key expansion", ClientRandom + ServerRandom)
    ```

    * The PRF is called multiple times (in chunks) until enough key material is generated.
3.  **Splitting the Key Block into Session Keys**\
    The `key_block` is split into the required keys for encryption and integrity:

    * **Client Write Key** (e.g., AES key for client→server encryption).
    * **Server Write Key** (e.g., AES key for server→client encryption).
    * **Client MAC Key** (for HMAC on client→server data).
    * **Server MAC Key** (for HMAC on server→client data).
    * **Initialization Vectors (IVs)** (if required by the cipher, e.g., AES-CBC).

    Example (simplified):

    ```
    key_block = [client_write_key][server_write_key][client_MAC_key][server_MAC_key][client_IV][server_IV]  
    ```
4. **Both Sides Use Identical Keys**
   * Since the **PRF is deterministic**, both the client and server generate the **exact same `key_block`**.
   * They then **split it the same way**, ensuring:
     * The client’s **"write" key** = the server’s **"read" key**.
     * The server’s **"write" key** = the client’s **"read" key**.

**Why Does This Work?**

* **Same Inputs → Same Outputs**: Both sides use identical inputs (`MasterSecret`, `ClientRandom`, `ServerRandom`).
* **PRF Guarantees Consistency**: The PRF (e.g., HMAC-SHA256) always produces the same output for the same input.
* **No Key Transmission Needed**: The keys are **derived locally**, never sent over the network.

**Example in TLS 1.2 (AES-256-CBC-SHA256)**

| **Key Material**   | **Size (Bytes)** | **Purpose**                           |
| ------------------ | ---------------- | ------------------------------------- |
| `client_write_key` | 32               | AES-256 encryption (client→server)    |
| `server_write_key` | 32               | AES-256 encryption (server→client)    |
| `client_MAC_key`   | 32               | HMAC-SHA256 (client→server integrity) |
| `server_MAC_key`   | 32               | HMAC-SHA256 (server→client integrity) |
| `client_IV`        | 16               | Initialization Vector (AES-CBC)       |
| `server_IV`        | 16               | Initialization Vector (AES-CBC)       |

Both sides derive **the same 6 keys** from the `key_block`, ensuring secure bidirectional communication.

**Summary**

1. **Master Secret** → Generated identically on both sides (PMS + nonces).
2. **PRF Expansion** → `key_block` = PRF(MasterSecret, "key expansion", nonces).
3. **Key Splitting** → Both sides extract the same keys in the same order.
4. **Secure Communication** → Symmetric encryption (AES) + integrity (HMAC) with synchronized keys.

This ensures **no key mismatch** while keeping keys **confidential** (never transmitted).
