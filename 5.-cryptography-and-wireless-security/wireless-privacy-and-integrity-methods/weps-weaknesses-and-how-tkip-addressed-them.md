# WEP's weaknesses and how TKIP addressed them

#### The Weakness of WEP (Wired Equivalent Privacy)

An explanation of the cryptographic flaws in WEP and the practical attack methods, followed by how TKIP mitigated them.

WEP was the original security protocol for Wi-Fi, introduced in 1999. Its fundamental flaws were architectural and rendered it completely insecure. The main weaknesses were:

**1. The Short and Static Initialization Vector (IV)**

* **What it was:** The IV was a 24-bit number that was supposed to be random and change with every data packet. It was concatenated with the long-term secret key before being fed into the RC4 stream cipher to generate the keystream for that packet.
* **The Weakness:**
  * **Extremely Small Space:** A 24-bit IV means there are only about 16.7 million (2^24) possible values. On a busy network, these IVs **must be reused** within a matter of hours or even minutes.
  * **Predictable IVs:** Many early implementations started the IV counter at 0 and incremented it, or used a pseudo-random generator that was easily predictable. This made IVs even less random.
  * **No Key Separation:** Reusing an IV with the same static key means you are reusing the same keystream. In cryptography, this is a catastrophic failure.

**2. The RC4 Stream Cipher Vulnerabilities**

* RC4, the cipher WEP used, has well-known biases. Certain keys (IV + Secret Key) produce keystreams that are not completely random. Some bits are more likely to be 0 or 1.
* A specific class of IVs, known as "**Weak IVs**," exacerbate these biases. When a weak IV is used, the relationship between the first few bytes of the keystream and the secret key becomes statistically evident.

**3. The Flawed Integrity Check (ICV)**

* WEP used a Cyclic Redundancy Check (CRC-32) to ensure data wasn't modified in transit.
* **The Weakness:** CRC-32 is **linear** and not cryptographically secure. An attacker can:
  * Flip a bit in the encrypted packet.
  * Calculate the change that bit flip would cause in the CRC.
  * Flip the corresponding bits in the ICV to make it appear valid.
  * This allows for undetectable packet modification.

**4. The Lack of a Key Management System**

* WEP keys were often manually entered and shared by all users on a network. Revoking access for a single user meant changing the key for everyone and re-distributing it.

***

#### How WEP Could Be Cracked

The combination of these flaws makes cracking WEP a straightforward, automated process. The most common method is the **FMS (Fluhrer, Mantin, Shamir) attack**, named after the researchers who first published the RC4 weaknesses in 2001.

Here is the step-by-step process:

1. **Capture Traffic:** The attacker passively monitors the wireless network, collecting all encrypted data packets. This is undetectable.
2. **Focus on IVs:** The attacker filters the captured packets, looking for those that use "Weak IVs."
3. **Statistical Analysis:** For each packet with a Weak IV, the attacker can make a probabilistic guess about a byte of the secret WEP key. By collecting a large number of these packets (typically **50,000 to 500,000**), the attacker gets thousands of guesses for each key byte.
4. **Correlate and Derive the Key:** The attacker uses statistical methods (like the KoreK attacks, which improved on FMS) to correlate all these guesses. The correct value for each key byte will be the one that appears most frequently.
5. **Complete the Key:** Once enough packets have been collected, the statistical signal becomes strong enough to reveal the entire WEP key with near-certainty.

**In a nutshell:** An attacker just needs to listen to a busy network for a few minutes. Modern tools like **Aircrack-ng** automate this entire process. If the network isn't busy enough, the attacker can use "packet injection" to re-transmit captured packets, artificially generating the traffic needed to speed up the cracking process from hours to minutes.

***

#### How TKIP Addressed These Weaknesses (The "Interim Solution")

TKIP was designed as a firmware upgrade for WEP-capable hardware. It couldn't change the underlying RC4 cipher, so it added a "wrapper" of security around it.

* **Fixes IV Reuse:** TKIP uses a **48-bit Sequence Counter** instead of a 24-bit IV. This sequence number is also used for replay protection. The 48-bit space is so vast (281 trillion values) that IV reuse is practically impossible on a single key.
* **Fixes Static Key:** TKIP implements a **per-packet key mixing** function. Instead of using the static key directly, it combines the base key with the transmitter's MAC address and the sequence counter to create a unique, dynamic 128-bit key for _every single packet_. This completely negates the Weak IV attacks.
* **Fixes Integrity:** TKIP replaced CRC-32 with **Michael (MIC)**, a cryptographically secure Message Integrity Code. It also includes countermeasures—if two MIC failures are detected within 60 seconds, the network disassociates the client and rekeys.
* **Adds Re-keying:** TKIP includes a mechanism to automatically change the base key (the Pairwise Transient Key) periodically, further limiting exposure.

While TKIP was a massive improvement over WEP and served its purpose well for several years, it was still built on the fragile RC4 foundation. It has since been deprecated in favor of AES-CCMP, which is used by WPA2.

---

The Flawed Integrity Check (ICV) is why under WEP it was possible to alter a packet whose content was known even if it had not been decrypted.

#### The Perfect Storm: Linearity + Stream Cipher

1. **Linear Integrity Check (CRC-32):** CRC-32 is designed to detect accidental errors, not malicious changes. It is a linear function. This means:
   * `CRC(A ⊕ B) = CRC(A) ⊕ CRC(B)` (where ⊕ is XOR)
   * If you know how the plaintext `A` is changed (to `B`), you can predict exactly how its CRC will change.
2. **Stream Cipher (RC4):** A stream cipher works by generating a keystream and simply XORing it with the plaintext to produce ciphertext.
   * Ciphertext = `(Plaintext ⊕ ICV) ⊕ Keystream`

In WEP, the encryption is done by XORing the plaintext with a keystream generated by RC4. The flawed integrity check (ICV) is computed on the plaintext and then encrypted along with the plaintext.

#### The Attack: Bit-Flipping Without the Key

An attacker who knows the original plaintext of a packet can alter it to say anything they want, and then create a valid checksum for the modified packet, **all without knowing the WEP key or decrypting the packet**.

**Step-by-Step:**

1. **Know the Plaintext:** The attacker has a captured encrypted packet and knows what the original plaintext (`P`) is. (This is often possible with common network protocols like ARP requests, TCP handshakes, etc.).
2. **Choose the Malicious Change:** The attacker decides they want to change the plaintext from `P` to a different message `M`.
3. **Calculate the Difference (Delta):** The attacker calculates the difference between the original and malicious plaintext: `Δ = P ⊕ M`.
4. **Flip Bits in the Ciphertext:** The attacker simply XORs the ciphertext with the same `Δ`. Because of how XOR works, this will cause the exact same bit-flips in the decrypted plaintext on the receiving end.
   * `C' = Ciphertext ⊕ Δ`
5. **Fix the Integrity Check (ICV):** This is the crucial part. The attacker also knows the original ICV. Because CRC-32 is linear, the new, valid ICV for the modified plaintext `M` is:
   * `ICV' = ICV_original ⊕ CRC(Δ)`
   * The attacker calculates `CRC(Δ)` and XORs it with the _encrypted_ ICV value in the captured packet.
6. **Transmit the Forged Packet:** The attacker now has a modified ciphertext `C'` and a modified, encrypted ICV `ICV'`. They transmit this packet.

**What Happens on the Other End?**

* The receiver gets the packet `(C', ICV'_encrypted)`.
* They decrypt it using the WEP key, which yields the malicious plaintext `M` and the integrity check value `ICV'`.
* The receiver independently calculates the CRC-32 of the decrypted plaintext `M`.
* Because of the linear property, the calculated CRC-32 will match the decrypted `ICV'`. **The packet passes the integrity check and is accepted as legitimate.**

#### Why This is Catastrophic

This bit-flipping attack was a primary tool for accelerating the cracking of WEP. Attackers could:

* **Replay and Modify ARP Packets:** They could capture an encrypted ARP request, flip bits to turn it into a new ARP request, and re-inject it. This would trick the access point into generating tons of traffic, providing the IVs needed to crack the key much faster (the "ARP injection replay attack").
* **Poison Data Streams:** They could alter the content of communications, for example, changing a "Transfer $10" command to "Transfer $1000" within an encrypted banking session.

The flawed ICV didn't just fail to detect tampering; it actively enabled an attacker to precisely control how a packet was tampered with, making the encryption useless for ensuring data integrity. This was one of the key flaws that TKIP's Michael (MIC) was designed to fix, as a cryptographic MIC makes it computationally infeasible to calculate the new integrity value without knowing the secret key.

---

So, WEP also had another problem beside integrity, that its keys could be cracked within minutes. That's the central, catastrophic failure of WEP. While the integrity flaw allowed for packet manipulation, the **ease and speed of cracking the secret key itself** is what truly killed WEP. The claim that it can be cracked "within minutes" is not an exaggeration; it's a routine reality.

Here’s a breakdown of _why_ the key cracking is so fast and how it works in practice.

#### The Core Problem: Keystream Reuse

As we discussed, the short 24-bit IV forces repetitions. But why is that so bad? Because when you use the same IV (and thus the same keystream) with the same static key for two different packets, you create a critical vulnerability.

If an attacker has two ciphertexts encrypted with the same keystream (`KS`):

* `C1 = P1 ⊕ KS`
* `C2 = P2 ⊕ KS`

XORing them together cancels out the keystream:

* `C1 ⊕ C2 = (P1 ⊕ KS) ⊕ (P2 ⊕ KS) = P1 ⊕ P2`

The attacker now has the XOR of two plaintexts. If they can guess the contents of one plaintext (e.g., a common network protocol packet like an ARP request), they can immediately recover the other plaintext.

#### The Automated Cracking Process (The "How")

Modern tools like **Aircrack-ng** have automated this entire process, making it accessible to anyone with a standard Wi-Fi card and Kali Linux. Here's how an attack unfolds in real-time:

1. **Monitor Mode:** The attacker puts their wireless card into "monitor mode" to capture all wireless traffic in the area.
2. **Target an Access Point:** They identify a target network using WEP.
3. **Capture IVs:** The attacker starts capturing all packets from that network. They are specifically collecting packets to harvest their **Initialization Vectors (IVs)**. The goal is to collect a large number of _unique_ IVs, but most importantly, the _weak IVs_ that leak information about the key.
4. **Accelerate with Packet Injection (The "Minutes" Part):** On a quiet network, it might take hours to capture enough IVs passively. To achieve the "minutes" timescale, the attacker actively **injects traffic**.
   * They capture a single data packet (even if they can't read it).
   * They re-transmit (replay) this packet back to the access point over and over.
   * Each time the access point accepts and processes this forged packet, it generates a _new response_ encrypted with a _new IV_.
   * This creates a feedback loop, causing the access point to flood the network with packets, generating tens of thousands of IVs per minute.
5. **Crack the Key:** Once the attacker has captured a sufficient number of IVs (often between 50,000 to 500,000, depending on key length and network traffic), they feed the capture file to `aircrack-ng`.
   * The tool uses statistical attacks (like the PTW attack, a refinement of the classic FMS attack) to analyze the relationship between the weak IVs and the encrypted data.
   * It makes probabilistic guesses for each byte of the WEP key.
   * Within **seconds or minutes** of starting the analysis, the correct key emerges from the statistical noise.

#### A Concrete Example: The ARP Request Replay Attack

This is the most famous and efficient method:

1. An attacker captures a single **ARP request** packet from the network. (They can often force one to be sent by disconnecting a client).
2. They don't need to decrypt it. They simply retransmit it to the access point. The AP sees it as a new ARP request and dutifully broadcasts an ARP response.
3. The attacker captures this new response, which has a new IV.
4. They immediately take this new response packet, modify it slightly, and re-inject it as _another_ new ARP request.
5. This process runs in a loop, thousands of times per minute, generating the IVs needed for the crack at an explosive rate.
