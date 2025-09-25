---
description: >-
  This section covers key wireless privacy and integrity algorithms, including
  TKIP (WPA), AES-CCMP (WPA2), AES-GCMP (WPA3), and MIC (Message Integrity Check
  "Michael" in WPA)
---

# Wireless privacy and integrity methods

## Learning objectives

* Become familiar with key encryption and message integrity algorithms used in securing wireless networks

This section covers key encryption and message integrity algorithms used in securing wireless networks, including TKIP (WPA), AES-CCMP (WPA2), AES-GCMP (WPA3), and MIC (Message Integrity Check "Michael" in WPA).

## Topics covered in this section

* **TKIP (WPA)**
* **AES-CCMP (WPA2)**
* **AES-GCMP (WPA3)**
* **MIC (Message Integrity Check "Michael" in WPA)**

### TKIP (WPA)

Temporal Key Integrity Protocol (TKIP) was designed by the IEEE 802.11i task group and the Wi-Fi Alliance as an interim solution to replace WEP without requiring the replacement of legacy hardware. Under WEP it was possible to alter a packet whose content was known even if it had not been decrypted. The breaking of WEP had left Wi-Fi networks without viable link-layer security, and a solution was required for already deployed hardware.

WPA (2003) primarily uses TKIP (Temporal Key Integrity Protocol) as its encryption method. AES was optional in WPA but not commonly supported. WPA2 (2004) made AES-CCMP mandatory as the encryption method, with TKIP as an optional fallback for backward compatibility. WPA3 mandates AES-CCMP (128-bit) for WPA3-Personal. WPA3-Enterprise supports AES-256-GCMP (stronger encryption for enterprise networks).

In WPA-Personal and WPA2-Personal, the PSK (your Wi-Fi password) is used to derive encryption keys. In WPA3-Personal, PSK is replaced by SAE for authentication but the actual encryption in WPA3 uses AES-CCMP (AES-GCMP for enterprise).

To be able to run on legacy WEP hardware with minor upgrades, TKIP uses RC4 as its cipher. TKIP also provides a rekeying mechanism. TKIP ensures that every data packet is sent with a unique encryption key (Interim Key/Temporal Key + Packet Sequence Counter). Key mixing increases the complexity of decoding the keys by giving an attacker substantially less data that has been encrypted using any one key.

TKIP brought the following security features using legacy hardware and the underlying WEP encryption (pp. 714-715):

■ MIC: This efficient algorithm adds a hash value to each frame as a message integrity check to prevent tampering; commonly called “Michael” as an informal reference to MIC.

■ Time stamp: A time stamp is added into the MIC to prevent replay attacks that attempt to reuse or replay frames that have already been sent.

■ Sender’s MAC address: The MIC also includes the sender’s MAC address as evidence of the frame source.

■ TKIP sequence counter: This feature provides a record of frames sent by a unique MAC address, to prevent frames from being replayed as an attack.

■ Key mixing algorithm: This algorithm computes a unique 128-bit WEP key for each frame.

■ Longer initialization vector (IV): The IV size is doubled from 24 to 48 bits, making it virtually impossible to exhaust all WEP keys by brute-force calculation.

TKIP became a stopgap measure to enable stronger encryption on WEP-supporting hardware until the 802.11i standard could be ratified. However, TKIP itself is no longer considered secure, and was deprecated in the 2012 revision of the 802.11 standard.

### AES-CCMP (WPA2)

The Counter/CBC-MAC Protocol (CCMP) is considered more secure than TKIP. CCMP consists of two algorithms:

■ AES (Advanced Encryption Standard) counter mode encryption.

■ Cipher Block Chaining Message Authentication Code (CBC-MAC) used as a message integrity check (MIC).

AES is open, publicly accessible, and is **the most secure encryption method** available today. AES is widely used around the world. AES is the encryption algorithm of choice for NIST and the U.S. government today.

CCMP cannot be used on legacy devices that only support WEP or TKIP. For CCMP to be used in a wireless network, the client devices and APs must support the AES counter mode and CBC-MAC in hardware. 

Devices that support CCMP have the WPA2 designation.

### AES-GCMP (WPA3)

The Galois/Counter Mode Protocol (GCMP) is a cryptographic protocol that provides confidentiality and integrity for data in wireless networks. It is used in the IEEE 802.11i standard for wireless security, and is also supported by some other wireless networking standards.

GCMP is an authenticated encryption suite that is more secure and more efficient than CCMP. GCMP consists of two algorithms:

■ AES counter mode encryption.

■ Galois Message Authentication Code (GMAC) used as a message integrity check (MIC). 

GCMP is used in WPA3.

### MIC (Message Integrity Check "Michael" in WPA)

A message integrity check (MIC) is a security tool that protects against data tampering. Two main types of MICs are:

1. Unkeyed Integrity Check (Cryptographic Hash): A function like SHA-256 calculates a unique "fingerprint" (a hash) of the data. A cryptographic hash protects against accidental corruption but not against a malicious attacker, because the attacker can simply alter the data and compute a new hash.
    
    - Example Use: Verifying a file download from a trusted website. The website displays the SHA-256 hash. You calculate the hash of the downloaded file. If they match, the file is intact. This only works because you trust the website itself not to be malicious.
        
2. Keyed Integrity Check (Message Authentication Code - MAC): A MAC algorithm uses a secret key known only to the sender and receiver to generate the integrity check value. An attacker cannot forge a valid MAC without knowing the secret key.
    
    - Examples: HMAC (Hash-based MAC), CMAC (Cipher-based MAC).

In a keyed integrity check (Message Authentication Code like Michael), a cryptographic algorithm calculates a MIC value from the message data and a secret key. The sender sends this MIC along with the message. The receiver recalculates the MIC using the shared secret key and compares the result to the transmitted value. A mismatch indicates tampering.

WPA uses a specific Message Authentication Code (MAC) called Michael. It is a keyed hash function. The access point and the client share a secret key to calculate and verify the MIC, preventing anyone without the key from tampering with the message.

MACs protect data in several ways:

- Verify file integrity: Websites can publish a MAC alongside a software download. Users verify the file's authenticity by recomputing the MAC with the correct key, ensuring no tampering occurred during transfer.
    
- Protect data in transit: Network protocols such as Transport Layer Security (TLS) use MACs to integrity-check data. The receiver discards any packet with an invalid MAC, preventing the acceptance of altered data.
    
- Prevent unauthorized access: By ensuring the integrity of authentication tokens or commands, MACs stop attackers from altering these elements to gain unauthorized privileges. Systems typically use encryption with a MAC to provide both confidentiality and integrity.

Figure 28-5 shows the MIC process.

<figure><img src="https://itnetworkingskills.wordpress.com/wp-content/uploads/2024/05/5aef3-checking-message-integrity-3.webp?w=1201" alt="Checking-Message-Integrity" height="430" width="1201"><figcaption><p>Figure 28-5 Checking Message Integrity over a Wireless Network (Odom, 2020, p. 710)</p></figcaption></figure>

WPA introduced the Michael message integrity check (MIC) to address the critical flaws in WEP. While an improvement, Michael remained vulnerable to forgery attacks. Michael was a temporary, weak MAC designed to run on legacy WEP hardware. It was better than WEP's CRC but had known vulnerabilities, which is why WPA2 replaced it with the much stronger AES-CCMP.

### Key takeaways

* Key encryption and message integrity algorithms used in securing wireless networks include TKIP (WPA), AES-CCMP (WPA2), AES-GCMP (WPA3), and Michael (WPA)

### References

Odom, W. (2020). CCNA 200-301 Official Cert Guide, Volume 1. Cisco Press.
