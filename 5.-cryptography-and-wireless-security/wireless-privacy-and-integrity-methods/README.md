---
description: This section covers key wireless privacy and integrity algorithms, including TKIP (WPA), MIC "Michael" (WPA), AES-CCMP (WPA2), and AES-GCMP (WPA3)
---

# Wireless privacy and integrity methods

## Learning objectives

* Explain the vulnerabilities in WEP that necessitated the development of TKIP and the Michael MIC
- Differentiate between unkeyed hashes and keyed Message Authentication Codes (MACs) for ensuring data integrity
- Describe the function of TKIP and the Michael MIC as interim security measures for WEP-era hardware
- Identify AES-CCMP as the core security protocol for WPA2 and AES-GCMP for WPA3, highlighting their advantages over previous standards
- Understand the progression from WPA to WPA3 as a response to evolving security threats and hardware capabilities

This section traces the evolution of key encryption and integrity algorithms developed to protect Wi-Fi networks. It covers interim solutions like TKIP and the Michael MIC, which were designed for legacy hardware, their security limitations, and the modern, robust protocols that replaced them. More specifically, this sections cover the following encryption and integrity algorithms: TKIP (WPA), MIC (Message Integrity Check "Michael" in WPA), AES-CCMP (WPA2), and AES-GCMP (WPA3).

## Topics covered in this section

* **TKIP (WPA)**
* **MIC (Message Integrity Check "Michael" in WPA)**
* **AES-CCMP (WPA2)**
* **AES-GCMP (WPA3)**

### TKIP (WPA)

WEP (Wired Equivalent Privacy) was included as the privacy component of the original IEEE 802.11 standard ratified in 1997. WEP uses the stream cipher RC4 for confidentiality, and the CRC-32 checksum for integrity. 
After a major design flaw in the algorithm was disclosed in 2001, WEP was no longer considered secure. 

In August 2001, Scott Fluhrer, Itsik Mantin, and Adi Shamir published a cryptanalysis of WEP that exploited the way RC4 and IVs were used, enabling a passive attack that could recover the RC4 key after eavesdropping on network traffic. Depending on traffic volume, a successful key recovery could take as little as one minute. If insufficient packets were available, attackers could stimulate traffic by sending packets to the network and analyzing the replies. The attack was quickly implemented, and automated tools were released. With a personal computer, standard hardware, and freely available software such as aircrack-ng, WEP keys can be cracked in minutes. (Wikipedia)

Under WEP it was possible to alter a packet whose content was known even if it had not been decrypted. 
An attacker who knows the original plaintext of a packet can alter it to say anything they want, and then create a valid checksum for the modified packet, all without knowing the WEP key or decrypting the packet.

WEP suffered two major security flaws that led to its demise. The fundamental cryptographic weakness that allowed the key to be recovered in minutes was the fatal blow. It transformed WEP from a privacy tool into a wide-open door. Further, the integrity flaw (ICV) was a critical enabler for attacks.




WEP was deprecated in 2004. The breaking of WEP had left Wi-Fi networks without viable link-layer security, and a solution was required for already deployed hardware.
Temporal Key Integrity Protocol (TKIP) was designed by the IEEE 802.11i task group and the Wi-Fi Alliance as an interim solution to replace WEP without requiring the replacement of legacy hardware. 

WPA (2003) primarily used TKIP as its encryption method. WPA2 (2004) made AES-CCMP mandatory as the encryption method, with TKIP as an optional fallback for backward compatibility. WPA3 mandated AES-256-GCMP for WPA3-Personal and WPA3-Enterprise.
In WPA-Personal and WPA2-Personal, the PSK (your Wi-Fi password) is used to derive encryption keys. In WPA3-Personal, PSK is replaced by SAE for authentication but the actual encryption in WPA3 uses AES-GCMP for enterprise.

To be able to run on legacy WEP hardware with minor upgrades, TKIP uses RC4 as its cipher. TKIP also provides a rekeying mechanism. TKIP ensures that every data packet is sent with a unique encryption key (Interim Key/Temporal Key + Packet Sequence Counter). Key mixing increases the complexity of decoding the keys by giving an attacker substantially less data that has been encrypted using any one key.

TKIP brought the following security features using legacy hardware and the underlying WEP encryption (pp. 714-715):

■ MIC: This efficient algorithm adds a hash value to each frame as a message integrity check to prevent tampering; commonly called “Michael” as an informal reference to MIC.

■ Time stamp: A time stamp is added into the MIC to prevent replay attacks that attempt to reuse or replay frames that have already been sent.

■ Sender’s MAC address: The MIC also includes the sender’s MAC address as evidence of the frame source.

■ TKIP sequence counter: This feature provides a record of frames sent by a unique MAC address, to prevent frames from being replayed as an attack.

■ Key mixing algorithm: This algorithm computes a unique 128-bit WEP key for each frame.

■ Longer initialization vector (IV): The IV size is doubled from 24 to 48 bits, making it virtually impossible to exhaust all WEP keys by brute-force calculation.

TKIP became a stopgap measure to enable stronger encryption on WEP-supporting hardware until the 802.11i standard could be ratified. However, TKIP itself is no longer considered secure, and was deprecated in the 2012 revision of the 802.11 standard.

### MIC (Message Integrity Check "Michael" in WPA)

A message integrity check (MIC) is a security tool that protects against data tampering. Two main types of MICs are:

1. Unkeyed Integrity Check (Cryptographic Hash): A function like SHA-256 calculates a unique "fingerprint" (a hash) of the data. A cryptographic hash protects against accidental corruption but not against a malicious attacker, because the attacker can simply alter the data and compute a new hash.
    
    - Example Use: Verifying a file download from a trusted website. The website displays the SHA-256 hash. You calculate the hash of the downloaded file. If they match, the file is intact. This only works because you trust the website itself not to be malicious.
        
2. Keyed Integrity Check (Message Authentication Code - MAC): A MAC algorithm uses a secret key known only to the sender and receiver to generate the integrity check value. An attacker cannot forge a valid MAC without knowing the secret key.
    
    - Examples: HMAC (Hash-based MAC), CMAC (Cipher-based MAC).

In a keyed integrity check (Message Authentication Code like Michael), a cryptographic algorithm calculates a MIC value from the message data and a secret key. The sender sends this MIC along with the message. The receiver recalculates the MIC using the shared secret key and compares the result to the transmitted value. A mismatch indicates tampering. Figure 28-5 shows the MIC process.

<figure><img src="https://itnetworkingskills.wordpress.com/wp-content/uploads/2024/05/5aef3-checking-message-integrity-3.webp?w=1201" alt="Checking-Message-Integrity" height="430" width="1201"><figcaption><p>Figure 28-5 Checking Message Integrity over a Wireless Network (Odom, 2020, p. 710)</p></figcaption></figure>

WPA uses a specific Message Authentication Code (MAC) called Michael. It is a keyed hash function. The access point and the client share a secret key to calculate and verify the MIC, preventing anyone without the key from tampering with the message.

MACs protect data in several ways:

- Verify file integrity: Websites can publish a MAC alongside a software download. Users verify the file's authenticity by recomputing the MAC with the correct key, ensuring no tampering occurred during transfer.
    
- Protect data in transit: Network protocols such as Transport Layer Security (TLS) use MACs to integrity-check data. The receiver discards any packet with an invalid MAC, preventing the acceptance of altered data.
    
- Prevent unauthorized access: By ensuring the integrity of authentication tokens or commands, MACs stop attackers from altering these elements to gain unauthorized privileges. Systems typically use encryption with a MAC to provide both confidentiality and integrity.

WPA introduced the Michael message integrity check (MIC) to address the critical flaws in WEP. While an improvement, Michael remained vulnerable to forgery attacks. Michael was a temporary, weak MAC designed to run on legacy WEP hardware. It was better than WEP's CRC but had known vulnerabilities, which is why WPA2 replaced it with the much stronger AES-CCMP.

### AES-CCMP (WPA2)

The Counter/CBC-MAC Protocol (CCMP) is considered more secure than TKIP. CCMP consists of two algorithms:

■ AES (Advanced Encryption Standard) counter mode encryption.

■ Cipher Block Chaining Message Authentication Code (CBC-MAC) used as a message integrity check (MIC).

AES is open, publicly accessible, and is the most secure encryption method available today. AES is widely used around the world. AES is the encryption algorithm of choice for NIST and the U.S. government today.

CCMP cannot be used on legacy devices that only support WEP or TKIP. For CCMP to be used in a wireless network, the client devices and APs must support the AES counter mode and CBC-MAC in hardware. 

Devices that support CCMP have the WPA2 designation.

### AES-GCMP (WPA3)

The Galois/Counter Mode Protocol (GCMP) is a cryptographic protocol that provides confidentiality and integrity for data in wireless networks. It is used in the IEEE 802.11i standard for wireless security, and is also supported by some other wireless networking standards.

GCMP is an authenticated encryption suite that is more secure and more efficient than CCMP. GCMP consists of two algorithms:

■ AES counter mode encryption.

■ Galois Message Authentication Code (GMAC) used as a message integrity check (MIC). 

GCMP is used in WPA3.
### Key takeaways

* The failure of WEP's weak integrity check (CRC-32) and RC4 cipher created an urgent need for new wireless security protocols.
- TKIP and the Michael MIC were designed as interim solutions for legacy hardware, introducing key security improvements like per-packet keys and message integrity checks without requiring new hardware.
- A keyed Message Authentication Code (MAC), unlike a simple cryptographic hash, uses a secret key to prevent malicious actors from forging data integrity checks.
- While an improvement, both TKIP (based on RC4) and the Michael MIC had known vulnerabilities and were ultimately deprecated.
- WPA2 established AES-CCMP as the mandatory, robust replacement, combining AES encryption for confidentiality with CBC-MAC for integrity.
- WPA3 introduces AES-GCMP as a more efficient and secure authenticated encryption protocol, especially for enterprise networks.
- The evolution from WPA to WPA3 represents a shift from backward-compatible patches to requiring modern, dedicated hardware for strong security.
- Key encryption and message integrity algorithms used in securing wireless networks include TKIP (WPA), Michael MIC (WPA), AES-CCMP (WPA2), and AES-GCMP (WPA3).

### References

Edney, J., & Arbaugh, W. A. (2004). *Real 802.11 Security: Wi-Fi Protected Access and 802.11i*. Addison-Wesley Professional.

Odom, W. (2020). *CCNA 200-301 Official Cert Guide, Volume 1*. Cisco Press.