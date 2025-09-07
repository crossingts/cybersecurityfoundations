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

Temporal Key Integrity Protocol (**TKIP**) was designed by the IEEE 802.11i task group and the Wi-Fi Alliance as an interim solution to replace WEP without requiring the replacement of legacy hardware. Under WEP it was possible to alter a packet whose content was known even if it had not been decrypted. The breaking of WEP had left Wi-Fi networks without viable link-layer security, and a solution was required for already deployed hardware.&#x20;

WPA (2003) primarily uses TKIP (Temporal Key Integrity Protocol) as its encryption method. AES was optional in WPA but not commonly supported. WPA2 (2004) made AES-CCMP mandatory as the encryption method, with TKIP as an optional fallback for backward compatibility. WPA3 mandates AES-CCMP (128-bit) for WPA3-Personal. WPA3-Enterprise supports AES-256-GCMP (stronger encryption for enterprise networks).

In WPA-Personal and WPA2-Personal, the PSK (your Wi-Fi **password**) is used to derive encryption keys. In WPA3-Personal, PSK is replaced by SAE for authentication but the actual encryption in WPA3 uses AES-CCMP (AES-GCMP for enterprise).

To be able to run on legacy WEP hardware with minor upgrades, **TKIP uses RC4 as its cipher.** TKIP also provides a rekeying mechanism. TKIP ensures that every data packet is sent with a unique encryption key (Interim Key/Temporal Key + Packet Sequence Counter). Key mixing increases the complexity of decoding the keys by giving an attacker substantially less data that has been encrypted using any one key.&#x20;

TKIP brought the following security features using legacy hardware and the underlying WEP encryption (pp. 714-715):

■ MIC: This efficient algorithm adds a hash value to each frame as a message integrity check to prevent tampering; commonly called “**Michael**” as an informal reference to MIC.

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

CCMP cannot be used on legacy devices that only support WEP or TKIP. For CCMP to be used in a wireless network, the client devices and APs must support the AES counter mode and CBC-MAC in hardware.&#x20;

Devices that support CCMP have the WPA2 designation.

### AES-GCMP (WPA3)

The Galois/Counter Mode Protocol (GCMP) is a cryptographic protocol that provides confidentiality and integrity for data in wireless networks. It is used in the IEEE 802.11i standard for wireless security, and is also supported by some other wireless networking standards.

GCMP is an authenticated encryption suite that is more secure and more efficient than CCMP. GCMP consists of two algorithms:

■ AES counter mode encryption.

■ Galois Message Authentication Code (GMAC) used as a message integrity check (MIC).&#x20;

GCMP is used in WPA3.

### MIC (Message Integrity Check "Michael" in WPA)

WPA introduced Michael MIC, which was better than WEP but still vulnerable to forgery.

A message integrity check (MIC) is a security tool that can protect against data tampering. A MIC is a value that is calculated from the data in a message using a cryptographic algorithm. The MIC is then sent along with the message. When the message is received, the MIC is recalculated and compared to the value that was sent. If the two values do not match, then the message has been tampered with.&#x20;

There are two main types of MICs:

* Hash functions: these calculate a value that is a fixed size, regardless of the size of the data that is hashed.&#x20;
* Message authentication codes (MACs): these calculate a value that is the same size as the data that is being protected.

MICs can be used to protect data in a variety of ways. For example, they can be used to:

* Verify the integrity of files that are downloaded from the internet.
* Protect data that is being transmitted over a network.
* Prevent unauthorized access to data.

MICs are an important part of many security protocols. For example, they are used in the Transport Layer Security (TLS) protocol, which is used to secure web traffic.

MICs are often used in conjunction with encryption to provide a higher level of security. But MICs are not perfect, and they can be fooled by attackers who have access to the cryptographic algorithm. Figure 28-5 shows the MIC process.

<figure><img src="https://itnetworkingskills.wordpress.com/wp-content/uploads/2024/05/5aef3-checking-message-integrity-3.webp?w=1201" alt="Checking-Message-Integrity" height="430" width="1201"><figcaption><p>Figure 28-5 Checking Message Integrity over a Wireless Network (Odom, 2020, p. 710)</p></figcaption></figure>

### Key takeaways

* Key encryption and message integrity algorithms used in securing wireless networks include TKIP (WPA), AES-CCMP (WPA2), AES-GCMP (WPA3), and Michael (WPA)

### References

Odom, W. (2020). CCNA 200-301 Official Cert Guide, Volume 1. Cisco Press.
