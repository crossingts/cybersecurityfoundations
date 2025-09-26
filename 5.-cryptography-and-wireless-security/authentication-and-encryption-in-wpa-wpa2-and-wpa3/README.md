---
description: >-
  This section compares authentication and encryption methods and algorithms
  used in WPA, WPA2, and WPA3
---

# Authentication and encryption in WPA, WPA2, and WPA3

## Learning objectives

* Become familiar with key authentication and encryption methods and algorithms used in WPA, WPA2, and WPA3

This section compares WPA, WPA2, and WPA3 wireless security protocols for authentication and encryption methods and algorithms.

## Topics covered in this section

* **Introduction**
* **Cryptographic methods and algorithms in personal and enterprise modes**
* **Final review**

### Introduction

Wi-Fi Protected Access (WPA) is a suite of security certifications for wireless networks, developed and maintained by the Wi-Fi Alliance (a nonprofit industry association that promotes Wi-Fi technology and interoperability). These certifications define security protocols to protect data transmitted over Wi-Fi. A wireless client device and an AP and its associated WLC certified by the Wi-Fi Alliance for the same WPA version are compatible and offer the same security components.

There are three WPA versions: WPA, WPA2, and WPA3. The first generation WPA certification (known simply as WPA) was introduced while the IEEE 802.11i amendment was still under development. The Wi-Fi Alliance based WPA on parts of 802.11i and included 802.1x authentication and Temporal Key Integrity Protocol (TKIP).

The Wi-Fi Alliance incorporated the full IEEE 802.11i standard into its WPA2 certification after it was ratified and published. WPA2 uses the superior AES CCMP algorithms instead of the deprecated TKIP algorithms from WPA. WPA2 was intended to replace WPA.

The Wi-Fi Alliance introduced WPA3 in 2018, adding several important and superior security mechanisms. WPA3 uses stronger AES encryption with the Galois/Counter Mode Protocol (GCMP). WPA3 also uses Protected Management Frames (PMF) to secure important 802.11 management frames between APs and clients. This prevents malicious activity targeting a BSS’s operation.

The Wi-Fi Alliance made wireless security configuration straightforward and consistent through its WPA, WPA2, and WPA3 certifications. WPA, WPA2, and WPA3 simplify wireless network configuration and compatibility because they limit which authentication and privacy/integrity methods can be used.  

If you are using WPA, you should consider using WPA2 instead—at least until WPA3 becomes widely available on wireless client devices, APs, and WLCs.

The three WPA versions support two client authentication modes, based on the scale of the deployment:  

* A pre-shared key (PSK) or personal mode
* 802.1x or enterprise mode

### Cryptographic methods and algorithms in personal and enterprise modes

Table 28-2 Comparing WPA, WPA2, and WPA3 (Odom, 2020, p. 716)

<figure><img src="https://itnetworkingskills.wordpress.com/wp-content/uploads/2024/05/2b141-comparing-wpa-wpa2-wpa3-5.webp?w=1201" alt="Comparing-WPA-WPA2-WPA3" height="395" width="1201"><figcaption><p>Table 28-2 Comparing WPA, WPA2, and WPA3 (Odom, 2020, p. 716)</p></figcaption></figure>

#### Personal mode

With personal mode, a key string must be shared or configured on every client and AP before the clients can connect to the wireless network. The pre-shared key is normally kept confidential so that unauthorized users have no knowledge of it. The key string is never sent over the air. Instead, clients and APs work through a four-way handshake procedure that uses the pre-shared key string to construct and exchange encryption key material that can be openly exchanged. Once that process is successful, the AP can authenticate the client and the two can secure data frames that are sent over the air. (p. 717)

With WPA-Personal and WPA2-Personal modes, a malicious user can intercept the four-way handshake between a client and an AP and then use a dictionary attack to guess the pre-shared key. If successful, the malicious user can then decrypt the wireless data or join the network as if a legitimate user.

WPA3-Personal can defeat such an attack by strengthening the key exchange between clients and APs using a method known as Simultaneous Authentication of Equals (SAE). “Rather than a client authenticating against a server or AP, the client and AP can initiate the authentication process equally and even simultaneously.

WPA3-Personal offers forward secrecy, so, even if a password or key is compromised, attackers are prevented from being able to use a key to unencrypt data that has already been transmitted over the air.

The Personal mode of any WPA version is easy to deploy in a small environment because a simple text key string is all that is needed to authenticate the clients.  

Note that all devices using the WLAN must be configured with an identical pre-shared key. Changing the key means every device using the WLAN must be updated.  

#### **Summary Table: WPA, WPA2, WPA3 (Personal Mode)**

| **Protocol** | **Authentication**   | **Encryption**                      | **Integrity Method** | **Key Derivation**                      |
| ------------ | -------------------- | ----------------------------------- | -------------------- | --------------------------------------- |
| **WPA**      | PSK                  | TKIP (default), AES (optional)      | TKIP (MIC)           | PBKDF2 + PSK → TKIP keys                |
| **WPA2**     | PSK                  | AES-CCMP (default), TKIP (fallback) | AES-CCMP (CBC-MAC)   | PBKDF2 + PSK → CCMP keys                |
| **WPA3**     | SAE (replaces PSK\*) | AES-GCMP (default)                  | AES-GCMP (GMAC)      | SAE (Dragonfly handshake) → Robust keys |

WPA3-Personal: Replaces PSK with SAE for authentication (PSK is still the "password," but SAE is the protocol for key derivation). Uses AES-GCMP (or AES-CCMP in some early implementations) for encryption and integrity.

#### Enterprise mode

Here’s a summary table for **WPA, WPA2, and WPA3 in Enterprise mode**, which replaces **PSK/SAE** with **802.1X authentication** (typically using RADIUS servers and EAP methods).

**Summary Table: WPA, WPA2, WPA3 (Enterprise Mode)**

| **Protocol**        | **Authentication** | **Encryption**                 | **Integrity Method** | **Key Management**                                         |
| ------------------- | ------------------ | ------------------------------ | -------------------- | ---------------------------------------------------------- |
| **WPA-Enterprise**  | 802.1X (EAP)       | TKIP (default), AES (optional) | TKIP (MIC)           | Dynamic per-user keys via 4-way handshake                  |
| **WPA2-Enterprise** | 802.1X (EAP)       | AES-CCMP (default)             | AES-CCMP (CBC-MAC)   | Dynamic per-user keys (PMK/R0/R1 in 802.11r)               |
| **WPA3-Enterprise** | 802.1X (EAP)       | AES-256-GCMP (mandatory)       | AES-256-GCMP (GMAC)  | Enhanced key derivation (192-bit security suite, optional) |

**Key Differences from Personal Mode:**

1. **Authentication**:
   * **Enterprise modes use 802.1X + EAP** (e.g., EAP-TLS, PEAP, EAP-TTLS) instead of PSK/SAE.
   * A RADIUS server validates user/device credentials.
2. **Encryption & Integrity**:
   * **WPA-Enterprise**: Relies on **TKIP** (weak) by default, with AES as optional.
   * **WPA2-Enterprise**: Mandates **AES-CCMP** (128-bit).
   * **WPA3-Enterprise**: Requires **AES-256-GCMP** (stronger) and adds **192-bit cryptographic suite** (optional for high-security networks).
3. **Integrity Methods**:
   * **WPA**: TKIP’s MIC (vulnerable to spoofing).
   * **WPA2/WPA3**: AES-CCMP (WPA2) and AES-GCMP (WPA3) provide cryptographic integrity.
4. **Key Management (Enterprise mode)**:
   * **WPA/WPA2: Per-user, dynamic keys**: Each device gets unique session keys, preventing PSK-style attacks.
   * **WPA3-Enterprise**: Adds forward secrecy and stronger key derivation (e.g., CNSA-compliant for gov/military).
   * **WPA2/WPA3-Enterprise** are the only modes compliant with modern security standards (e.g., PCI-DSS).

Notice from Table 28-2 that WPA, WPA2, and WPA3 support 802.1x or enterprise authentication. This implies EAP-based authentication, but the WPA versions do not require any specific EAP method. Instead, the Wi-Fi Alliance certifies interoperability with well- known EAP methods like EAP-TLS, PEAP, EAP-TTLS, and EAP-SIM. Enterprise authentication is more complex to deploy than personal mode because authentication servers must be set up and configured as a critical enterprise resource. (p. 717)

### Final review

Remember that an effective wireless security strategy includes a method to authenticate clients and a method to provide data privacy and integrity. These two types of methods are listed in the leftmost column. Work your way to the right to remember what types of authentication and privacy/integrity are available. (Odom, 2020, p. 718)

Table 28-3 Review of Wireless Security Mechanisms and Options (Odom, 2020, p. 718)

<figure><img src="https://itnetworkingskills.wordpress.com/wp-content/uploads/2024/05/0f424-wireless-security-mechanisms-7.webp?w=849" alt="Wireless-Security-Mechanisms" height="675" width="849"><figcaption><p>Table 28-3 Review of Wireless Security Mechanisms and Options (Odom, 2020, p. 718)</p></figcaption></figure>

### Key takeaways

* Key authentication methods in personal mode include PSK (WPA, WPA2) and SAE (WPA3)
* Enterprise mode uses the 802.1X (EAP) authentication method
* Key encryption algorithms in personal and enterprise mode include TKIP (WPA), AES-CCMP (WPA2), and AES-GCMP (WPA3)

### References

Odom, W. (2020). CCNA 200-301 Official Cert Guide, Volume 1. Cisco Press.
