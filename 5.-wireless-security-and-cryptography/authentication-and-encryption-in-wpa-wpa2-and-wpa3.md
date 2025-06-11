---
description: >-
  This section compares authentication and encryption methods and algorithms
  used in WPA, WPA2, and WPA3
---

# Authentication and encryption in WPA, WPA2, and WPA3

Compare WPA, WPA2, and WPA3 protocols for authentication and encryption.

Describe wireless security protocols (WPA, WPA2, and WPA3).

Wi-Fi Protected Access (WPA) is a suite of security certifications for wireless networks, developed and maintained by the Wi-Fi Alliance (a nonprofit industry association that promotes Wi-Fi technology and interoperability). These certifications define security protocols to protect data transmitted over Wi-Fi. A wireless client device and an AP and its associated WLC certified by the Wi-Fi Alliance for the same WPA version are compatible and offer the same security components.

Table 28-2 Comparing WPA, WPA2, and WPA3 (Odom, 2020, p. 716)

<figure><img src="https://itnetworkingskills.wordpress.com/wp-content/uploads/2024/05/2b141-comparing-wpa-wpa2-wpa3-5.webp?w=1201" alt="Comparing-WPA-WPA2-WPA3" height="395" width="1201"><figcaption><p>Table 28-2 Comparing WPA, WPA2, and WPA3 (Odom, 2020, p. 716)</p></figcaption></figure>

**Personal mode**

#### **Summary Table: WPA, WPA2, WPA3 (Personal Mode)**

| **Protocol** | **Authentication**   | **Encryption**                      | **Integrity Method** | **Key Derivation**                      |
| ------------ | -------------------- | ----------------------------------- | -------------------- | --------------------------------------- |
| **WPA**      | PSK                  | TKIP (default), AES (optional)      | TKIP (MIC)           | PBKDF2 + PSK → TKIP keys                |
| **WPA2**     | PSK                  | AES-CCMP (default), TKIP (fallback) | AES-CCMP (CBC-MAC)   | PBKDF2 + PSK → CCMP keys                |
| **WPA3**     | SAE (replaces PSK\*) | AES-GCMP (default)                  | AES-GCMP (GMAC)      | SAE (Dragonfly handshake) → Robust keys |

WPA3-Personal: Replaces PSK with SAE for authentication (PSK is still the "password," but SAE is the protocol for key derivation). Uses AES-GCMP (or AES-CCMP in some early implementations) for encryption and integrity.

**Enterprise mode**

Here’s a summary table for **WPA, WPA2, and WPA3 in Enterprise mode**, which replaces **PSK/SAE** with **802.1X authentication** (typically using RADIUS servers and EAP methods).

***

#### **Summary Table: WPA, WPA2, WPA3 (Enterprise Mode)**

| **Protocol**        | **Authentication** | **Encryption**                 | **Integrity Method** | **Key Management**                                         |
| ------------------- | ------------------ | ------------------------------ | -------------------- | ---------------------------------------------------------- |
| **WPA-Enterprise**  | 802.1X (EAP)       | TKIP (default), AES (optional) | TKIP (MIC)           | Dynamic per-user keys via 4-way handshake                  |
| **WPA2-Enterprise** | 802.1X (EAP)       | AES-CCMP (default)             | AES-CCMP (CBC-MAC)   | Dynamic per-user keys (PMK/R0/R1 in 802.11r)               |
| **WPA3-Enterprise** | 802.1X (EAP)       | AES-256-GCMP (mandatory)       | AES-256-GCMP (GMAC)  | Enhanced key derivation (192-bit security suite, optional) |

***

#### **Key Differences from Personal Mode:**

1. **Authentication**:
   * **Enterprise modes use 802.1X + EAP** (e.g., EAP-TLS, PEAP, EAP-TTLS) instead of PSK/SAE.
   * A RADIUS server validates user/device credentials.
2. **Encryption & Integrity**:
   * **WPA-Enterprise**: Relies on **TKIP** (weak) by default, with AES as optional.
   * **WPA2-Enterprise**: Mandates **AES-CCMP** (128-bit).
   * **WPA3-Enterprise**: Requires **AES-256-GCMP** (stronger) and adds **192-bit cryptographic suite** (optional for high-security networks).
3. **Key Management**:
   * **Per-user, dynamic keys**: Each device gets unique session keys, preventing PSK-style attacks.
   * **WPA3-Enterprise**: Adds forward secrecy and stronger key derivation (e.g., CNSA-compliant for gov/military).
4. **Integrity Methods**:
   * **WPA**: TKIP’s MIC (vulnerable to spoofing).
   * **WPA2/WPA3**: AES-CCMP (WPA2) and AES-GCMP (WPA3) provide cryptographic integrity.

***

#### **Notes:**

* **WPA3-Enterprise Mode** has two "flavors":
  * **Mandatory**: AES-128-GCMP (same as WPA3-Personal).
  * **Optional (192-bit mode)**: Uses **AES-256-GCMP + SHA-384** for higher-security environments (e.g., government).
* **WPA2/WPA3-Enterprise** are the only modes compliant with modern security standards (e.g., PCI-DSS).

***

#### **Comparison to Personal Mode:**

| **Feature**        | **Enterprise Mode**    | **Personal Mode**          |
| ------------------ | ---------------------- | -------------------------- |
| **Authentication** | 802.1X + EAP           | PSK (WPA/WPA2), SAE (WPA3) |
| **Key Security**   | Per-user, dynamic      | Shared key (PSK)           |
| **Best for**       | Businesses, large orgs | Home/SOHO                  |

**Final review**

Table 28-3 Review of Wireless Security Mechanisms and Options (Odom, 2020, p. 718)

<figure><img src="https://itnetworkingskills.wordpress.com/wp-content/uploads/2024/05/0f424-wireless-security-mechanisms-7.webp?w=849" alt="Wireless-Security-Mechanisms" height="675" width="849"><figcaption><p>Table 28-3 Review of Wireless Security Mechanisms and Options (Odom, 2020, p. 718)</p></figcaption></figure>

### References

Odom, W. (2020). Chapter 28. Securing Wireless Networks, _CCNA 200-301 Official Cert Guide_ (pp. 704-719), Volume 1. Cisco Press.
