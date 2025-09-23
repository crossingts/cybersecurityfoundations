---
description: >-
  This section covers key wireless client authentication methods, including open
  authentication, WEP, PSK, SAE, and 802.1x/EAP
---

# Wireless client authentication methods

## Learning objectives

* Identify IEEE 802.11 as a basis for a wireless security management framework
* Become familiar with common wireless client authentication methods
* Identify common EAP-based authentication methods

This section has two main goals. First, this section introduces the IEEE 802.11 networking standard which provides a basis for a wireless security management framework (client authentication, message privacy, and message integrity). Second, this section introduces the wireless client authentication methods of open authentication, WEP, PSK, SAE, and 802.1x/EAP.

## Topics covered in this section

- **Introduction**
- **The IEEE 802.11 standard as a wireless security management framework**
  - **Authentication (trust)**
    - **Open authentication**
    - **WEP (Wired Equivalent Privacy)**
  - **Data privacy**
  - **Data integrity**
- **Wireless client authentication methods in chronological order**
* **Pre-Shared Key (PSK) and SAE (Simultaneous Authentication of Equals)**
* **Key developments within the IEEE 802.1x/EAP standard**
* **802.1x/EAP (Extensible Authentication Protocol)**
* **EAP-based authentication methods**
  * **LEAP (Lightweight EAP)**
  * **EAP-FAST (Flexible Authentication by Secure Tunneling)**
  * **PEAP (Protected EAP)**
  * **EAP-TLS (EAP Transport Layer Security)**

### Introduction

In a wireless connection, data is transmitted via radio waves that propagate in all directions, making it accessible to any nearby device within range. Unlike wired connections, which confine signals to physical cables, wireless signals are inherently broadcasted, allowing unintended recipients to potentially intercept them if not properly encrypted or secured.

A comprehensive approach to securing a wireless network involves:

1. Identifying the endpoints (authenticating client devices) – for example, using MAC address filtering or IEEE 802.1X certificate-based device authentication.
2. Authenticating the end user accessing the network – for example, via WPA2-Enterprise with EAP-TLS or EAP-PEAP for username/password verification.
3. Protecting the wireless data from eavesdroppers using encryption – for example, using AES-CCMP encryption (WPA3) or TKIP (legacy WPA).
4. Protecting the wireless data from tampering with frame authentication – for example, with IEEE 802.11’s frame integrity checks (MIC) or GCMP in WPA3.

Endpoint identification ensures only authorized devices connect, while user authentication verifies legitimate users. Together, these measures strengthen access control, while encryption and integrity checks safeguard data in transit.

### The IEEE 802.11 standard as a wireless security management framework

IEEE 802.11 is part of the IEEE 802 collection of technical standards for local area networks (LANs). The IEEE 802 standards are created and maintained by the Institute of Electrical and Electronics Engineers (IEEE) LAN/MAN Standards Committee (IEEE 802). 

IEEE 802.11 specifies the set of protocols for the medium access control (MAC) and physical layer (PHY) that implement wireless local area network (WLAN) computer communication. This standard and its amendments are the underlying technology for Wi-Fi branded products, making them the most widely used wireless computer networking standards globally. Commonly used in home and office settings, IEEE 802.11 allows devices such as laptops, printers, and smartphones to communicate with each other and access the Internet without wires. Furthermore, IEEE 802.11 provides the foundation for vehicle-based communication networks via IEEE 802.11p.

The IEEE 802.11 standard provides a basis for a wireless security management framework that can be used to add trust, privacy, and integrity to a wireless network. The following discussion gives a brief overview of the IEEE 802.11 standard.

#### Authentication (trust)

Clients must first discover a BSS (Basic Service Set) and then request permission to associate with it. Only trusted and expected devices should be given network access. Clients should be authenticated before they are allowed to associate. Potential clients must present a form of credentials to the APs (Access Points) to identify themselves. The original IEEE 802.11 standard gave only two options to authenticate clients: open authentication and WEP.

**Open authentication**

The open authentication process has only one requirement for a client wishing to access a WLAN, that they must use an IEEE 802.11 authentication request before attempting to associate with an AP. No other credentials are needed.

With no challenge, any IEEE 802.11 client may authenticate to access the network. That is, in fact, the whole purpose of open authentication—to validate that a client is a valid IEEE 802.11 device by authenticating the wireless hardware and the protocol. Authenticating the user’s identity is handled as a true security process through other means. (Odom, 2020, p. 710)

Client screening in WLANs with open authentication will often be a form of web authentication. Most client operating systems will flag WLANs with open authentication to warn you that your wireless data will not be secured in any way if you join.

After the open IEEE 802.11 connection is established, the user’s identity is authenticated by higher-layer security methods. These methods include Pre-Shared Key (PSK) for personal networks (like WPA2/3-Personal), the robust IEEE 802.1X framework with EAP for enterprise environments, and captive portals for public guest access.

**WEP (Wired Equivalent Privacy)**

WEP uses a shared key (WEP key) that must be known to both the sender and receiver ahead of time in order to encrypt and decrypt data. WEP keys are either 40 or 104 bits in length, represented by a string of 10 or 26 hex digits. Every potential client and AP must share the same key before any client can associate with the AP.

WEP uses the RC4 cipher algorithm to encrypt data that is transmitted over a wireless network. “The same algorithm encrypts data at the sender and decrypts it at the receiver. The algorithm uses a string of bits as a key, commonly called a WEP key, to derive other encryption keys—one per wireless frame” (Odom, 2020, p. 711).

The WEP key can also be used as an optional authentication method. A client not using the correct WEP key cannot associate with an AP. The AP sends a random challenge phrase to the client. The client must then encrypt this phrase using its WEP key and send the encrypted result back. The AP verifies the client's key by encrypting the same challenge itself and comparing the two results.

#### Data privacy

To protect data privacy on a wireless network, the data must be encrypted while it is traveling between clients and APs. This is done by encrypting the data payload in each wireless frame just before it is transmitted, and then decrypting it as it is received. The encryption method must be one that the transmitter and receiver share so that the data can be encrypted and decrypted successfully.

Only WEP (RC4-based) is defined in the original IEEE 802.11 standard. As noted, WEP’s shared key is both the authentication secret and encryption key, making it fundamentally insecure. Modern protocols such as Wi-Fi Protected Access (WPA2 and WPA3) derive temporary keys instead. WEP’s encryption was optional – networks could run unencrypted (open authentication + no encryption is one option; open authentication + WEP encryption is another option). No other encryption options existed until TKIP (WPA, 2003) and AES-CCMP (WPA2, 2004).

#### Data integrity

No true message authentication existed within the original IEEE 802.11 standard. WPA introduced Michael MIC, which was better than WEP but still vulnerable to forgery.

**Evolution of the IEEE 802.11 Security Protocols**

| **Feature**        | **Original 802.11 (1997)**          | **Modern Fix (WPA2/WPA3)**       |
| ------------------ | ----------------------------------- | -------------------------------- |
| **Privacy**        | WEP (RC4) or None (Open)            | AES-CCMP / GCMP                  |
| **Integrity**      | CRC-32 (ICV) – No security          | AES-CBC-MAC (CCMP) / GMAC (GCMP) |
| **Authentication** | Open System or Shared Key (WEP PSK) | 802.1X/EAP or SAE (WPA3)         |

While IEEE 802.11 defines the fundamental operation of Wi-Fi, its built-in security (Open and WEP) was fundamentally weak. The modern wireless security management framework is based primarily on the IEEE 802.11i amendment (2004), which introduced the Robust Security Network (RSN) framework. This framework underpins WPA2 and WPA3, providing the basis for strong authentication, encryption, and integrity.

The Wi-Fi Protected Access (WPA) protocol was introduced by the Wi-Fi Alliance in 2003 as an interim security standard to address the critical vulnerabilities of WEP, which by then were well-known. The full, robust IEEE 802.11i amendment was still under development and years away from final ratification. To provide a immediate solution, the Wi-Fi Alliance created WPA by defining a subset of the draft IEEE 802.11i specifications that were mature enough to implement. Essentially, WPA served as a "pre-standard" version of IEEE 802.11i, incorporating its key enhancements like the Temporal Key Integrity Protocol (TKIP) for dynamic encryption keys and the Michael message integrity check, thus providing a crucial stopgap of improved security while the industry awaited the stronger, final IEEE 802.11i standard (which would later be branded as WPA2).

**Comparison Table (WEP, WPA, WPA2, WPA3)**

|Protocol|Authentication|Encryption|Integrity Mechanism|Key Size / Security Suite|Introduced|
|---|---|---|---|---|---|
|**WEP**|Open System or Shared Key (WEP PSK)|RC4 (weak)|CRC-32 (ICV) – Easily forged|40-bit / 104-bit|1997 (802.11)|
|**WPA**|WPA-Personal (PSK) or WPA-Enterprise (802.1X/EAP)|TKIP (RC4 with fixes)|Michael MIC – Weak, but better than WEP|128-bit (TKIP)|2003 (Wi-Fi Alliance)|
|**WPA2-Personal**|PSK (Pre-Shared Key)|AES-CCMP (mandatory)|CCMP (AES-CBC-MAC) – Strong|128-bit (AES)|2004 (802.11i)|
|**WPA2-Enterprise**|802.1X/EAP|AES-CCMP (mandatory)|CCMP (AES-CBC-MAC) – Strong|128-bit (AES)|2004 (802.11i)|
|**WPA3-Personal**|SAE (Simultaneous Authentication of Equals)|AES-CCMP (mandatory); GCMP optional|CCMP (AES-CBC-MAC) – Strong|128-bit (AES)|2018|
|**WPA3-Enterprise**|802.1X/EAP (with stricter requirements)|AES-CCMP or AES-256-GCMP<sup>1</sup>|CCMP or 256-bit GMAC (with GCMP)|128-bit or 192-bit mode<sup>2</sup>|2018|

**Note:**

1. WPA3-Enterprise Encryption: The standard mode uses AES-CCMP (128-bit). The higher-security 192-bit mode, aligned with the CNSA suite, mandates AES-256-GCMP.
    
2. WPA3-Enterprise Key Size / Security Suite: This column is best understood as the minimum security strength of the cryptographic suite. The standard mode offers 128-bit strength. The optional 192-bit mode uses a 256-bit AES key (and other stronger algorithms) to achieve a higher overall security strength of 192 bits.

Technically, both the WEP key and the WPA/WPA2 PSK are pre-shared secrets used for network access. However, their security differs drastically due to how they are implemented, particularly in how they handle authentication and key management.

WEP uses the WEP key directly for both authentication (the client proves it knows the key by encrypting a challenge from the AP) and encryption (the same static key is used to encrypt all data packets via RC4). This direct use means compromising the key through the authentication process breaks both trust and privacy. In contrast, in WPA/WPA2-Personal the PSK itself is never used for encryption. Instead, the PSK serves as a starting point in a secure 4-Way Handshake that achieves two separate goals:

1. Secure authentication: The 4-Way Handshake mutually verifies that both the client and AP know the PSK.
    
2. Dynamic key derivation: The 4-Way Handshake generates unique, temporary session keys used solely for encrypting data with strong algorithms (TKIP or AES-CCMP).

This fundamental shift from a static secret to a dynamic key management system was a monumental security improvement. This separation of the authentication secret from the encryption keys is why PSK is fundamentally more secure than the WEP key.

### Wireless client authentication methods in chronological order

Wireless client authentication methods (sometimes generically referred to as IEEE 802.11 authentication methods or Wi-Fi authentication methods) can be categorized into Open System Authentication, Shared Key Authentication, and more advanced methods used in WPA/WPA2/WPA3. Follows is a list of wireless authentication methods in chronological order.

#### **1. Open System Authentication (1997 – IEEE 802.11 original standard)**

* No real authentication; any client can connect.
* Most common in public hotspots (e.g., cafes, airports).
* Often paired with captive portals (web-based login).

#### **2. Shared Key Authentication (WEP – 1997, deprecated)**

* Used a static 40/104-bit WEP key (easily crackable).
* Easily crackable; deprecated by early 2000s.

#### **3. WPA-Personal/WPA-Enterprise (2003 – Wi-Fi Alliance interim fix)**

* Introduced WPA-PSK (Pre-Shared Key) as a WEP replacement for home users.
* WPA-Enterprise (802.1X/EAP) for businesses. 802.1X/EAP is defined in IEEE 802.1X, not IEEE 802.11 itself. Used in WPA/WPA2/WPA3-Enterprise.

#### **4. WPA2-Personal/WPA2-Enterprise (2004 – IEEE 802.11i standard)**

* WPA2-PSK became the dominant Wi-Fi security method.
* WPA2-Enterprise (802.1X/EAP).
* Replaced TKIP with AES-CCMP (stronger encryption).

#### **5. Wi-Fi Protected Setup (WPS – 2006)**

* Simplified device onboarding (Push Button/PIN).
* Later found vulnerable to brute-force attacks.

#### **6. WPA3-Personal (2018 – Wi-Fi Alliance)**

* Introduced Simultaneous Authentication of Equals (SAE) to replace PSK.
* Protects against offline dictionary attacks.

#### **7. WPA3-Enterprise (2018)**

* WPA3-Enterprise (802.1X/EAP).
* Added 192-bit cryptographic suite for higher-security environments.
* Mandates use of AES-GCMP instead of TKIP.

#### **Note:**

1. 802.1X/EAP is not part of the original IEEE 802.11 standard:
   * It was introduced later (via IEEE 802.11i/WPA) for enterprise security.
   * 802.1X is a port-based authentication framework (from wired networks) adapted for Wi-Fi.
1. EAP methods (LEAP, PEAP, EAP-TLS, etc.) are not IEEE 802.11 authentication:
   * They are authentication protocols running inside 802.1X.
   * The actual IEEE 802.11 layer just facilitates the exchange (EAPoL frames).
1. Modern Wi-Fi uses a mix of IEEE 802.11 and non-802.11 auth methods:
   * WPA/WPA2-Personal (PSK/SAE) uses pre-shared keys, not part of original IEEE 802.11 auth.
   * WPA/WPA2/WPA3-Enterprise relies on 802.1X/EAP, not native IEEE 802.11.

### Pre-Shared Key (PSK) and SAE (Simultaneous Authentication of Equals)

There are several methods of wireless client authentication. One common method is to use a shared static text string, also known as a pre-shared key (PSK). The PSK is stored on the client device and is presented to the AP when the client attempts to connect to the network. Any user who possessed the device could authenticate to the network. More stringent authentication methods require interaction with a user database, with the end user entering a valid username and password.

In WPA-Personal and WPA2-Personal, the PSK (your Wi-Fi password) is used to derive encryption keys. In WPA3-Personal, PSK is replaced by SAE (Simultaneous Authentication of Equals) for authentication, a more secure method for key exchange (WPA3-Enterprise uses 802.1X for authentication)—the actual encryption in WPA3 uses AES-CCMP.

### Key developments within the IEEE 802.1x/EAP standard

IEEE 802.1X (Port-Based Network Access Control) and EAP (Extensible Authentication Protocol) are not tied to a single Wi-Fi security generation but have evolved alongside Wi-Fi authentication methods. The IEEE 802.1x/EAP standard is used in corporate/enterprise networks and relies on RADIUS servers and uses EAP-based authentication methods.

Here is a chronology of key developments within the IEEE 802.1x/EAP standard.

#### **1. Initial Introduction (2001 – IEEE 802.1X standard)**

* The IEEE 802.1X standard was originally ratified for port-based access control on wired Ethernet networks, providing a framework to authenticate devices before granting them network access. 
* IEEE 802.1X was later adopted as a cornerstone of Wi-Fi authentication with the introduction of WPA-Enterprise in 2003.
* EAP (RFC 2284, 1998) was integrated into 802.1X to provide a flexible authentication framework.
* Used in early enterprise Wi-Fi networks even before WPA/WPA2.

#### **2. Formal Wi-Fi Adoption (2003 – WPA-Enterprise)**

* When WPA was introduced, 802.1X/EAP became the backbone of WPA-Enterprise.
* Replaced WEP’s weak authentication with dynamic key generation via RADIUS servers.
* Common EAP methods at the time:
  * EAP-TLS (certificate-based, most secure but complex).
  * EAP-MD5 (deprecated, no encryption).
  * LEAP (Cisco-proprietary, later found insecure).

#### **3. WPA2-Enterprise (2004 – IEEE 802.11i)**

* 802.1X/EAP became the gold standard for enterprise Wi-Fi under WPA2.
* Newer EAP methods emerged:
  * PEAP (Protected EAP, e.g., PEAP-MSCHAPv2 for username/password).
  * EAP-TTLS (similar to PEAP but more flexible).
  * EAP-FAST (Cisco’s replacement for LEAP).

#### **4. WPA3-Enterprise (2018)**

* Still relies on 802.1X/EAP but with stricter security:
  * Mandates AES-256-GCMP encryption (vs. AES-CCMP in WPA2).
  * Introduces 192-bit security mode (for governments/enterprises).
* EAP-TLS remains the most secure method (certificate-based).

#### **5. Modern Usage (2020s)**

* 802.1X/EAP is still dominant in enterprises, universities, and large orgs.
* Cloud RADIUS services (e.g., Azure AD, Okta) now integrate with 802.1X.
* EAP-TLS is growing due to zero-trust security trends.

### Key takeaways

* 802.1X/EAP is not a Wi-Fi authentication method itself but a framework used by WPA-Enterprise (2003), WPA2-Enterprise (2004), and WPA3-Enterprise (2018).
* Common EAP-based authentication methods include LEAP, EAP-FAST, PEAP, and EAP-TLS.
* EAP methods evolved from weak (LEAP, EAP-MD5) to robust (EAP-TLS, PEAP).
* Still the most secure Wi-Fi authentication method when properly configured (e.g., with certificates).

### References

Odom, W. (2020). CCNA 200-301 Official Cert Guide, Volume 1. Cisco Press.