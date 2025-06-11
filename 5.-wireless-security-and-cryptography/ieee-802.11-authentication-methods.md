---
description: >-
  This section covers key IEEE 802.11 authentication methods, including open
  authentication, WEP, and 802.1x/EAP
---

# IEEE 802.11 authentication methods

This section has two main goals. First, this section will hep students understand how the IEEE 802.11 standard provides a basis for a wireless security management framework (client authentication, message privacy, and message integrity). Second, this section will familiarize students with authentication methods used in the IEEE 802.11 wireless networking standard.&#x20;

In a wireless connection, data is transmitted via radio waves that propagate in all directions, making it accessible to any nearby device within range. Unlike wired connections, which confine signals to physical cables, wireless signals are inherently broadcasted, allowing unintended recipients to potentially intercept them if not properly encrypted or secured.

A comprehensive approach to securing a wireless network involves:

1. **Identifying the endpoints** (authenticating client devices) of the wireless connection – for example, using **MAC address filtering** or **IEEE 802.1X certificate-based device authentication**.
2. **Authenticating the end user** accessing the network – for example, via **WPA2-Enterprise** with **EAP-TLS** or **EAP-PEAP** for username/password verification.
3. **Protecting the wireless data from eavesdroppers** using encryption – for example, using **AES-CCMP encryption** (WPA3) or **TKIP** (legacy WPA).
4. **Protecting the wireless data from tampering** with frame authentication – for example, with **802.11’s frame integrity checks (MIC)** or **GCMP** in WPA3.

Endpoint identification ensures only authorized devices connect, while user authentication verifies legitimate users. Together, these measures strengthen access control, while encryption and integrity checks safeguard data in transit.

* **Wireless client authentication methods**
  * **Open authentication**
  * **WEP (Wired Equivalent Privacy)**
  * **802.1x/EAP (Extensible Authentication Protocol)**
  * **EAP-based authentication methods**
    * **LEAP (Lightweight EAP)**
    * **EAP-FAST (Flexible Authentication by Secure Tunneling)**
    * **PEAP (Protected EAP)**
    * **EAP-TLS (EAP Transport Layer Security)**

#### The IEEE 802.11 standard

The IEEE 802.11 standard provides a wireless security management framework to be used to add trust, privacy, and integrity to a wireless network. The following discussion gives an overview of the wireless security framework.

**Authentication (trust)**

Clients must first discover a BSS and then request permission to associate with it. Only trusted and expected devices should be given network access. Clients should be authenticated before they are allowed to associate. Potential clients must present a form of credentials to the APs to identify themselves.&#x20;

There are several methods of wireless authentication. One common method is to use a shared static text string, also known as a pre-shared key (PSK). The PSK is stored on the client device and is presented to the AP when the client attempts to connect to the network. Any user who possessed the device could authenticate to the network. More stringent authentication methods require interaction with a user database, with the end user entering a valid username and password.

**Data privacy**

To protect data privacy on a wireless network, the data must be encrypted while it is traveling between clients and APs. This is done by encrypting the data payload in each wireless frame just before it is transmitted, and then decrypting it as it is received. The encryption method must be one that the transmitter and receiver share, so that the data can be encrypted and decrypted successfully.

In WPA/WPA2-Personal, the PSK (your Wi-Fi password) is used to derive encryption keys. In WPA3-Personal, PSK is replaced by SAE, a more secure method for key exchange.

For encryption, WPA uses TKIP (AES optional), and WPA2 uses AES-CCMP (default), TKIP (fallback).

**Data integrity**

A message integrity check (MIC) is a security tool that can protect against data tampering. A MIC is a value that is calculated from the data in a message using a cryptographic algorithm. The MIC is then sent along with the message. When the message is received, the MIC is recalculated and compared to the value that was sent. If the two values do not match, then the message has been tampered with.&#x20;

There are two main types of MICs:

* Hash functions: these calculate a value that is a fixed size, regardless of the size of the data that is hashed.&#x20;
* Message authentication codes (MACs): these calculate a value that is the same size as the data that is being protected.

MICs can be used to protect data in a variety of ways. For example, they can be used to:

* Verify the integrity of files that are downloaded from the internet.
* Protect data that is being transmitted over a network.
* Prevent unauthorized access to data.

#### IEEE 802.11 authentication methods

IEEE 802.11 (Wi-Fi) authentication methods can be categorized into **Open System Authentication**, **Shared Key Authentication**, and more advanced methods used in **WPA/WPA2/WPA3**. Below is a list of IEEE 802.11 authentication methods in chronological order.

#### **1. Open System Authentication (1997 – 802.11 original standard)**

* No real authentication; any client can connect.
* **Most common in public hotspots** (e.g., cafes, airports).
* Often paired with **captive portals** (web-based login).

#### **2. Shared Key Authentication (WEP – 1997, deprecated)**

* Used a static 40/104-bit WEP key (easily crackable).
* Easily crackable; deprecated by early 2000s.

#### **3. WPA-Personal/WPA-Enterprise (2003 – Wi-Fi Alliance interim fix)**

* Introduced **TKIP** (Temporal Key Integrity Protocol) as a WEP replacement.
* **WPA-PSK (Pre-Shared Key)** for home users.
* **WPA-Enterprise (802.1X/EAP)** for businesses.

#### **4. WPA2-Personal/WPA2-Enterprise (2004 – 802.11i standard)**

* Replaced TKIP with **AES-CCMP** (stronger encryption).
* **WPA2-PSK** became the dominant Wi-Fi security method.
* **WPA2-Enterprise** with EAP methods (e.g., PEAP, EAP-TLS) for corporations.

#### **5. Wi-Fi Protected Setup (WPS – 2006)**

* Simplified device onboarding (Push Button/PIN).
* Later found vulnerable to brute-force attacks.

#### **6. WPA3-Personal (2018 – Wi-Fi Alliance)**

* Introduced **Simultaneous Authentication of Equals (SAE)** to replace PSK.
* Protects against offline dictionary attacks.

#### **7. WPA3-Enterprise (2018)**

* Added **192-bit cryptographic suite** for higher-security environments.
* Mandates use of **AES-GCMP** instead of TKIP.

#### **8. WPA3-Enhanced Open (OWE – 2018)**

* Replaced **Open Authentication** with encryption (no passwords).
* Protects against passive eavesdropping in public Wi-Fi.

#### **9. WPA3 Version 2 (2022–2023 updates)**

* Further refinements in SAE and enterprise security.
* Phasing out legacy protocols (e.g., WPA2 transition guidance).

