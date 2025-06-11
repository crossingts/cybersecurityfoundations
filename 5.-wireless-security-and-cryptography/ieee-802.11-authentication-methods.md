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

* **Wireless security framework**
  * **Authentication**
  * **Message privacy**
  * **Message integrity**
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

#### &#x20;IEEE 802.11 authentication methods
