# IEEE 802.1x/EAP: EAP-based authentication methods

### 802.1x/EAP (Extensible Authentication Protocol)

Client authentication typically involves a challenge-response mechanism, in which the client is presented with a challenge and must provide a correct response in order to be authenticated. Client authentication can also involve the exchange of session or encryption keys.

When 802.1x is enabled, for a wireless client to gain access to the network, the client must first associate with an AP and then successfully authenticate. The client uses open authentication to associate with the AP, and then the actual client authentication occurs at a dedicated authentication server.  This is different from open and WEP authentication where wireless clients are authenticated locally at the AP without further intervention.&#x20;

The three-party 802.1x arrangement involves of the following entities:

■ Supplicant: The client device requesting access. The client is the device that is trying to connect to the network, while the supplicant is the software on the client that is responsible for actually authenticating with the network.

■ Authenticator: The network device providing (controlling) access to the network, a LAN switch or a WLC.

■ Authentication server (AS): The device that takes client credentials and permits or denies network access based on a user database and policies (usually a **RADIUS** server).

<figure><img src="https://itnetworkingskills.wordpress.com/wp-content/uploads/2024/05/dbe52-802.1x-client-authentication-roles-4.webp?w=1201" alt="802.1x-Client-Authentication-Roles" height="395" width="1201"><figcaption><p>Figure 28-6 802.1x Client Authentication Roles (Odom, 2020, p. 712)</p></figcaption></figure>

The WLC acts as a middleman in the client authentication process, controlling user access according to 802.1x and communicating with the authentication server using the EAP framework.

The **Extensible Authentication Protocol (EAP)** is a flexible and scalable authentication framework. “EAP defines a set of common functions that actual authentication methods can use to authenticate users” (p. 712). EAP is commonly integrated with the **IEEE 802.1x** port-based access control standard.&#x20;

The client authentication process involving a WLC is as follows:

* The client device sends a wireless association request to the AP.
* The AP forwards the request to the WLC.
* The WLC authenticates the client device via a RADIUS server.
* If the client device is authenticated successfully, the WLC grants access to the network.
* The client device can then start sending and receiving data on the network.

The RADIUS server uses a variety of authentication methods, such as passwords, certificates, and biometrics.

The WLC uses the RADIUS server to authenticate client devices because it is a more secure and scalable approach to protecting wireless networks from unauthorized access than authenticating client devices directly on the AP. The RADIUS server can be located in a central location, which makes it easier to manage and secure. Additionally, the RADIUS server can support a large number of client devices, which is ideal for large networks.

Benefits of using a WLC for client authentication include:

* Centralized management: WLCs allow network administrators to manage all of their APs from a single location. This can save time and effort, and it can also help to improve security.
* Increased scalability: WLCs can support more APs than standalone APs. This makes them ideal for large networks.
* Improved performance: WLCs can improve the performance of wireless networks by offloading some of the processing tasks from the APs.
* Robust security: WLCs can use a variety of authentication methods, such as passwords, certificates, and biometrics. This makes them a more secure solution than authenticating client devices directly on the AP.

### EAP-based authentication methods

The following discussion gives an overview of some common EAP-based authentication methods.&#x20;

Note, when configuring user authentication on a WLAN, you do not need to select a specific authentication method. Instead, you select 802.1x on the WLC. This will allow the WLC to handle a variety of EAP methods. The client and authentication server will then use a compatible method. Once 802.1X is enabled on the WLC, the client and authentication server will negotiate a method to use.

**\*LEAP (Lightweight EAP)**

Lightweight Extensible Authentication Protocol (**LEAP**) is a wireless authentication method that uses challenge-response messages to authenticate clients. LEAP was developed by Cisco in an early attempt to address the weaknesses in WEP.

The client sends its username and password to the authentication server, which then generates a challenge message and sends it back to the client. The client encrypts the challenge message using its password and sends it back to the authentication server. The authentication server then decrypts the challenge message and compares it to the original challenge message. If the messages match, the authentication server grants access to the client.

This process provides mutual authentication because both the client and the authentication server must be able to successfully decrypt the challenge messages. If either party is unable to decrypt the messages, the authentication will fail.

LEAP attempted to overcome WEP weaknesses by using dynamic WEP keys that changed frequently. Nevertheless, the method used to encrypt the challenge messages was found to be vulnerable, so LEAP has since been deprecated. (p. 713)

Wireless clients and controllers may still offer LEAP, but you should not use it.

**\*EAP-FAST (EAP Flexible Authentication by Secure Tunneling)**

In Cisco’s more secure authentication method called EAP Flexible Authentication by Secure Tunneling (**EAP-FAST**), authentication credentials are protected by passing a protected access credential (**PAC**) between the AS and the supplicant. The PAC is a shared secret generated by the AS and used for mutual authentication.&#x20;

EAP-FAST constitutes of a sequence of three phases:

■ Phase 0: The PAC is generated by the AS and installed on the client.

■ Phase 1: The supplicant and AS authenticate each other and then they negotiate a Transport Layer Security (TLS) tunnel.

■ Phase 2: The end user can then be authenticated through the TLS tunnel.

Like in other EAP-based authentication, a RADIUS server (AS) is required. However, the RADIUS server must also operate as an EAP-FAST server to be able to generate PACs, one per user.

**\*PEAP (Protected EAP)**

The Protected EAP (PEAP) method, like EAP-FAST, uses an inner authentication (inside the TLS tunnel) and outer authentication (outside the TLS tunnel), but in the outer authentication the AS presents a digital certificate to authenticate itself with the supplicant. If the supplicant authenticates the AS, they both build a TLS tunnel to be used for the inner client authentication and encryption key exchange.

The digital certificate of the AS consists of data in a standard format that identifies the owner and is “signed” or validated by a third party. The third party is known as a certificate authority (CA) and is known and trusted by both the AS and the supplicants. The supplicant must also possess the CA certificate just so that it can validate the one it receives from the AS. The certificate is also used to pass a public key, in plain view, which can be used to help decrypt messages from the AS. (p. 713)

In this process, only the AS has a certificate for PEAP, so the supplicant can readily authenticate the AS. Since the client does not use a certificate of its own, the client must be authenticated within the TLS tunnel via one of the following two methods:

■ MSCHAPv2: Microsoft Challenge Authentication Protocol version 2.

■ GTC: Generic Token Card; a hardware device that generates one-time passwords for the user or a manually generated password.

**\*EAP-TLS (EAP Transport Layer Security)**

PEAP uses a digital certificate on the AS to authenticate the RADIUS server. The clients have to identify themselves through other means. EAP Transport Layer Security (EAP- TLS) goes one step above PEAP by requiring certificates on the AS and on every client device. With EAP-TLS, the AS and the supplicant exchange certificates and authenticate each other. A TLS tunnel is then built to exchange encryption key material.

EAP-TLS is considered “**the most secure wireless authentication method available**” but its implementation can be complex.

Along with the AS, each wireless client must obtain and install a certificate. Manually installing certificates on hundreds or thousands of clients can be impractical. Instead, you would need to implement a Public Key Infrastructure (PKI) that could supply certificates securely and efficiently and revoke them when a client or user should no longer have access to the network. (p. 714)

EAP-TLS can only be used if the wireless clients can accept and use digital certificates.&#x20;

### References

Odom, W. (2020). Chapter 28. Securing Wireless Networks, _CCNA 200-301 Official Cert Guide_ (pp. 704-719), Volume 1. Cisco Press.
