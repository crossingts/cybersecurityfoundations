# How asymmetric encryption enables secure key exchange and server authentication during the handshake

How asymmetric encryption enables secure key exchange and server authentication during the handshake in TLS 1.2 and TLS 1.3:

Let's break it down:

* **Secure key exchange**: This is true for both, but the mechanism is different.
  * In **TLS 1.2 (with RSA key exchange)**, asymmetric encryption _directly_ performs the key exchange by encrypting the pre-master secret.
  * In **TLS 1.2 (with ECDHE) and TLS 1.3**, asymmetric encryption is _not_ used to encrypt the key exchange material. Instead, it is used only to **authenticate** the Diffie-Hellman parameters (i.e., to sign them), while the key exchange itself is done using the DH algorithm. The key exchange algorithm itself (Diffie-Hellman) is an asymmetric cryptosystem. It enables the secure computation of a shared secret over an insecure channel. The server's static public key (RSA/ECDSA) is then used to authenticate the DH parameters, making the entire key exchange process secure.
* **Server authentication**: This is **always** a core function of asymmetric encryption in both TLS 1.2 and 1.3. The server proves its identity by:
  1. Presenting a certificate containing its public key, which is signed by a CA (asymmetric cryptography).&#x20;
  2. Proving it owns the private key for that certificate. This proof is done differently:
     * In **TLS 1.2 RSA key exchange**, the proof is implicit: the server decrypts the client's encrypted pre-master secret. Only the true server can do this.
     * In **TLS 1.2 ECDHE** and **TLS 1.3**, the proof is explicit: the server uses its private key to sign a hash of the handshake messages (in the `CertificateVerify` message). The client uses the server's public key to authenticate the server.
