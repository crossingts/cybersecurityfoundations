# Pretty Good Privacy (PGP)

## How to encrypt your communications using PGP (GPG)

Pretty Good Privacy (PGP) is an encryption program that provides cryptographic privacy and authentication for data communication. PGP is a real-world application of asymmetric encryption. This discussion shows you how to start exchanging encrypted messages using PGP to safeguard your privacy.

* **Introduction: PGP is darn good privacy**
* **The PGP encryption and decryption process**
* **Ensure GPG is installed**
* **Generating a new key pair**
* **Share your public key so others can encrypt emails to you**
* **Test your PGP key with encryption/decryption**
* **How to send me encrypted emails using PGP (GPG)**
* **How to send me an authenticated message**

### Introduction: PGP is darn good privacy <a href="#ember614" id="ember614"></a>

PGP (Pretty Good Privacy) is one of the most secure and widely trusted encryption systems when used correctly. First, PGP provides strong encryption via a combination of symmetric key encryption (e.g., AES, CAST5) and asymmetric encryption (e.g., RSA, ECC). Messages are encrypted with a one-time session key, which is itself encrypted with the recipient's public key. This hybrid approach is highly secure against brute-force attacks if strong algorithms (e.g., AES-256, RSA-4096) are used. Second, PGP provides message integrity (via hashing) and sender verification (via digital signatures). Finally, unlike many modern messaging apps, PGP does not rely on centralized servers that could be compromised - only the intended recipient (with the private key) can decrypt the message.

The OpenPGP standard (RFC 4880) is an open standard for encrypting and decrypting data. GnuPG (GNU Privacy Guard) or GPG is the most widely used free and open-source implementation of OpenPGP and alternative to Symantec's cryptographic software suite PGP.

### The PGP encryption and decryption process <a href="#ember617" id="ember617"></a>

User A wants to send User B an encrypted email.

<figure><img src="../../.gitbook/assets/image (3).png" alt="How PGP Encryption Works" width="563"><figcaption></figcaption></figure>

* First, using GPG, User A generates a random symmetric session key using AES or 3DES (GPG defaults to AES-256 since \~2014). This key is only used once.
* User A encrypts their message to User B using the session key.
* User A fetches User B’s public key (RSA/ECDH/ElGamal) from a trusted source.
* Next, User A encrypts the session key using the public key of User B. The public key is tied to a particular person’s identity in a PGP certificate, and anyone can use it to send them a message.
* (Optional) User A signs the message with their own private key for authentication.
* User A sends User B the encrypted message along with the encrypted session key (and optional signature).
* User B is able to decrypt the session key using their private key.
* Using the session key, the recipient is now able to decrypt the actual message.
* (If signed) User B verifies the signature using User A’s public key.

### Ensure GPG is installed <a href="#ember621" id="ember621"></a>

which gpg # ensure GPG is installed

gpg --version | head -n1 # check your GPG version

brew install gnupg # install GPG on macOS

brew update && brew upgrade gnupg # update Homebrew and upgrade GnuPG

#### List your GPG public keys <a href="#ember627" id="ember627"></a>

gpg --list-keys # check if you have any existing public keys

user@hostname \~ % gpg --list-keys

gpg: directory '/Users/user/.gnupg' created

gpg: /Users/user/.gnupg/trustdb.gpg: trustdb created

In this case, this is the first time GPG is being used on this macOS user account. The gpg --list-keys command tried to check for existing PGP keys, but it couldn’t find the GPG directory (\~/.gnupg). So GPG automatically:

* Created the directory /Users/user/.gnupg (where keys and settings are stored).
* Generated a trustdb.gpg file (a database tracking which keys you trust).

#### Generate a new key pair or import existing keys <a href="#ember635" id="ember635"></a>

If you want to start using PGP (e.g., for encrypted emails or signing commits), run:

gpg --full-generate-key

Follow the prompts to create an RSA key.

If you already have a PGP key, import it to the GPG keyring:

gpg --import /path/to/your/private-key.asc

### Generating a new key pair <a href="#ember643" id="ember643"></a>

user@hostname \~ % gpg --full-generate-key

gpg (GnuPG) 2.4.7; Copyright (C) 2024 g10 Code GmbH This is free software: you are free to change and redistribute it. There is NO WARRANTY, to the extent permitted by law.

Please select what kind of key you want: (1) RSA and RSA (2) DSA and Elgamal (3) DSA (sign only) (4) RSA (sign only) (9) ECC (sign and encrypt) _default_ (10) ECC (sign only) (14) Existing key from card

Since you want people to **send you encrypted emails**, you need a key that supports **both signing and encryption**.

**Recommended selection:** (1) RSA and RSA, since RSA is the most widely compatible algorithm (works with all email clients like Thunderbird, ProtonMail, etc.). This option creates: 1) A **primary RSA key** for **signing/certifying** (\[SC]). 2) A **subkey (RSA)** for **encryption** (\[E]), which is what others will use to encrypt emails to you.

**How to proceed:** Type 1 and press **Enter**. Next, set the **key size**: Choose **4096 bits** (stronger security) if prompted. Set an **expiration date** (e.g., 5y for 5 years). Enter your **name** and **email** (use the email where you want to receive encrypted messages). Protect the key with a **strong passphrase**.

#### Verify GPG public keys <a href="#ember651" id="ember651"></a>

Run gpg --list-keys again after generating/importing keys.

user@hostname \~ % gpg --list-keys

\[keyboxd]

\---------

pub   rsa4096 2025-05-02 \[**SC**] \[expires: 2030-05-01]

2FC6F12930D378E3048EC6286CA33C2D9F494DB1 **← full fingerprint (last 16 characters = Key ID)**

uid           \[ultimate] Firstname Lastname \<example@example.com>

sub   rsa4096 2025-05-02 \[**E**] \[expires: 2030-05-01]

* pub = Public key → primary key
* uid = Your identity (name & email)
* sub = Subkey (**usually for encryption**)
* \[SC] = Signing (S) + Certifying (C)
* \[E] = Encryption
* \[S] = Signing (rarely used; most just use the primary key).
* **Key ID** = The last **16 characters** of the long hex string after pub (e.g., 6CA33C2D9F494DB1).
* **Full fingerprint (or just "fingerprint")** = The entire string.

#### Check for private keys <a href="#ember662" id="ember662"></a>

gpg --list-secret-keys # no output means you don’t have a private key

user@hostname \~ % gpg --list-secret-keys

\[keyboxd]

\---------

sec   rsa4096 2025-05-02 \[**SC**] \[expires: 2030-05-01]

2FC6F12930D378E3048EC6286CA33C2D9F494DB1

uid           \[ultimate] Firstname Lastname \<example@example.com>

ssb   rsa4096 2025-05-02 \[**E**] \[expires: 2030-05-01]

* sec = Secret (private) key → primary key
* ssb = Secret subkey

#### Why subkeys exist <a href="#ember672" id="ember672"></a>

The distinction between the **primary key (pub/sec)** and **subkey (sub/ssb)** in PGP/GPG is designed for security and practicality. A primary key pair (pub/sec) and subkey pair (sub/ssb) serve different roles:

* **Primary Key (pub/sec)**: Used for **signing** (proving identity) and **certifying** other keys (e.g., "I trust this person’s key"). Typically has a long expiration (or none) because losing it compromises your identity. **Not used for encryption/decryption** (unless explicitly configured otherwise).
* **Subkey (sub/ssb)**: Often used for **encryption/decryption** (marked \[E] in gpg --list-keys). Can also be used for **signing** (marked \[S]), but this is less common. Designed to be **replaceable** (shorter expiry, can be revoked without affecting your primary key).

#### How encryption works in practice <a href="#ember675" id="ember675"></a>

1. **Sender** encrypts a message using the **recipient’s public subkey (**\[E]**)**.
2. **Recipient** decrypts it using their **private subkey (**\[E]**)** (not the primary private key).
3. **Signing** works similarly: You sign a message with your **primary private key (**\[SC]**)** (or a signing subkey if you have one). Others verify it with your **primary public key**.

#### After generating the key: <a href="#ember678" id="ember678"></a>

* Share your public key so others can encrypt emails to you
* Test your PGP key with encryption/decryption

### Share your public key so others can encrypt emails to you <a href="#ember681" id="ember681"></a>

**Export your public key**:

gpg --armor --export example@example.com

* This retrieves your public key from your GPG keyring (stored in \~/.gnupg/).
* \--armor ensures it’s ASCII-formatted (readable text, not binary). ASCII armor is email-friendly formatting. The ASCII-armored output can be pasted directly into an email.
* You can use your OpenPGP Key ID in lieu of the email address

This displays the public key in your terminal. Upload it to a keyserver, share it on your social media, or send it directly to your contacts. The keyserver acts like a public directory where people upload their OpenPGP keys.

gpg --armor --export example@example.com > public.asc

This saves a copy of the exported key to a file (type/extension: ASCII armor) named public.asc in your current working directory.

user@hostname \~ % gpg --armor --export example@example.com

\-----BEGIN PGP PUBLIC KEY BLOCK-----

mQINBGgU7b0BEAC6iYroybQHWstvOT312TxdDtsDGdQEPjI8RMmG1doqDQ+Wp0we

0NShyUp0M1YRfgO6ZfrIR1V4CSj20T9drnhqK73L...

\-----END PGP PUBLIC KEY BLOCK-----

**Upload your public key to a keyserver (for discoverability):**

hkps://keys.openpgp.org (recommended for privacy and control)

gpg --keyserver hkps://keys.openpgp.org --send-keys YOUR\_KEY\_FINGERPRINT

(Replace YOUR\_KEY\_FINGERPRINT with the fingerprint from gpg --list-keys.)

user@hostname \~ % gpg --keyserver hkps://keys.openpgp.org --send-keys 2FC6F12930D378E3048EC6286CA33C2D9F494DB1

gpg: sending key 6CA33C2D9F494DB1 to hkps://keys.openpgp.org

**Verify email (for searchability):**

1. **Check your email inbox** for a verification link from keys.openpgp.org.
2. Click the link to confirm ownership.
3. Your email will now be searchable on the keyserver.

### Test your PGP key with encryption/decryption <a href="#ember703" id="ember703"></a>

#### Encrypt a message (using your public key) <a href="#ember704" id="ember704"></a>

Run this command (replace example@example.com with your actual email):

echo "Test message" | gpg --encrypt --armor --recipient example@example.com

* echo "Test message" → Creates a plaintext message.
* gpg --encrypt → Encrypts it.
* \--armor → Outputs in ASCII (readable) format instead of binary.
* \--recipient example@example.com → Uses your public key to encrypt.
* You can use your OpenPGP Key ID in lieu of the email address

**Expected output:**

\-----BEGIN PGP MESSAGE-----

hQEMAx1l1JZJ8d...

\-----END PGP MESSAGE-----

You can copy this encrypted message and save it to a file (e.g., encrypted.asc), manually or using the command line.

**Manually:**

* Select and copy the text (from -----BEGIN PGP MESSAGE----- to -----END PGP MESSAGE-----).
* Paste the text into a new file. Using TextEdit worked for me. I pasted the encrypted text in a new file, removed the formatting, and saved the file as a .txt file to my desktop.

I decrypted the file with the command: gpg --decrypt \~/Desktop/encrypted.txt

**Using the command line:**

* Select and copy the text (from -----BEGIN PGP MESSAGE----- to -----END PGP MESSAGE-----).
* Paste the text into a new file using: pbpaste > \~/Desktop/encrypted.asc

This saves a copy of the key in a file named encrypted.asc on your Desktop. Open it later with: open \~/Desktop/encrypted.asc

Decrypt encrypted.asc with: gpg --decrypt \~/Desktop/encrypted.asc

#### Decrypt the message (using your private key) <a href="#ember721" id="ember721"></a>

#### Method 1: Direct pasting into the terminal <a href="#ember722" id="ember722"></a>

Run:

gpg --decrypt --armor

* Immediately paste the entire encrypted block (including -----BEGIN PGP MESSAGE----- and -----END PGP MESSAGE-----). Do this while GPG is waiting for input (before pressing Enter again).
* Press Ctrl+D to signal the end of input. This tells GPG: "I’m done pasting; proceed."

**You will be promoted to enter your passphrase.**

#### Method 2: Encrypt and save to a file directly <a href="#ember728" id="ember728"></a>

Instead of printing to terminal, save the encrypted message to a file:

echo "Test message" | gpg --encrypt --armor --recipient example@example.com > encrypted.asc

Then decrypt it:

gpg --decrypt encrypted.asc # prints the decrypted content directly to the terminal

Or

gpg --decrypt encrypted.asc > decrypted.txt # saves the output to the current working directory

**You will be promoted to enter your passphrase.**

### How to send me encrypted emails using PGP (GPG) <a href="#ember737" id="ember737"></a>

#### Example workflow <a href="#ember738" id="ember738"></a>

* Alice wants to send an encrypted email to Bob: Alice fetches Bob’s public key (gpg --recv-keys bob@example.com). She encrypts the message using Bob’s encryption subkey (\[E]). Bob decrypts it with his private encryption subkey (\[E]).
* (Optional) Bob signs a message with his primary private key (\[SC]). Alice verifies it with Bob’s primary public key.

#### Step 1: Get my public key <a href="#ember740" id="ember740"></a>

**Download from a Keyserver**:

* Go to keys.openpgp.org
* Search for my **Key ID**: 6CA33C2D9F494DB1
* Click the result → Download (saves as a .asc file, e.g., as 2FC6F12930D378E3048EC6286CA33C2D9F494DB1.asc).

<figure><img src="../../.gitbook/assets/image (1) (1).png" alt="keys.openpgp.org"><figcaption></figcaption></figure>

Next, import 2FC6F12930D378E3048EC6286CA33C2D9F494DB1.asc to the GPG keyring:

gpg --import 2FC6F12930D378E3048EC6286CA33C2D9F494DB1.asc

Or, import the public key directly to the GPG keyring using the **Command Line (Linux/macOS)**:

```
gpg --keyserver hkps://keys.openpgp.org --recv-keys 6CA33C2D9F494DB1
```

This imports the public key. An output of "not changed" means GPG already has your public key in its local keyring database, typically in \~/.gnupg/pubring.kbx (modern GnuPG) or \~/.gnupg/pubring.gpg (older versions). You've previously imported the key.

List all keys in your keyring (the Key ID is the last 16 characters of the fingerprint):

gpg --list-keys

**Verify the fingerprint** (Critical!):

```
gpg --fingerprint 6CA33C2D9F494DB1
```

user@hostname \~ % gpg --fingerprint 6CA33C2D9F494DB1

pub   rsa4096 2025-05-02 \[SC] \[expires: 2030-05-01]

2FC6 F129 30D3 78E3 048E  C628 6CA3 3C2D 9F49 4DB1

uid           \[ultimate] Firstname Lastname \<example@example.com>

sub   rsa4096 2025-05-02 \[E] \[expires: 2030-05-01]

**Confirm with me** that the fingerprint matches (e.g., via Proton Mail/Signal/SMS/in person).

#### Step 2: Encrypt your message <a href="#ember758" id="ember758"></a>

1. Save your message to a file (e.g., message.txt).
2. Encrypt it using my public key:

**Option 1:**

gpg --encrypt --armor --recipient 6CA33C2D9F494DB1 message.txt

* Output filename: Automatically set to message.txt.asc (appends .asc to the original filename).
* Behavior: GPG defaults to adding .asc (for armored output) or .gpg (for binary output) to the input filename.
* Creates file "message.txt.asc" with the encrypted text message (ciphertext you can paste into an email) in your current working directory.

**Option 2:**

gpg --encrypt --armor --recipient 6CA33C2D9F494DB1 --output message.asc message.txt

* Output filename: Explicitly set to message.asc (no automatic .txt.asc suffix).
* Behavior: You manually control the output filename with --output.
* Creates file "message.asc" with the encrypted text message (ciphertext you can paste into an email) in your current working directory.

**Note:**

* Options 1 and 2 both produce the exact same encrypted content (ASCII-armored ciphertext suitable for email). The only difference is the filename.
* Some corporate email systems block .asc attachments (paste into email body instead).

**Option 3:**

Encrypt directly in an email client. For example, Thunderbird with Enigmail: Compose email → Enable encryption → Select your key.

CLI (for email body):

echo "Hello Courage!" | gpg --encrypt --armor --recipient 6CA33C2D9F494DB1

(Produces ASCII-armored output to paste into an email.)

#### Step 3: Email the encrypted message <a href="#ember774" id="ember774"></a>

1. **Attach** message.asc to an email (or copy-paste the -----BEGIN PGP MESSAGE----- block into the body).
2. **Subject line**: Use something generic like "Encrypted Message".
3. **Do not include sensitive info in unencrypted parts** (e.g., subject line).

### How to send me an authenticated message <a href="#ember777" id="ember777"></a>

The message sender can sign their message (e.g., message.txt) using their private GPG key for authentication.

**Option 1: Sign the encrypted message itself**

```
# Encrypt AND sign in one step (recommended)
gpg --sign --encrypt --armor --recipient example@example.com --output message.asc message.txt
```

* \--sign: Signs the message.
* \--encrypt: Encrypts the message.
* \--armor: Outputs in ASCII-armored format (instead of binary).
* \--recipient: Specifies the recipient.
* \--output message.asc: Sets the output file.
* message.txt: The input file to be processed.

**What the command does**:

* Encrypts message.txt with my public key (you're sending me an encrypted message).
* **Signs it with sender's private key** (proves it came from them).
* Outputs a single message.asc file containing both the encrypted content and signature (signed and encrypted and ASCII-armored).

**How to send**:

* Attach message.asc to an email or paste its content in the email body.
* No separate signature file needed.

**Why this is best**:

* Prevents tampering with both content **and metadata** (e.g., someone swapping attachments).
* Standard practice in tools like Enigmail/ProtonMail.

The message recipient decrypts the message with their private key (gpg --decrypt message.asc), and GPG automatically verifies the sender's signature if the sender’s public key is in the recipient's keyring.

**This is the most common and secure method** because:

* The signature is protected by encryption (so an attacker can’t strip it).
* The entire message (including signature) is confidential.

**Decryption**:

```
gpg --decrypt message.asc
```

GPG automatically verifies sender's signature during decryption.

**What I see**:

```
gpg: Good signature from "Sender's Name <sender@example.com>"
[Decrypted content]
```

Signing the encrypted message this way is sufficient for:

1. **Authentication** (proves the sender’s identity via their private key).
2. **Integrity** (ensures the message wasn’t modified after signing).

To verify the sender’s signature (to authenticate the message), I need the sender’s public key.

**What happens when I decrypt without the sender's public key**

When I run:

```
gpg --decrypt message.asc > message.txt
```

GPG performs **two actions**:

1. **Decrypts** the message using _my private key_ (since it was encrypted for me@proton.me).
2. **Attempts to verify the signature** using the _sender’s public key_ (if available in my keyring).

**If I don’t have the sender’s public key:**

* The decryption **succeeds** (l'll see the plaintext in message.txt).
* But GPG will **warn me** that it _could not verify the signature_:

**Option 2 (paranoid mode): Adding a clearsigned plaintext note**

The sender has encrypted and signed a message to send to me (e.g., message.asc) using:

gpg --encrypt --armor --sign -r example@example.com -o message.asc message.txt

(Option 1: Sign the encrypted message itself)

**Next**, the sender can create a clearsigned plaintext note (note.txt). For example:

```
Hello,  
This is a cryptographic signature to verify my identity. My OpenPGP Key ID is <key_id>. 
Please find the encrypted message attached.  
PS: I may be paranoid, but that doesn't mean they're not out to get me.
```

Run:

gpg --armor --clearsign note.txt

Or

gpg --clearsign --armor --output note.txt.asc note.txt

Output: note.txt.asc (readable text)

```
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA256

Hello,
This is a cryptographic signature to verify my identity. My OpenPGP Key ID is <key_id>. 
Please find the encrypted message attached.  
PS: I may be paranoid, but that doesn't mean they're not out to get me.
-----BEGIN PGP SIGNATURE-----
[ASCII-armored signature block]
-----END PGP SIGNATURE-----
```

Send the message: Send both files

**Method 1**: Email body + attachment

* Paste note.txt.asc (clearsigned note) in the **email body**.
* Attach message.asc (encrypted message).

**Method 2**: Two attachments

* Attach both note.txt.asc and message.asc.

#### Verify and decrypt <a href="#ember820" id="ember820"></a>

**1. Verify the clearsigned note** to confirm the sender’s identity: gpg --verify note.txt.asc

* If I don’t have the sender’s public key, GPG will warn me.
* Fetch the sender's key (e.g., from a keyserver) and retry verification.

**2. Decrypt the attached** message.asc: gpg --decrypt message.asc > decrypted.txt

GPG will:

* Decrypt using _the recipient's_ (my) private key.
* Verify the embedded signature (if signed) using the _sender’s_ public key.
