# Burp Suite cheat sheet for netadmins/sysadmins

The ultimate web app security testing toolkit for penetration testers and security professionals—perfect for intercepting, analyzing, and exploiting web vulnerabilities.

This cheat sheet covers:

✔ **Proxy setup & traffic interception**\
✔ **Vulnerability scanning & exploitation**\
✔ **Repeater & Intruder techniques**\
✔ **Tips for efficient web app testing**

## **Burp Suite Cheat Sheet**

_Proxy & Interception, Vulnerability Scanning, and Repeater & Intruder Techniques_

***

### **1. Setup & Configuration**

#### **Launch Burp Suite**

bash

```
burpsuite   # Community/Pro edition  
```

#### **Configure Browser Proxy**

* **Proxy IP:** `127.0.0.1`
* **Port:** `8080` (default)
* **Disable HTTPS warnings** (install Burp CA certificate)

#### **Import CA Certificate**

1. Visit `http://burp` in browser
2. Download `cacert.der`
3. Import into browser/OS trust store

***

### **2. Proxy & Interception**

#### **Intercept HTTP/S Requests**

* Turn **Intercept on/off** (`Proxy → Intercept`)
* **Forward** (send request)
* **Drop** (block request)

#### **Modify Requests**

* Edit headers, parameters, cookies
* Right-click → **Send to Repeater/Intruder**

#### **Match & Replace Rules**

* `Proxy → Options → Match and Replace`
* Auto-modify requests/responses (e.g., User-Agent, cookies)

***

### **3. Scanner (Pro Feature)**

#### **Run Automated Scan**

1. `Target → Site map` → Right-click → **Scan**
2. Select scan type (**Active/Passive**)

#### **Configure Scan Settings**

* `Scanner → Scan queue` → Fine-tune insertion points

***

### **4. Repeater**

#### **Manual Request Testing**

* Send requests, modify, and replay
* Compare responses (`< >` diff view)

#### **Tips**

* Use **Ctrl+R** to quickly send to Repeater
* Enable **Follow Redirects** for chain testing

***

### **5. Intruder (Automated Attacks)**

#### **Attack Types**

* **Sniper:** Single payload, one position
* **Battering ram:** Single payload, multiple positions
* **Pitchfork:** Multiple payloads (parallel)
* **Cluster bomb:** Multiple payloads (combinatorial)

#### **Payload Sets**

* Simple list, numbers, dates, custom regex
* Load from file (`Payloads → Load`)

#### **Example: Brute-Force Login**

1. Send request to Intruder
2. Mark `username` & `password` as payload positions
3. Load wordlists → Start attack

***

### **6. Other Modules**

#### **Sequencer (Session Token Analysis)**

* `Proxy → HTTP history` → Right-click → **Send to Sequencer**
* Check randomness of tokens/cookies

#### **Decoder (Data Transformation)**

* Encode/decode Base64, URL, HTML, hex, etc.
* Smart decode (auto-detect encoding)

#### **Comparer (Diff Tool)**

* Compare responses byte-by-byte

***

### **7. Tips & Tricks**

#### **Bypass Client-Side Validation**

* Intercept → Modify input limits (`maxlength`, JS checks)

#### **Test for IDOR**

* Change IDs in requests (e.g., `user_id=100 → 101`)

#### **Find Hidden Endpoints**

* `Target → Site map` → Spider feature
* Check `robots.txt`, JS files

***

### **Quick Reference Table**

| **Shortcut**   | **Action**                      |
| -------------- | ------------------------------- |
| `Ctrl+Shift+D` | Send to Repeater                |
| `Ctrl+I`       | Send to Intruder                |
| `Ctrl+R`       | Send to Scanner (Pro)           |
| `Alt+Q`        | Switch to Quick send (Repeater) |

***

**Pro Tips:**\
✔ Use **Burp Collaborator** (Pro) for blind SSRF/RCE detection\
✔ Save projects (`Project → Save`) for long-term testing\
✔ Combine with **OAuth testing extensions** for API security

**Learn More:**

* [PortSwigger Academy](https://portswigger.net/web-security)
* `Help → Burp Suite Documentation`
