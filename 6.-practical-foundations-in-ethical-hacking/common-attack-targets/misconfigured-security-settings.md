# Misconfigured security settings

## Topics covered

* **Insecure default settings**
* **Misconfigured security settings**
* **How to prevent misconfiguration vulnerabilities**

### Insecure default settings

Misconfigurations occur when systems, applications, or networks are improperly set up, often due to reliance on default settings that prioritize ease of deployment over security. Here are common examples:

**1. Default Credentials**

* Many devices (routers, IoT devices, servers) ship with **default usernames and passwords** (e.g., `admin:admin`).
* **Example:** Attackers scan for devices with unchanged default logins (e.g., Mirai botnet exploited default IoT credentials).

**2. Open or Unrestricted Ports & Services**

* Unnecessary services (e.g., Telnet, FTP, SMB) left enabled by default.
* **Example:** EternalBlue exploited open SMB ports in Windows systems.

**3. Excessive Permissions**

* Default configurations granting **unnecessary privileges** (e.g., "Everyone: Full Control" in file shares).
* **Example:** AWS S3 buckets set to **public by default**, leading to data leaks.

**4. Debug Mode Enabled in Production**

* Web applications/frameworks (e.g., Django, Flask) sometimes run in **debug mode by default**, exposing sensitive data.

**5. Directory Listing Enabled**

* Web servers (e.g., Apache, Nginx) may allow **directory traversal**, exposing files unintentionally.

**6. Unpatched or Outdated Default Software**

* Some systems ship with **old, vulnerable software versions** (e.g., outdated PHP, WordPress plugins).

**7. Default Cryptographic Keys/Certificates**

* Devices (e.g., routers, IoT) sometimes use **hardcoded encryption keys**, making decryption easy for attackers.

**8. Cloud Misconfigurations**

* **Example:**
  * Publicly accessible **Kubernetes dashboards**.
  * **Overprivileged IAM roles** in AWS/Azure.
  * **Unencrypted storage** (e.g., databases/blobs set to public).

**9. Unsecured APIs**

* APIs with **no authentication**, **exposed admin endpoints**, or **excessive data exposure** by default.

**10. Lack of Logging/Monitoring**

* Many systems **do not log security events by default**, allowing attackers to operate undetected.

**11. Services with No Default Authentication**

- Some databases and search engines historically shipped with no authentication mechanism enabled by default, assuming they would be placed in a trusted network.
- **Examples:**
   - **MongoDB ransomware attacks:** Thousands of databases were left exposed to the public internet, leading to mass data theft and ransomware campaigns where attackers deleted data and demanded payment for its return.
   - **Elasticsearch data leaks:** Similarly, exposed clusters without authentication have led to numerous large-scale leaks of sensitive user data.

### Misconfigured security settings

Misconfigured security settings occur when systems, applications, or networks are set up insecurely, leaving them vulnerable to attacks. 

Unlike simple default settings issues, misconfigurations can arise from configuration or coding errors, lack of security awareness, and poor maintenance.

**Common Examples of Security Misconfigurations**

**1. Exposed Admin Interfaces**

* Web-based admin dashboards (e.g., `/admin`, `/wp-admin`, `/manager`) left publicly accessible.
* **Real-world example:**
  * **Jenkins servers** exposed online without authentication, allowing attackers to execute arbitrary code.
  * **Router admin panels** (e.g., `192.168.1.1`) exposed to the internet, leading to credential brute-forcing.

**2. Unprotected Cloud Storage (S3 Buckets, Blob Storage)**

* AWS S3 buckets or Azure Blob Storage set to **public** instead of private.
* **Example:**
  * **Verizon (2017)** – Misconfigured S3 bucket exposed **6 million customer records**.
  * **Facebook (2019)** – Publicly accessible databases leaked **540 million user records**.

**3. Verbose Error Messages**

* Applications revealing **stack traces, database errors, or server details** in production.
* **Example:**
  * SQL errors exposing table names, helping attackers refine SQL injection attacks.

**4. Unsecured APIs**

* APIs with **no authentication**, **excessive data exposure**, or **deprecated versions** left running.
* **Example:**
  * **Peloton (2021)** – API leaked user data due to lack of authentication checks.

**5. Directory Listing Enabled**

* Web servers (Apache, Nginx) allow **browsing of directories**, exposing sensitive files.
* **Example:**
  * A misconfigured backup directory might expose `.bak` or `.sql` files containing credentials.

**6. Unnecessary HTTP Methods (PUT, DELETE, TRACE)**

* Web servers allowing dangerous methods (e.g., **PUT** for file uploads, **DELETE** for wiping data).
* **Example:**
  * Attackers exploit **HTTP PUT** to upload malicious scripts (e.g., web shells).

**7. Default or Sample Files Left Installed**

* Web servers with **default pages** (e.g., `phpinfo.php`, `test.cgi`) that leak system info.
* **Example:**
  * **Oracle WebLogic** had default samples vulnerable to remote code execution (CVE-2020-14882).

**8. Improper CORS (Cross-Origin Resource Sharing) Policies**

* Misconfigured CORS allows **any domain** to access APIs, leading to data theft.
* **Example:**
  * A banking site allowing `Access-Control-Allow-Origin: *` could leak sensitive data via malicious scripts.

**9. Missing Security Headers**

* Lack of **HTTP Security Headers** (e.g., `X-Content-Type-Options`, `Content-Security-Policy`).
* **Example:**
  * Clickjacking attacks succeed when `X-Frame-Options` is missing.

**10. Unrestricted File Uploads**

* Web apps allowing **executable files** (`.php`, `.jsp`) to be uploaded without validation.
* **Example:**
  * Attackers upload a `.php` shell to gain remote control (e.g., **Alibaba Cloud (2020)**).

**11. Vulnerable Network Appliances with Default Deployment Settings**

- **Content:** Network appliances like ADCs, VPN gateways, and firewalls are often deployed using vendor templates that may not follow security best practices, leaving them vulnerable to widespread attacks.
- **Real-world example:**
   - **Citrix ADC (CVE-2019-19781):** While this was a code vulnerability, its impact was magnified because default configuration settings and common deployment patterns allowed for unauthenticated remote code execution, leading to the compromise of thousands of companies.

### How to prevent misconfiguration vulnerabilities

✔ **Eliminate Defaults:** Change default credentials and remove default/sample files immediately.  
✔ **Minimize Attack Surface:** Disable unnecessary services, ports, admin interfaces from public access (use VPNs/IP whitelisting), and unnecessary HTTP methods (e.g., PUT, DELETE).  
✔ **Enforce Least Privilege:** Follow the principle of least privilege for users, services, and cloud permissions (e.g., IAM roles, file shares).  
✔ **Harden Configurations:** Enable security features (encryption, WAFs), disable debug mode and directory listing in production, and implement proper security headers (e.g., CSP, HSTS) and CORS policies.  
✔ **Automate Security & Audit Continuously:** Use security tools (e.g., **Nessus, OpenVAS, AWS Config, OWASP ZAP, Burp Suite**) to automate checks and regularly audit configurations and permissions.
