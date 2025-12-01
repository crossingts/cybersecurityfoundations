---
hidden: true
---

# Attack target vs attack vector

### Attack Target vs Attack Vector

Here’s a comparison table separating Attack Targets, Attack Vectors, and Underlying Vulnerabilities for two common attacks (OS and web application):

| **Attack Target**                  | **Attack Vector**                                         | **Underlying Vulnerability**                    |
| ---------------------------------- | --------------------------------------------------------- | ----------------------------------------------- |
| **Operating System (OS)**          | Exploiting unpatched services                             | Unpatched OS vulnerabilities (CVE-listed flaws) |
|                                    | Brute-forcing weak credentials                            | Default or weak passwords                       |
| **Web Application (OWASP Top 10)** | SQL Injection (SQLi) (database manipulation)              | Improper input sanitization in database queries |
|                                    | Cross-Site Scripting (XSS) (client side script execution) | Lack of output encoding/input validation        |
|                                    | CSRF (Cross-Site Request Forgery)                         | Missing anti-CSRF tokens                        |

#### **Key Clarifications**

1. Attack Target: The asset being attacked (e.g., OS, user, app).
2. Attack Vector: The delivery method (e.g., phishing, SQLi).
3. Underlying Vulnerability: The weakness enabling the attack (e.g., unpatched software).

#### **Example Flow**

* Target: Web Application → Vector: XSS → Vulnerability: Lack of input sanitization.
* Target: User → Vector: Phishing → Vulnerability: Human error (clicking malicious links).
