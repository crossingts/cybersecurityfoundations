# Secure cookie attributes explained

Session hijacking occurs when an attacker steals a user's session token (usually stored in a cookie) and uses it to impersonate that user on the web application. The methods below aim to make stealing or misusing that token significantly more difficult.

#### 1. The `Secure` Attribute

* **Mitigation Goal:** Prevent the session cookie from being transmitted over an insecure, unencrypted channel (HTTP) where it could be intercepted by eavesdroppers.
* **Mechanism of Action:**
  1. **Setting the Attribute:** When a web server sets a session cookie in the user's browser, it includes the `Secure` flag in the `Set-Cookie` HTTP response header. This is only done if the response itself is sent over HTTPS.
     * Example Header: `Set-Cookie: sessionid=abc123; Secure; HttpOnly`
  2. **Browser Enforcement:** The browser receives this instruction and stores the cookie along with the rule that it is "Secure".
  3. **Outbound Request Rule:** From that point on, the browser's internal policy engine will **only** include this cookie in requests that are sent over an HTTPS connection to the same domain. It will **never** include it in any HTTP request.
* **How This Mitigates Hijacking:**
  * **Prevents Eavesdropping on Networks:** On an unencrypted Wi-Fi network (e.g., a public café), any HTTP traffic can be read by anyone else on that network. If a session cookie was sent via HTTP, an attacker could trivially sniff it out of the air. The `Secure` attribute guarantees the cookie is only ever transmitted inside an encrypted HTTPS tunnel, making it useless to a passive network sniffer.
  * **Prevents Downgrade Attacks:** It helps prevent attackers from tricking a user's browser into making an HTTP request to a site that should be HTTPS, which could expose the cookie.

#### 2. The `HttpOnly` Attribute

* **Mitigation Goal:** Mitigate the impact of Cross-Site Scripting (XSS) attacks by removing a common payload target: the user's session cookie.
* **Mechanism of Action:**
  1. **Setting the Attribute:** The server sets the cookie with the `HttpOnly` flag.
     * Example Header: `Set-Cookie: sessionid=abc123; Secure; HttpOnly`
  2. **Browser Enforcement:** The browser stores the cookie and marks it as accessible only by the network layer (HTTP/HTTPS requests).
  3. **JavaScript Isolation:** The browser's JavaScript engine is instructed to hide this cookie from any JavaScript code running in the document. API calls like `document.cookie` will simply not return any cookie marked as `HttpOnly`.
* **How This Mitigates Hijacking:**
  * **Renders Many XSS Payloads Ineffective:** A very common goal of an XSS attack is to steal session cookies. A classic payload looks like this: `<script>sendToAttacker(document.cookie);</script>`. If the session cookie is protected with `HttpOnly`, this script will run but will fail to read the valuable session token, returning an empty string or other non-sensitive cookies instead. The attacker's attack vector is closed.
  * **Important Note:** `HttpOnly` does not _prevent_ XSS attacks—the malicious script can still execute and perform other actions (like changing the user's password, making transactions, etc.). However, it specifically mitigates the _session hijacking_ aspect of XSS by protecting the cookie itself.

#### 3. The `SameSite` Attribute

* **Mitigation Goal:** Protect against Cross-Site Request Forgery (CSRF) and cross-origin attacks that could lead to session hijacking by controlling when cookies are sent with cross-site requests.
*   **Mechanism of Action:** The browser makes a decision on whether to send the cookie based on the _context_ of the request (who initiated it and what type it is). There are three modes:

    **A. `SameSite=Strict`**

    * **Rule:** The browser will **only** send the cookie with requests that are made from a page on the _exact same site_ (e.g., from `https://example.com` to `https://example.com`).
    * **Mechanism:** If a user clicks a link to `https://example.com/dashboard` from an email or another website (`https://other-site.com`), the browser will _not_ send the session cookie. The user will arrive at the site but be treated as "not logged in," protecting the session.

    **B. `SameSite=Lax` (The Balanced Default)**

    * **Rule:** The browser will send the cookie with **same-site requests** and with **top-level navigations** (e.g., GET requests from another site by clicking a link) but **not** with cross-site requests initiated by scripts (e.g., AJAX calls, image/fetch requests from other sites).
    * **Mechanism:** This provides a good balance of security and usability. It allows users to follow links to your site and still be logged in (the cookie is sent for that top-level navigation), but it blocks cookies from being sent in forged POST requests or API calls embedded in other sites, which is the core of CSRF attacks.

    **C. `SameSite=None`**

    * **Rule:** The browser will send the cookie with all cross-site requests. **This requires the `Secure` attribute to be set simultaneously** (e.g., `SameSite=None; Secure`).
    * **Mechanism:** This is necessary for functionality that requires the session in a third-party context, such as "Login with X" buttons or widgets embedded in iframes. The `Secure` requirement ensures the cookie is still protected in transit.
* **How This Mitigates Hijacking:**
  * **Neutralizes CSRF:** CSRF relies on the browser automatically sending cookies (including the session cookie) with forged requests to a target site. `SameSite=Lax` or `Strict` breaks this mechanism by refusing to send the cookie for cross-origin POST requests, rendering the attack ineffective.
  * **Prevents Leakage in Cross-Site Scenarios:** It stops other websites from being able to silently embed requests (e.g., `<img src="https://bank.com/transfer-funds">`) that would automatically be authenticated with the user's session cookie.

#### **Summary Table**

| Attribute      | Primary Threat Mitigated | Mechanism of Action                                                                                              |
| -------------- | ------------------------ | ---------------------------------------------------------------------------------------------------------------- |
| **`Secure`**   | Network Eavesdropping    | Browser restricts cookie transmission to **encrypted (HTTPS) channels only**.                                    |
| **`HttpOnly`** | XSS-based Cookie Theft   | Browser hides the cookie from **client-side JavaScript** (`document.cookie` API).                                |
| **`SameSite`** | CSRF & Cross-Site Leaks  | Browser controls cookie sending based on the **request context** (same-site vs. cross-site, GET vs. POST, etc.). |

For maximum security, a session cookie should ideally be configured with **`Secure; HttpOnly; SameSite=Strict`** (or **`Lax`** for better usability). This "defense in depth" approach creates multiple layers of protection, making session hijacking extremely difficult for an attacker.
