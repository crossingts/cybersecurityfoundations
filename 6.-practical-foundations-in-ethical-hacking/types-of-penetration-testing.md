---
description: >-
  This section explores six types of penetration testing, including
  vulnerabilities targeted/attack vectors and technologies used, and
  differentiates between black box and white box penetration testing
---

# Types of penetration testing

• Describe types of penetration testing: network, wireless, web application, physical, social engineering, and cloud.

• Compare black box penetration testing and white box penetration testing methods.

• Evaluate organizational benefits of ethical hacking (risk reduction) vs. risks (e.g., system disruption and privacy concerns).

### Types of penetration testing

• Reconnaissance or Open Source Intelligence (OSINT) gathering

• Network penetration testing

• Wireless network penetration testing

• Website/web application

• Physical penetration testing

• Social engineering

• Cloud penetration testing

### Black box penetration testing and white box penetration testing

Based on the type of auditing required, there are two main penetration testing types. In black box testing, the penetration tester has no prior knowledge of a company’s network, more closely replicating remote attacks. In white box testing, the testers typically have complete access to information about the application they are attacking, that is, the testers have a complete knowledge of the network. White box testing represents a worst-case scenario where the attacker has a complete knowledge of the network.

**White box** and **black box penetration testing** are two fundamental approaches to security assessments, differing in the level of knowledge and access given to the testers. Here’s a breakdown:

**1. White Box Penetration Testing ("Clear Box" or "Full Knowledge")**

* **Definition:** The tester has **full access** to internal information (source code, architecture diagrams, credentials, etc.).
* **Pros:**
  * More thorough (no blind spots).
  * Finds **logic flaws, misconfigurations, and hidden vulnerabilities** that black box might miss.
  * Faster (no time wasted on reconnaissance).
* **Cons:**
  * Less realistic (attackers usually don’t have full internal knowledge).
  * May miss issues that only appear in an external (unprivileged) attack scenario.
* **Use Cases:**
  * Secure code reviews.
  * Testing internal applications before release.
  * Compliance audits (e.g., PCI DSS).

**2. Black Box Penetration Testing ("Zero Knowledge")**

* **Definition:** The tester has **no prior knowledge** of the system and simulates an external attacker.
* **Pros:**
  * More realistic (mimics real-world threats).
  * Tests **external-facing defenses** (firewalls, APIs, web apps).
  * Uncovers issues like **information leakage, weak authentication, or exposed services**.
* **Cons:**
  * Time-consuming (requires reconnaissance).
  * May miss deep internal flaws (e.g., business logic errors).
* **Use Cases:**
  * External network penetration tests.
  * Red team engagements (simulating real attackers).
  * Bug bounty programs (ethical hackers operate in black/gray box).

**Gray Box Testing (Hybrid Approach)**

* **Definition:** Partial knowledge (e.g., low-privilege user access or limited docs).
* **Balances speed and realism**—common in internal pentests.

**Comparison Table**

| Feature       | White Box                       | Black Box                     | Gray Box                  |
| ------------- | ------------------------------- | ----------------------------- | ------------------------- |
| **Knowledge** | Full                            | None                          | Partial                   |
| **Speed**     | Fast                            | Slow                          | Moderate                  |
| **Realism**   | Low                             | High                          | Medium                    |
| **Best For**  | Code review, pre-release audits | External attacks, red teaming | Internal apps, compliance |

**Which One Should You Use?**

* **White Box** → Best for **developers, internal security teams**.
* **Black Box** → Best for **external security assessments, red teams**.
* **Gray Box** → A **balanced** approach for most pentests.

### References

Cipher. (n.d.). The types of pentests you must know about. Retrieved January 21, 2020, from https://cipher.com/blog/the-types-of-pentests-you-must-know-about/
