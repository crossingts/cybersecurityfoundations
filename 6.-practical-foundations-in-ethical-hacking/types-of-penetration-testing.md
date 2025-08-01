---
description: >-
  This section explores types of penetration testing, differentiates black box
  from white box penetration testing, and possible risks of penetration testing
---

# Types of penetration testing

## Learning objectives

* Describe main types of penetration testing
* Compare black box penetration testing and white box penetration testing methods
* Identify the possible risks of penetration testing

This section explores six types of penetration testing, compares between black box and white box penetration testing, and shed light on possible risks of penetration testing to the client organization.

## Topics covered in this section

* **Types of penetration testing**
* **Black box penetration testing and white box penetration testing**
* **Possible risks of penetration testing**

### Types of penetration testing

• Describe main types of penetration testing: network, wireless, web application, physical, social engineering, and cloud.

• Reconnaissance or Open Source Intelligence (OSINT) gathering

• Network penetration testing

• Wireless network penetration testing

• Website/web application

• Physical penetration testing

• Social engineering

• Cloud penetration testing

### Black box penetration testing and white box penetration testing

• Compare black box penetration testing and white box penetration testing methods.

Black box penetration testing and white box penetration testing methods broadly simulate an insider's and outsider's attack types

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

**Testing from an outsider vs insider perspective**

There are several kinds of testing. Any combination of the following may be called for:

• Remote network. This test simulates the intruder launching an attack across the Internet. The primary defenses that must be defeated here are border firewalls, filtering routers, and Web servers.

• Remote dial-up network. This test simulates the intruder launching an attack against the client’s modem pools. The primary defenses that must be defeated here are user authentication schemes. These kinds of tests should be coordinated with the local telephone company. (Palmer 2001, p. 777)

• Local network. This test simulates an employee or other authorized person who has a legal connection to the organization’s network. The primary defenses that must be defeated here are intranet firewalls, internal Web servers, server security measures, and e-mail systems.

• Stolen laptop computer. (Palmer 2001, p. 778)

• Social engineering. This test evaluates the target organization’s staff as to whether it would leak information to someone. A typical example of this would be an intruder calling the organization’s computer help line and asking for the external telephone numbers of the modem pool. Defending against this kind of attack is the hardest, because people and personalities are involved. Most people are basically helpful, so it seems harmless to tell someone who appears to be lost where the computer room is located, or to let someone into the building who “forgot” his or her badge. The only defense against this is to raise security awareness.

• Physical entry. This test acts out a physical penetration of the… (Palmer 2001, p. 778)

Each of these kinds of testing can be performed from three perspectives: as a total outsider, a “semi-outsider,” or a valid user. (Palmer 2001, p. 779)

### Possible risks of penetration testing

• Potential benefits of ethical hacking: security breach risk reduction

• Possible risks of ethical hacking: system disruption, privacy concerns...

There are risks inherent to ethical hacker evaluations and the client should be made fully aware of them. Organizations must weigh potential benefits vs possible risks when deciding the details of the penetration test. Organizations must decide what devices and applications to test and when and how to test them--and the risks involved in performing the security testing.&#x20;

"These risks include alarmed staff and unintentional system crashes, degraded network or system performance, denial of service, and log-file size explosions" (Palmer, 2001, p. 776).

The risk of serious side effects from performing penetration testing will inform the specific tests to be made and how on a live system.&#x20;

The best evaluation is done under a “no-holds-barred” approach. This means that the ethical hacker can try anything he or she can think of to attempt to gain access to or disrupt the target system. While this is the most realistic and useful, some clients balk at this level of testing. Clients have several reasons for this, the most common of which is that the target systems are “in production” and interference with their operation could be damaging to the organization’s interests. (Palmer, 2001, pp. 775-776)

Once the contractual agreement is in place, the testing may begin as defined in the agreement. It should be noted that the testing itself poses some risk to the client, since a criminal hacker monitoring the transmissions of the ethical hackers could learn the same information. If the ethical hackers identify a weakness in the client’s security, the criminal hacker could potentially attempt to exploit that vulnerability. This is especially vexing since the activities of the ethical hackers might mask those of the criminal hackers. The best approach to this dilemma is to maintain several addresses around the Internet from which the ethical hacker’s transmissions will emanate, and to switch origin addresses often. Complete logs of the tests performed by the ethical hackers are always maintained, both for the final report and in the event that something unusual occurs. In extreme cases, additional intrusion monitoring software can be deployed at the target to ensure that all the tests are coming from the ethical hacker’s machines. (Palmer, 2001, p. 777)

### Key takeaways

* Types of penetration testing include network, wireless, web application, physical, social engineering, and cloud
* Black box penetration testing and white box penetration testing methods broadly simulate an insider's and outsider's attack types
* Organizations must weigh potential benefits vs possible risks when deciding the details of the penetration test

### References

Cipher. (n.d.). The types of pentests you must know about. Retrieved January 21, 2020, from https://cipher.com/blog/the-types-of-pentests-you-must-know-about/
