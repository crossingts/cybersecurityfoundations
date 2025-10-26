---
description: >-
  This section explores types of penetration testing, differentiates black box
  from white box penetration testing, and explores possible risks of penetration
  testing
---

# Types of penetration testing

## Learning objectives

* Describe main types of penetration testing
* Compare black box and white box penetration testing methods
* Identify the possible risks of penetration testing

This section explores six types of penetration testing, compares between black box and white box penetration testing, and sheds light on possible risks of penetration testing to the client organization.

## Topics covered in this section

* **Types of penetration testing**
* **Black box penetration testing and white box penetration testing**
* **Possible risks of penetration testing**

### Types of penetration testing

• Network penetration testing

• Wireless network penetration testing

• Website/web application penetration testing

• Physical penetration testing

• Social engineering

• Cloud penetration testing

Network penetration testing and exploitation techniques typically include bypassing firewalls, router testing, IPS/IDS evasion, DNS footprinting, open port scanning and testing, SSH attacks, proxy servers, network vulnerabilities, and application penetration testing (Cipher, n.d.).

### Black box penetration testing and white box penetration testing

**White box** and **black box penetration testing** are two fundamental approaches to security assessments, differing in the level of knowledge and access given to the testers. Broadly, white box penetration testing and black box penetration testing simulate an insider's and an outsider's attack types, respectively. Based on the type of auditing required, there are two main penetration testing types. In black box testing, the penetration tester has no prior knowledge of a company’s network, more closely resembling remote attacks. In white box testing, the penetration tester typically has complete access to information about the application or system he is attacking, that is, complete knowledge of the network. White box testing represents a worst-case scenario where the attacker has a complete knowledge of the network.

White box penetration testing, also referred to as "clear box" or "full knowledge" testing, is a security assessment where the tester is granted full access to the target system's internal information. This includes source code, architecture diagrams, network configurations, and even credentials. With this level of transparency, the primary advantage is the ability to conduct a more thorough examination, uncovering logic flaws, complex misconfigurations, and hidden vulnerabilities that other methods might miss. Because testers do not need to spend time on reconnaissance, the process is also significantly faster. However, this approach is less realistic, as real-world attackers typically do not start with such extensive internal knowledge. Consequently, it is ideally suited for secure code reviews, testing internal applications before release, and meeting specific compliance audit requirements like those for PCI DSS.

In contrast, black box penetration testing operates on a "zero knowledge" premise, where the tester begins with no prior understanding of the system's internal workings, simulating the perspective of an external attacker. This method is highly valued for its realism, as it directly mimics the threats an organization faces from the outside. The process tests the effectiveness of external-facing defenses such as firewalls, web applications, and APIs, and is particularly effective at uncovering issues like information leakage, weak authentication mechanisms, and exposed services. The main drawback is that it can be time-consuming, as a significant portion of the engagement is dedicated to reconnaissance and fingerprinting. Furthermore, it may miss deeper internal flaws, such as business logic errors, that are not accessible from an unprivileged viewpoint. Common use cases include external network penetration tests, red team engagements, and bug bounty programs, where ethical hackers often operate with limited information.

Bridging the gap between these two methodologies is grey box penetration testing, a hybrid approach where the tester is provided with partial knowledge of the system. This often includes low-privilege user account credentials or limited documentation. By providing this contextual information, grey box testing strikes a balance between the speed and depth of white box testing and the realism of the black box approach. It allows testers to bypass the initial reconnaissance phase and focus their efforts more efficiently, while still simulating an attack vector that could come from a compromised user account or an insider threat. This balanced nature makes it a common and practical choice for internal penetration tests and for organizations seeking a comprehensive yet efficient security assessment that aligns well with various compliance frameworks.

**Comparison Table**

| Feature       | White Box                                     | Black Box                                  | grey Box                        |
| ------------- | --------------------------------------------- | ------------------------------------------ | ------------------------------- |
| **Knowledge** | Full                                          | None                                       | Partial                         |
| **Speed**     | Fast                                          | Slow                                       | Moderate                        |
| **Realism**   | Low                                           | High                                       | Medium                          |
| **Best For**  | Code review, pre-release audits, blue teaming | External security assessments, red teaming | A balanced approach, compliance |

**Testing from an outsider vs insider perspective**

There are several kinds of testing—each of which can be performed from an outsider or insider perspective (Palmer, 2001, pp. 777-778):

• Remote network. This test simulates the intruder launching an attack across the Internet. The primary defenses that must be defeated here are border firewalls, filtering routers, and Web servers.

• Remote dial-up network. This test simulates the intruder launching an attack against the client’s modem pools. The primary defenses that must be defeated here are user authentication schemes. These kinds of tests should be coordinated with the local telephone company.&#x20;

• Local network. This test simulates an employee or other authorized person who has a legal connection to the organization’s network. The primary defenses that must be defeated here are intranet firewalls, internal Web servers, server security measures, and e-mail systems.

• Stolen laptop computer. In this test, the laptop computer of a key employee, such as an upper-level manager or strategist, is taken by the client without warning and given to the ethical hackers.

• Social engineering. This test evaluates the target organization’s staff as to whether it would leak information to someone. A typical example of this would be an intruder calling the organization’s computer help line and asking for the external telephone numbers of the modem pool. Defending against this kind of attack is the hardest, because people and personalities are involved. Most people are basically helpful, so it seems harmless to tell someone who appears to be lost where the computer room is located, or to let someone into the building who “forgot” his or her badge. The only defense against this is to raise security awareness.

• Physical entry. This test acts out a physical penetration of the organization's building.

### Possible risks of penetration testing

There are risks inherent to ethical hacker evaluations and the client should be made fully aware of them. Organizations must weigh potential benefits vs possible risks when deciding the details of the penetration test. Organizations must decide what devices and applications to test and when and how to test them--and the risks involved in performing the security testing.&#x20;

"These risks include alarmed staff and unintentional system crashes, degraded network or system performance, denial of service, and log-file size explosions" (Palmer, 2001, p. 776).

The risk of serious side effects from performing penetration testing will inform the specific tests to be made and how on a live system.&#x20;

The best evaluation is done under a “no-holds-barred” approach. This means that the ethical hacker can try anything he or she can think of to attempt to gain access to or disrupt the target system. While this is the most realistic and useful, some clients balk at this level of testing. Clients have several reasons for this, the most common of which is that the target systems are “in production” and interference with their operation could be damaging to the organization’s interests. (Palmer, 2001, pp. 775-776)

Once the contractual agreement is in place, the testing may begin as defined in the agreement. It should be noted that the testing itself poses some risk to the client, since a criminal hacker monitoring the transmissions of the ethical hackers could learn the same information. If the ethical hackers identify a weakness in the client’s security, the criminal hacker could potentially attempt to exploit that vulnerability. This is especially vexing since the activities of the ethical hackers might mask those of the criminal hackers. The best approach to this dilemma is to maintain several addresses around the Internet from which the ethical hacker’s transmissions will emanate, and to switch origin addresses often. Complete logs of the tests performed by the ethical hackers are always maintained, both for the final report and in the event that something unusual occurs. In extreme cases, additional intrusion monitoring software can be deployed at the target to ensure that all the tests are coming from the ethical hacker’s machines. (Palmer, 2001, p. 777)

Penetration testing involves “launching real attacks on real systems and data using tools and techniques commonly used by hackers” (NIST SP 800-115, p. 5-2). &#x20;

Performing real attacks on real systems carries a higher risk that must be weighed carefully against the intended benefits. It must be justified on a cost-benefit basis by a security analyst with broad and interdisciplinary knowledge about the social threat landscape, human behavior, sociopolitical conflicts, in addition to the technical knowledge. Penetration testing can compromise data integrity or availability (accidental damage) or confidentiality (the penetration tester sees confidential information just by virtue of performing the test).

The technical risks of penetration testing on computer systems to an organization include damaging the system infrastructure or data assets, or exposing confidential information, downtime, and exploits may remain in the system. Given the potential side effects of penetration testing, the work of penetration testers is often conducted on a defined schedule and focuses on specific aspects of a network or computer infrastructure rather than being an ongoing overall security. The penetration tester may have only limited access to the system that is subject to testing and only for the duration of the testing.

### Key takeaways

* Types of penetration testing include network, wireless, web application, physical, social engineering, and cloud
* Black box penetration testing and white box penetration testing methods broadly simulate an insider's and outsider's attack types
* Organizations must weigh potential benefits vs possible risks when deciding the details of the penetration test

### References

Cipher. (n.d.). The types of pentests you must know about. Retrieved January 21, 2020, from https://cipher.com/blog/the-types-of-pentests-you-must-know-about/

Palmer, C. C. (2001). Ethical hacking. _IBM Systems Journal, 40_(3), 769-780.
