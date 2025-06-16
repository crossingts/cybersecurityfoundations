---
description: >-
  This sections introduces core and foundational cybersecurity concepts and
  practices such as confidentiality, integrity, and availability (the CIA triad)
---

# Foundational cybersecurity concepts and practices

## Learning objectives

• Point 1\
• Point 2 \
• Point 3\
• Point 4 \
• Point 5

This section introduces core and foundational cybersecurity concepts and practices to help learners develop a practical understanding of the goals of cybersecurity and how it is defined and practiced within organizations. This section covers definitions of information security, the CIA triad, risk, threat, vulnerability, mitigation, and the AAA framework (Authentication, Authorization, and Accounting).

## Topics covered in this section

* **Information security definition**
* **Confidentiality, integrity, and availability of information**
* **Cybersecurity risk management**
* **Other cybersecurity concepts and practices**

### Information security definition

Definitions of information security

Definitions of cybersecurity

### Confidentiality, integrity, and availability of information

The main goals of cybersecurity are confidentiality, integrity, and availability of information (the CIA triad).

### Confidentiality

\<A key **technology** for data confidentiality is data leakage prevention (DLP), a system that tracks specific sets of sensitive data. For example, DLP can issue alerts when sensitive files are copied to a USB, or credit-card numbers are shared. DLP is a great tool, but it requires precise, organization specific data classification and alert creation in order to be effective.>

### Integrity

**Technologies**: encryption, backups, AAA accounting (data access), SVN/Git (data modification), SIEM

\<To protect data integrity, regular audits of information access and change are required. Data access has to be centrally logged, in case a bad actor manages to damage log data at the endpoint. Any employee who modifies sensitive data should do so using his or her personal user name. This allows non-repudiation, which means that an employee who modified data can’t deny his or her action.&#x20;

\<To truly safeguard information integrity, you’ll want to incorporate change management technology. Change management basically tracks changes to data, requires management approval of changes, or prevents changes forbidden by policy. Change management usually stores snapshot of data and tracks changes that are performed on it. Those changes are compared with system policy, and carried out only when they are in compliance with the policy. There are numerous change management products that can apply granular policies to track and prevent unwanted changes on almost any device, from storage filers to firewalls. One of best-known systems for change management is free SVN, which allows the detailed tracking of data inside a file, as well as granular permission control.

### Availability

Data can become unavailable due to being damaged or destroyed, or due to ransomeware.

You should also be aware that your data could be damaged by malware that remains dormant for long period of time.&#x20;

### Cybersecurity risk management

Cybersecurity risk management concepts and practices

**How cybersecurity is practiced within organizations**

Organizations take a risk-based approach to information security management.

**Understanding enterprise cybersecurity in terms of risk, threat, vulnerability, and mitigation**

\<In order to simplify data governance, information **should be segregated by levels of importance and risk**, since it is very complicated to safeguard all the data in organization using the same standards … sensitive data has to be protected by more security measures in order to safeguard it. In some cases, in order to archive “defense in depth,” multiple security devices from different vendors are recommended.

**Acceptable risk**

After risk assessment, risks may be accepted, mitigated, or transferred (e.g., to another department or third party better equipped to manage them).

Systems can be more secure or less secure, but there is no absolute security. For example, you can implement malware detection on your network firewall and have the best antivirus software on client PCs, but the chance of the PCs getting infected with malware is never zero.&#x20;

**Security vs functionality**

Yes, data that isn’t accessible to anyone may be perfectly secure, but it’s worthless to the enterprise if it can’t be seen and used.

### Other cybersecurity concepts and practices

**The AAA framework**&#x20;

AAA stands for Authentication, Authorization, and Accounting. It’s a framework for controlling and monitoring users of a computer system, such as a network.

**The primary goals of cryptography**

The primary goals of cryptography are confidentiality, authentication, data integrity, and non-repudiation.

• Confidentiality is the property that keeps information secret/non-available to unauthorized parties. \
• Authentication relates to the identification of a user and data; in other words, it is a process of confirming that the data and user are genuine. \
• Data integrity is related to ensuring that information is not changed or manipulated by unauthorized parties. The focus in on verifying that that the data or message that you’ve received is genuine and hasn’t been altered by an unauthorized third party.\
• Non-repudiation prevents a user from denying authorship of actions and information they’ve made. For instance, a friend of yours may promise to join your team in Pokémon Go, then refuse to admit they’d made that promise. To resolve that type of situation, there should be a trusted third party (say, some mutual friend) who will keep track of everybody’s commitments.>

### Essential cryptography terms&#x20;

<**Encryption** is a process of transforming simple text/data, called plaintext, into unintelligible form, named as ciphertext. Decryption is the inverse process of encryption. **Cipher** is an algorithm that performs encryption/decryption. A **key** is a secret string of characters or symbols that is used for the encryption/decryption of plaintext/ciphertext. Sometimes, the term **cryptosystem** is used instead of cipher. There are two types of ciphers depending on the use of keys: symmetric and asymmetric.\
**Symmetric ciphers**, also referred as secret-key ciphers, use the same key for encryption and decryption. Symmetric cryptosystems are divided into two groups: block and stream ciphers. In block ciphers, operations of encryption/decryption are performed on blocks of bits or bytes, whereas stream ciphers operate on individual bits/bytes. **Asymmetric ciphers**, alternatively named public-key ciphers, use two keys, one for encryption and other for decryption. **Cryptanalysis** is a study of techniques for “cracking” encryption ciphers, i.e., attacks on cryptosystems. And chances are you’ve heard about **hashing algorithms**, which involves taking an input of any length and outputting a fixed-length string, called a hash. Which can be used, for example, as signatures or for data-integrity purposes.>

### Key takeaways

• Point 1\
• Point 2\
• Point 3 \
• Point 4 &#x20;

### References

Shamil Alifov. (2016). How to get started in cryptography (Ch. 5). In _Beginner’s Guide To Information Security_ (pp. 27-31). Peerlyst. Retrieved from https://www.peerlyst.com/posts/peerlyst-announcing-its-first-community-ebook-the-beginner-s-guide-to-information-security-limor-elbaz

Yuri Livshitz. (2016). How to secure your data (Ch. 6). In Beginner’s Guide To Information Security (pp. 32-35). Peerlyst. Retrieved from https://www.peerlyst.com/posts/peerlyst-announcing-its-first-community-ebook-the-beginner-s-guide-to-information-security-limor-elbaz
