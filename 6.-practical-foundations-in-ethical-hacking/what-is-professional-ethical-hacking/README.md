---
description: >-
  This section frames an understanding of ethical hacking (penetration testing)
  as professional ethical hacking
hidden: true
---

# What is professional ethical hacking

## Learning objectives

* Point 1
* Become familiar with the professional ethics of ethical hackers&#x20;

This section frames an understanding of ethical hacking (penetration testing) as professional ethical hacking. The analysis differentiates white hat hacking from gray hat hacking, black hat hacking, and hacktivism on the basis of **ethics (moral ethics), professional ethics, and legal practices.**

## Topics covered in this section

* **Introduction**
* **Profiles of hackers**&#x20;
* **Professional ethics of ethical hackers**

### Introduction

There are many approaches to distinguish between white hat hackers, gray hat hackers, black hat hackers, and hacktivists. For example, idioms and practices, or historical account.&#x20;

However, we make a comparison differentiating between these four hacker groups and their hacking practices on the logic that there is only one category of white hat hacking: legal hacking. Ethical values and professional ethics underlying the practices of white hat hackers further cement this taxonomy of the various hacker groups.

Ethical hackers (as penetration testers) necessarily fit into the white hat hackers group—there's no moral or legal ambiguity regrading the legality of their practices. No greyness. In this classification scheme, the terms white hat hacking and ethical hacking can be used **interchangeably**.&#x20;

Finally, we advance an understanding that professional ethical hacking is ethical hacking (penetration testing) performed in accordance with widely established industry and licensing standards regarding what constitutes professional conduct.

Assumptions:

• Penetration testing is ethical hacking, since ethical hacking most formally refers to penetration testing, and since penetration testing professionals strictly abide by a legal framework, while acknowledging that it does not follow from this that all ethical hacking is penetration testing—there could be other varieties of claimed ethical hacking practices (e.g., hacktivists). So we further specify what constitutes "ethical" in ethical hacking and we advance that it refers to claimed or demonstrated moral ethics and to widely established professional codes on conduct (which hacktivists, e.g., do not adhere to).

• Ethical hackers (as penetration testers) fit only within the white hat hackers group on the basis of legal and ethical (moral) conduct.

• Professional ethical hacking is ethical hacking performed in accordance with widely established industry standards and professional licensing authorities regarding what constitutes professional conduct.

### Profiles of hackers

Follows is an analysis of the four types of hacking/hacker groups classified based on the legality of their practices, professional ethical conduct, and moral ethics.

#### White Hat Hackers: The Ethical Professionals

1\) White hat hackers only hack systems or machines with legal authorization to do so (including legal contractual agreements). So whether resident (in-house) employees of a company or hired by a company for security testing, this would be ethical hacking as long as hacking is performed in accordance with agreed upon terms and within the specified authorization parameters (hacking beyond authorized level or terms ceases to be ethical). Bug bounty hunters are ethical hackers since they work within this contractual framework.&#x20;

White hat hackers operate within legal boundaries, conducting security assessments only with explicit authorization from computer system. They adhere to strict ethical guidelines, often working as in-house experts, consultants, or bug bounty hunters.

Their practices align with professional codes like the ACM Code of Ethics (2018), which mandates permission-based hacking, and industry standards such as IEEE guidelines on penetration testing (e.g., IEEE 2600-series) and NIST SP 800-115

The **ACM Code of Ethics (2018)** stresses **permission-based hacking** (e.g., Principle 2.8: "Access computing and communication resources only when authorized").

white hat hackers operate with **explicit permission**, follow **ethical guidelines** (e.g., **EC-Council’s CEH**, **OSSTMM**, or **NIST SP 800-115**), and often work as professionals or bug bounty hunters.

**penetration testing ethics** are often covered in other IEEE standards or guidelines, such as those from the **IEEE Cybersecurity Initiative** or **IEEE Certifed Ethical Hacker (CEH) resources**. For example:

* **IEEE 802.10** (historical standard for security) and newer frameworks emphasize authorized testing.
* **IEEE Std. 1012** (software verification) or **IEEE 2600** (hardware security) may touch on testing protocols.

widely recognized frameworks&#x20;

* **NIST SP 800-115** (Technical Guide to Penetration Testing).
* **ISO/IEC 27001** (for security testing norms).
* **EC-Council’s CEH Code of Ethics** (explicit rules for pentesters).

Their primary goal is to improve cybersecurity by identifying and fixing vulnerabilities before malicious actors can exploit them. Unlike gray or black hats, they never disclose vulnerabilities publicly without permission and adhere to contracts and responsible disclosure policies.

* **Key Traits:**
  * Operate legally under contracts or employment agreements (Schneier, 2020).
  * Follow responsible disclosure practices (ISO/IEC 29147), e.g., report vulnerabilities privately to the vendor.
  * Motivated by improving security, not fame or profit.
  * Often hold certifications like CEH (Certified Ethical Hacker) or OSCP (Offensive Security Certified Professional).
  * Compliance with laws like the Computer Fraud and Abuse Act (CFAA) (Schneier, 2020).

**Examples:**

1. **Kevin Mitnick (post-reformation)** – Once a notorious black hat, he became a respected cybersecurity consultant and author.
2. **Charlie Miller** – A well-known security researcher who worked for companies like Uber and Cruise Automation, uncovering critical vulnerabilities responsibly.
3. **Troy Hunt** – Creator of _Have I Been Pwned_, a security expert who collaborates with companies to expose data breaches ethically.

#### Gray Hat Hackers: The Unauthorized "Researchers"

2\) Gray hat hackers hack systems or computers to discover vulnerabilities and then inform the hacked entity about the vulnerabilities so that they can fix their commercial software/products or else hackers will publicly disclose the discovered vulnerabilities to shame a software vendor to pressure it into patching the vulnerabilities. However, hackers of this category often end up bragging about their hacking prowess/activities and call themselves security researchers. There are legitimate security researchers who work professionally within the scope of authorized hacking.

Gray hat hackers fall between white and black hats—they hack systems without permission but usually claim altruistic motives (Jordan & Taylor, 2004). They often breach regulations (e.g., CFAA) in the course of discovering security flaws within commercial software—a practice critiqued in literature as "vigilante security" (Denning, 2010). They then notify the software vendor (sometimes demanding payment) or threaten public exposure to force fixes. While some may genuinely help improve security, their methods are illegal and ethically questionable. Some call themselves security researchers, but legitimate researchers work within legal frameworks (e.g., bug bounty programs).

* **Key Traits:**
  * Hack without permission but often claim to act in the public interest.
  * May extort companies by threatening to release vulnerabilities.
  * Often seek recognition (bragging about exploits on social media or at conferences).
  * Some transition into white hat roles, while others drift toward black hat activities.

**Examples:**

1. **Marcus Hutchins (MalwareTech)** – Initially a gray hat hacker, he later became a white hat after stopping the _WannaCry_ ransomware attack.
2. **The Anonymous Researcher Who Leaked iOS Vulnerabilities** – Some gray hats have exposed Apple or Microsoft flaws without authorization, claiming it was for public safety.
3. **Researchers Who Sold Zero-Days** – Some gray hats have sold exploits to companies (or even governments) instead of reporting them responsibly.

#### Black Hat Hackers: The Criminals

3\) Black hat hackers come in two variations. The original/more traditional attribution of the label "black hat hackers" was given to the bad actors who hack for profit or for some other criminal goal. The more recent adoption of the term black hat hacking refers to presumably legal hacking practices whereby hackers have no prior knowledge of the target system (i.e., an label/attribution based on a technical perspective rather than an ethical perspective).

Black hat hackers engage in illegal hacking for personal gain, sabotage, or espionage (Chandler, 1996). They exploit vulnerabilities to steal data, deploy ransomware, or disrupt systems. Research ties them to organized crime and state-sponsored threats (Rid, 2013), with motivations ranging from financial theft to ideological disruption. Unlike white hats, they have no ethical constraints and often work within organized cybercrime syndicates or are rogue intelligence operatives. Their activities include identity theft, financial fraud, and espionage.

* **Key Traits:**
  * Operate purely for personal profit or destruction.
  * Use malware, phishing, and zero-day exploits maliciously.
  * Often work in underground forums (e.g., Dark Web markets).
  * May be state-sponsored (e.g., hacking for governments).

**Examples:**

1. **Albert Gonzalez** – Mastermind behind the _TJX and Heartland Payment Systems_ breaches, stealing millions of credit card details.
2. **Evgeniy Bogachev** – Creator of the _Zeus_ banking Trojan, responsible for stealing over $100 million.
3. **The Lazarus Group** – A North Korean state-sponsored hacking group behind the _Sony Pictures hack_ and _WannaCry_.

#### Hacktivists: The Politically Motivated Hackers

4\) Hacktivists hack for political ends.&#x20;

Hacktivists leverage cyber techniques for political or social causes, blurring lines between activism and cybercrime (Samuel, 2004). While some actions (e.g., DDoS) are illegal, their goals distinguish them from profit-driven black hats (Coleman, 2014). Unlike black hats, they are not primarily motivated by money but by ideology. Their targets include governments, corporations, or organizations they oppose. Tactics include DDoS attacks, website defacements, and data leaks.

* **Key Traits:**
  * Motivated by political/social causes (e.g., human rights, anti-censorship).
  * May work in collectives (e.g., _Anonymous_).
  * May blur the line between activism and cybercrime.

**Examples:**

1. **Anonymous** – Known for attacks on Sony (2011), the Church of Scientology, and governments in support of free speech.
2. **WikiLeaks Supporters** – Hackers who targeted institutions to expose classified documents (e.g., _Chelsea Manning leaks_).
3. **Phineas Fisher** – A hacktivist who breached _Hacking Team_ and _Gamma Group_, exposing surveillance tools sold to oppressive regimes.

#### **Final Comparison Table**

| Type           | Legal? | Motivation              | Methods                             | Examples                        |
| -------------- | ------ | ----------------------- | ----------------------------------- | ------------------------------- |
| **White Hat**  | ✅ Yes  | Improve security        | Authorized pentesting, bug bounties | Kevin Mitnick, Troy Hunt        |
| **Gray Hat**   | ❌ No   | Fame, forced fixes      | Unauthorized hacking, extortion     | Marcus Hutchins, iOS exploiters |
| **Black Hat**  | ❌ No   | Profit, destruction     | Malware, fraud, ransomware          | Albert Gonzalez, Lazarus Group  |
| **Hacktivist** | ❌ No   | Political/social change | DDoS, leaks, defacements            | Anonymous, Phineas Fisher       |

Each type has distinct motivations and methods, but the legality and ethics separate them most clearly. While white hats work within the system, gray hats operate in a moral gray zone, black hats are outright criminals, and hacktivists prioritize ideology over law.

### Professional ethics of ethical hackers

White hat hackers, or professional ethical hackers, operate under strict ethical guidelines to ensure their actions remain legal, responsible, and beneficial to cybersecurity. Unlike malicious hackers, they adhere to formalized codes of conduct, often outlined by organizations such as the **EC-Council (International Council of E-Commerce Consultants)**, **(ISC)²**, and the **IEEE**. These frameworks emphasize principles like **authorization, confidentiality, and non-maleficence** (avoiding harm). Academic research highlights that ethical hackers must balance aggressive security testing with respect for privacy and system integrity (Furnell & Warren, 1999).

* **Key Ethical Principles:**
  * **Authorization:** Ethical hackers must obtain explicit permission before testing systems (Harris, 2021).
  * **Confidentiality:** Discovered vulnerabilities must be reported privately to the organization, not publicly disclosed without consent.
  * **Integrity:** Findings should not be exploited for personal gain or malicious purposes.

#### **Legal and Contractual Obligations**

Professional ethical hackers work within legal boundaries, often bound by contracts that define the scope of penetration testing, data handling, and disclosure procedures. The **Computer Fraud and Abuse Act (CFAA)** in the U.S. and similar laws globally criminalize unauthorized access, making formal agreements essential (Schneier, 2020). Ethical hackers must also comply with industry standards like **ISO/IEC 27001** (information security management) and **NIST SP 800-115** (penetration testing guidelines). Failure to adhere to these obligations can result in legal consequences and reputational damage.

* **Critical Contractual Elements:**
  * **Scope of Work:** Clearly defined systems, networks, and testing methods.
  * **Non-Disclosure Agreements (NDAs):** Preventing leaks of sensitive findings.
  * **Responsible Disclosure Timelines:** Allowing vendors reasonable time to patch vulnerabilities before public disclosure.

#### **Moral Responsibility and Public Trust**

Ethical hackers hold a unique position of trust, as their work involves accessing sensitive systems that could be exploited if mishandled. Research by Tavani (2016) emphasizes the **duty of care** that ethical hackers owe to organizations and end-users. This includes avoiding unnecessary disruptions (e.g., crashing production servers) and ensuring that discovered vulnerabilities are not leaked to malicious actors. Additionally, ethical hackers must avoid conflicts of interest—such as working for competing firms without transparency—to maintain professional credibility.

* **Ethical Dilemmas in Practice:**
  * **Bug Bounty Ethics:** Should a hacker report a flaw for free or demand payment? Legitimate programs (e.g., HackerOne) provide structured rewards.
  * **Whistleblowing:** If a company ignores critical vulnerabilities, should the hacker go public? Most frameworks discourage this unless all legal avenues are exhausted.

#### **Academic and Industry Standards**

Academic literature underscores the need for standardized ethical training in cybersecurity education. Studies by Whitman & Mattord (2018) argue that ethical hacking curricula should include **philosophical ethics (utilitarianism, deontology)** alongside technical skills. Certifications like **Certified Ethical Hacker (CEH)** and **Offensive Security Certified Professional (OSCP)** include ethics modules to reinforce professional conduct. Furthermore, organizations like **OWASP (Open Web Application Security Project)** provide guidelines for responsible vulnerability disclosure, ensuring ethical hackers contribute positively to the cybersecurity ecosystem.

* **Best Practices from Research:**
  * **Transparency:** Documenting all testing activities for accountability.
  * **Continuous Education:** Staying updated on legal and ethical developments in cybersecurity.
  * **Public Interest:** Prioritizing vulnerabilities that pose significant societal risks (e.g., medical systems, infrastructure).

#### **Conclusion**

The professional ethics of white hat hackers are defined by legal compliance, contractual obligations, moral responsibility, and adherence to industry standards. Unlike gray or black hat hackers, ethical hackers must navigate complex ethical landscapes where their actions can either strengthen cybersecurity or inadvertently cause harm. By following established frameworks and maintaining public trust, they play a crucial role in defending digital systems against malicious threats.

### Other perspectives on hacking/hacker ethics

Coleman and Golub (2008) offer an anthropological taxonomy of various hacker ethic based on idioms and practices. Coleman and Golub (2008) see various hacker ethic as representative of the subjective self. They conceptualize three liberal moral expressions of hackers and hacking (cultural sensibilities or hacker ethics) revealed variably in the context of computer hacking: Cryptofreedom, free and open source software, and the hacker underground.

[Table 14: Profiles of Hackers](https://docs.google.com/document/d/e/2PACX-1vQVQ4AWXWyM83aXg5QxKwWkl9Oi8-gfRvUh7WhrMKekgb_I8yph4dTOtQYoXjflUA_6roJD5hWRGUT5/pub)

The pioneering historical work of Steven Levy (1984) on hacker culture and hacker ethic (Hackers: Heroes of the Computer Revolution) presents one of the earliest theorizations of hacker ethic (what hackers thought it meant to be a hacker), particularly in the early decades of computer technology in the 1950s and 1960s. Levy (1984) distilled the hacker ethic into six bullet points:

* Access to computers—and anything that might teach you something about the way the world works—should be unlimited and total. Always yield to the Hands-On Imperative!
* All information should be free.
* Mistrust authority—promote decentralization.
* Hackers should be judged by their hacking, not criteria such as degrees, age, race, sex, or position.
* You can create art and beauty on a computer.
* Computers can change your life for the better.

### Key takeaways

• Professional ethical hacking is legal (authorized) and contract based.

• Gray hat hacking is unauthorized hacking, but is essentially apolitical.

• Black hat hacking is criminal hacking (on ethical, not technical, grounds).

• Hacktivisim is politically motivated hacking.

### References

Chandler, A. (1996). The changing definition and image of hackers in popular discourse. _International Journal of the Sociology of Law, 24_(2), 229–251. [https://doi.org/10.1006/ijsl.1996.0012](https://doi.org/10.1006/ijsl.1996.0012)

Coleman, G. (2014). _Hacker, Hoaxer, Whistleblower, Spy: The Many Faces of Anonymous_. Verso.

Denning, D. (2010). "Cyber Conflict as an Emergent Social Phenomenon." _Corporate Cyber Security_.

Furnell, S., & Warren, M. (1999). "Ethical Hacking: A Necessary Evil?" _Computers & Security_.

Harris, S. (2021). CISSP All-in-One Exam Guide. McGraw-Hill.

Jordan, T., & Taylor, P. (2004). _Hacktivism and cyberwars: Rebels with a cause?_ Routledge. [https://doi.org/10.4324/9780203637997](https://doi.org/10.4324/9780203637997)

Rid, T. (2013). _Cyber War Will Not Take Place_. Oxford University Press.

Samuel, A. (2004). Hacktivism and the future of political participation. _Harvard Law Review, 117_(8), 2714–2727. [https://doi.org/10.2307/4093405](https://doi.org/10.2307/4093405)

Schneier, B. (2020). _Click here to kill everybody: Security and survival in a hyper-connected world._ W.W. Norton & Company.

Tavani, H. (2016). Ethics and Technology: Controversies, Questions, and Strategies for Ethical Computing. Wiley.

Whitman, M., & Mattord, H. (2018). Principles of Information Security. Cengage Learning.
