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
  * **White Hat Hackers: The Ethical Professionals**
  * **Gray Hat Hackers: The Unauthorized Researchers**
  * **Black Hat Hackers: The Criminals**
  * **Hacktivists: The Politically Motivated Hackers**
* **Other perspectives on hacking/hacker ethics**

### Introduction

There are many approaches to distinguish between white hat hackers, gray hat hackers, black hat hackers, and hacktivists (see Other perspectives on hacking/hacker ethics).

However, we make a comparison differentiating between these four hacker groups and their hacking practices on the logic that there is only one category of white hat hacking: legal hacking. Ethical values and professional ethics underlying the practices of white hat hackers further cement this taxonomy of the various hacker groups.

Ethical hackers (as penetration testers) necessarily fit into the white hat hackers group—there's no moral or legal ambiguity regrading the legality of their practices. No greyness. In this classification scheme, the terms white hat hacking and ethical hacking can be used **interchangeably**.&#x20;

Finally, we advance an understanding that professional ethical hacking is ethical hacking (penetration testing) performed in accordance with widely established industry and licensing standards regarding what constitutes professional conduct.

Assumptions:

• Penetration testing is ethical hacking, since ethical hacking most formally refers to penetration testing, and since penetration testing professionals strictly abide by a legal framework, while acknowledging that it does not follow from this that all ethical hacking is penetration testing—there could be other varieties of claimed ethical hacking practices (e.g., hacktivists). So we further specify what constitutes "ethical" in ethical hacking and we advance that it refers to claimed or demonstrated moral ethics and to widely established professional codes on conduct (which hacktivists, e.g., do not adhere to).

• Ethical hackers (as penetration testers) fit only within the white hat hackers group on the basis of legal and ethical (moral) conduct.

• Professional ethical hacking is ethical hacking performed in accordance with widely established industry standards and professional licensing authorities regarding what constitutes professional conduct.

### Profiles of hackers

Follows is an analysis of the four types of hacking/hacker groups classified based on the legality of their practices, professional ethical conduct, and moral ethics.

The professional ethics of white hat hackers are defined by legal compliance, contractual obligations, moral responsibility, and adherence to industry standards. Unlike gray or black hat hackers, ethical hackers must successfully navigate complex ethical and legal landscapes to preserve their professional and reputational standing. By following established frameworks and maintaining public trust, ethical hackers play a crucial role in defending digital systems against malicious threats.

#### White Hat Hackers: The Ethical Professionals

White hat hackers only hack systems or machines with legal authorization to do so (including legal contractual agreements). So whether resident (in-house) employees of a company or hired by a company for security testing, the practices of white hat hackers would be ethical as long as hacking is performed in accordance with agreed upon terms and within the specified authorization parameters (hacking beyond authorized levels or terms of service ceases to be ethical). Bug bounty hunters are ethical hackers since they work within this contractual framework.&#x20;

White hat hackers operate with **explicit permission** and follow **industry and regulatory ethical guidelines** (e.g., **EC-Council’s CEH**, **OSSTMM**, or **NIST SP 800-115**)

The practices of white hats align with professional codes like the **ACM Code of Ethics (2018)**, which mandates permission-based hacking, and guidelines such as IEEE code of ethics, IEEE code of conduct and NIST SP 800-115. The **ACM Code of Ethics (2018)** stresses **permission-based hacking** (e.g., Principle 2.8: "Access computing and communication resources only when authorized").

**Penetration testing ethics** are covered in IEEE standards or guidelines, such as those from the **IEEE Cybersecurity Initiative** or **IEEE Certified Ethical Hacker (CEH) resources**. For example:

* **IEEE 802.10** (historical standard for security) and newer frameworks emphasize authorized testing.
* **IEEE Std. 1012** (software verification).
* **NIST SP 800-115** (Technical Guide to Penetration Testing).
* **ISO/IEC 27001** (for security testing norms).
* **EC-Council’s CEH Code of Ethics** (explicit rules for pentesters).
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

#### Gray Hat Hackers: The Unauthorized Researchers

Gray hat hackers fall between white and black hats—they hack computer systems without permission but usually claim altruistic motives (Jordan & Taylor, 2004). They often breach regulations (e.g., CFAA) in the course of discovering security flaws within commercial software—a practice critiqued in literature as "vigilante security" (Denning, 2010). They then notify the software vendor asking it to fix discovered vulnerabilities and threaten public exposure of the vulnerabilities if the vendor does not oblige (sometimes they demand payment). While some may genuinely help improve security, their methods are illegal and ethically questionable. Some call themselves security researchers, but legitimate researchers work within legal frameworks (e.g., bug bounty programs).

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

Black hat hackers come in two variations. The original/more traditional attribution of the label "black hat hackers" is associated with the bad actors who hack for personal profit or for some other criminal goal. The more recent use of the term black hat hacking refers to presumably legal hacking practices whereby hackers have no prior knowledge of the target system (i.e., an attribution based on a technical perspective rather than an ethical perspective).

Black hat hackers as criminals engage in illegal hacking for personal gain, sabotage, or espionage (Chandler, 1996). They exploit vulnerabilities to steal data, deploy ransomware, or disrupt systems. Research ties them to organized crime and state-sponsored threats (Rid, 2013), with motivations ranging from financial theft to ideological disruption. Unlike white hats, they have no ethical constraints and often work within organized cybercrime syndicates or are rogue intelligence operatives. Their activities include identity theft, financial fraud, and espionage.

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

Hacktivists leverage cyber techniques for political or social causes, blurring the line between activism and cybercrime (Samuel, 2004). While some actions (e.g., DDoS) are illegal, their goals distinguish them from profit-driven black hats (Coleman, 2014). Unlike black hats, they are not primarily motivated by money but by ideology. Their targets include governments, corporations, or organizations they oppose. Tactics include DDoS attacks, website defacements, and data leaks.

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

Each hacker group has distinct motivations, but the legality of their practices and their moral ethics separate them most clearly. While white hats work within the legal system, gray hats operate in a moral gray zone, black hats are outright criminals, and hacktivists prioritize ideology over law.

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

Harris, S. (2021). CISSP All-in-One Exam Guide. McGraw-Hill.

Jordan, T., & Taylor, P. (2004). _Hacktivism and cyberwars: Rebels with a cause?_ Routledge. [https://doi.org/10.4324/9780203637997](https://doi.org/10.4324/9780203637997)

Rid, T. (2013). _Cyber War Will Not Take Place_. Oxford University Press.

Samuel, A. (2004). Hacktivism and the future of political participation. _Harvard Law Review, 117_(8), 2714–2727. [https://doi.org/10.2307/4093405](https://doi.org/10.2307/4093405)

Schneier, B. (2020). _Click here to kill everybody: Security and survival in a hyper-connected world._ W.W. Norton & Company.

Tavani, H. (2016). Ethics and Technology: Controversies, Questions, and Strategies for Ethical Computing. Wiley.

Whitman, M., & Mattord, H. (2018). Principles of Information Security. Cengage Learning.
