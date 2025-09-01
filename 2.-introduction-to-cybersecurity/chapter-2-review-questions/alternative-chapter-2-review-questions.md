---
hidden: true
---

# Alternative Chapter 2 review questions

### Foundational cybersecurity concepts

**1. Define the three components of the CIA triad and provide a simple example of what protecting each one means for a company's customer database.**\
**Answer:**

* **Confidentiality:** Protecting information from unauthorized access. Example: Ensuring only authorized employees can view customer personal information using passwords and encryption.
* **Integrity:** Ensuring data is accurate and unaltered. Example: Preventing a hacker from maliciously changing customer order details or account balances.
* **Availability:** Ensuring information is accessible when needed. Example: Keeping the database online so customers can place orders and access their accounts without interruption.

**2. Explain the relationship between a vulnerability, a threat, and a risk in the context of information security.**\
**Answer:**\
A **vulnerability** is a weakness in a system (e.g., unpatched software). A **threat** is a potential danger that could exploit a vulnerability (e.g., a hacker looking to attack). **Risk** is the potential for loss or damage when a threat successfully exploits a vulnerability. It is often calculated as Threat × Vulnerability × Impact.

**3. What are the three standard responses to a risk identified during a risk assessment? Briefly describe each.**\
**Answer:**\
The three standard responses are:

* **Accept:** The cost of implementing countermeasures is deemed higher than the potential cost of the loss, so the risk is consciously accepted.
* **Mitigate:** Implementing safeguards and controls (like firewalls or policies) to reduce either the vulnerability or the impact of the threat.
* **Transfer:** Shifting the financial burden of the risk to another party, such as by purchasing cybersecurity insurance.

**4. The text states that a SYN flood attack is a technique that compromises availability. How does this attack work?**\
**Answer:**\
A SYN flood attack targets the TCP three-way handshake. An attacker sends a flood of SYN packets (connection requests), often with spoofed source IP addresses. The target server allocates resources for each request and sends back a SYN-ACK, but the attacker never sends the final ACK to complete the connection. This exhausts the server's resources, making it unable to respond to legitimate connection requests and causing a denial of service.

**5. Differentiate between the purposes of the RADIUS and TACACS+ protocols within the AAA framework.**\
**Answer:**\
Both RADIUS and TACACS+ are AAA protocols, but they have key differences:

* **RADIUS** is an open standard that combines authentication and authorization. It uses UDP and is often used for network access control (like Wi-Fi logins).
* **TACACS+** (developed by Cisco) separates authentication, authorization, and accounting into discrete processes. It uses TCP and provides more detailed control and accounting, making it popular for administering network devices like routers and switches.

### The cybersecurity threat landscape

