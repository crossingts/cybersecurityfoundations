# Wazuh (SEIM/XDR)

### Wazuh (SIEM/XDR)

The Wazuh Security Information and Event Management (SIEM) solution is a centralized platform for aggregating and analyzing telemetry in real time for threat detection and compliance. Wazuh collects event data from various sources like endpoints, network devices, cloud workloads, and applications for broader security coverage. (wazuh.com)

The Wazuh Extended Detection and Response (XDR) platform provides a comprehensive security solution that detects, analyzes, and responds to threats across multiple IT infrastructure layers. Wazuh collects telemetry from endpoints, network devices, cloud workloads, third-party APIs, and other sources for unified security monitoring and protection. (wazuh.com)

Wazuh is an open-source security monitoring platform that provides SIEM (log analysis) and EDR (endpoint monitoring and response) functionalities, enabling centralized visibility, threat detection, compliance monitoring, and automated mitigation.

1. **SIEM (Security Information and Event Management)**\
   Wazuh provides log collection, analysis, and correlation, which are core SIEM functionalities. It can aggregate logs from various sources (network devices, endpoints, and cloud services) and apply rules to detect threats.
2. **EDR (Endpoint Detection and Response)** \
   Wazuh provides EDR capabilities (file integrity monitoring, process monitoring, behavioral analysis, and automated responses).
3. **Centralized Visibility & Threat Mitigation**\
   Wazuh offers a centralized dashboard for monitoring security events across endpoints, supports active responses (e.g., blocking malicious IPs), and integrates with threat intelligence feeds.

**How Wazuh Works:**

1. **Log Collection**
   * Wazuh collects logs from various sources, including:
     * **Network devices** (firewalls, routers, switches via syslog, SNMP, etc.).
     * **Endpoints** (servers, workstations, cloud instances using the Wazuh agent).
     * **Third-party APIs** (cloud services like AWS, Azure, Office 365, etc.).
     * **Security tools** (IDS/IPS, antivirus, vulnerability scanners).
2. **Log Analysis & Correlation**
   * Wazuh **normalizes and parses** logs into a structured format.
   * It applies **rules** (predefined & custom) to detect suspicious activity.
   * It **correlates events** (e.g., multiple failed logins + a successful login from a new IP → potential brute-force attack).
3. **Alerting on Threats**
   * When a rule is triggered, Wazuh generates an **alert**.
   * Alerts can be sent via email, SIEM integrations (Elasticsearch, Splunk), or other notification methods.
   * Wazuh also provides **active monitoring** (e.g., checking for unauthorized changes in files, detecting malware) and **automated responses** (e.g., blocking an IP after too many failed logins).
