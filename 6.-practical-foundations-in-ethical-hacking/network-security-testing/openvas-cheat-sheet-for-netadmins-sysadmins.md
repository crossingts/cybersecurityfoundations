# OpenVAS cheat sheet for netadmins/sysadmins

A concise guide to vulnerability scanning, assessment, and management with OpenVAS—designed for netadmins and sysadmins to identify security risks, prioritize patching, and harden systems.

This cheat sheet covers:

✔ **Installation & initial setup**\
✔ **Scanning targets & scheduling tasks**\
✔ **Report analysis & vulnerability management**\
✔ **CLI usage & troubleshooting tips**

## **OpenVAS Cheat Sheet for NetAdmins & SysAdmins**

_Vulnerability Scanning, Reporting, and Management_

***

### **1. Installation & Setup**

#### **Install OpenVAS (Debian/Ubuntu)**

sh

```
sudo apt update  
sudo apt install openvas  
sudo gvm-setup  # Initial setup (takes time)  
sudo gvm-check-setup  # Verify installation  
sudo gvm-start  # Start services  
```

#### **Access Web Interface**

* URL: `https://127.0.0.1:9392`
* Default credentials:
  * Username: `admin`
  * Password: (generated during `gvm-setup`)

#### **Update Vulnerability Databases**

sh

```
sudo gvm-feed-update  
```

***

### **2. Basic Scanning**

#### **Create a New Target**

1. **Navigate:** `Configuration → Targets → New Target`
2. **Enter:**
   * Name: `Internal Network Scan`
   * Hosts: `192.168.1.0/24` or `192.168.1.100`
   * Ports: `default` (or customize, e.g., `T:1-1000,U:53,161`)
   * Alive Test: `ICMP, TCP-ACK Service Ping`

#### **Create a New Task**

1. **Navigate:** `Scans → Tasks → New Task`
2. **Configure:**
   * Name: `Full Vulnerability Scan`
   * Target: Select previously defined target
   * Scan Config:
     * **Full and fast** (recommended for most scans)
     * **Full and very deep** (comprehensive, slow)
     * **Host Discovery** (quick host detection)

#### **Start a Scan**

* Select task → Click **Start** (▶️)
* Monitor progress in **Reports**

***

### **3. Advanced Scanning**

#### **Custom Scan Configurations**

1. **Navigate:** `Configuration → Scan Configs`
2. **Modify existing or create new:**
   * Adjust **NVT (Network Vulnerability Tests) Families** (e.g., disable "DoS" for production scans).
   * Set **Performance Options** (reduce timeout for faster scans).

#### **Scheduled Scans**

1. **Create Task → Schedule:**
   * Set **Recurrence** (Daily, Weekly, Monthly).
   * Example: Weekly scan every Sunday at 2 AM.

#### **Authenticated Scans**

* **For Windows (SMB/Credentials):**
  * Provide **Username/Password** in **Target → Credentials**.
* **For Linux (SSH):**
  * Use SSH keys or credentials.

#### **Exclude Hosts/IPs from Scan**

* In **Target Configuration**, set **Exclude Hosts**: `192.168.1.50, 192.168.1.60`

***

### **4. Report Generation & Analysis**

#### **View Reports**

* **Navigate:** `Scans → Reports`
* Filter by: **High Severity, False Positives, Fixed Vulnerabilities**

#### **Export Reports**

* **Formats:**
  * **PDF** (for management)
  * **CSV** (for spreadsheets)
  * **XML** (for integration with other tools)

#### **Filtering Vulnerabilities**

* Use **Filters** to show:
  * Only **Critical/High** vulnerabilities.
  * **False Positives** (mark after verification).

#### **Compare Reports (Trend Analysis)**

* **Navigate:** `Reports → Compare`
* Select two reports to see changes over time.

***

### **5. Vulnerability Management**

#### **False Positive Management**

1. **Navigate to Report → Select Vulnerability → Override**
2. Set status: **False Positive** (add notes for justification).

#### **Remediation Tracking**

* **Mark as Fixed:** After patching, override status.
* **Add Notes:** Document mitigation steps.

#### **Alerting & Notifications**

* **Configure:** `Configuration → Alerts`
* **Email Notifications:** Send alerts when new critical vulnerabilities are found.

***

### **6. Command-Line (GVM-Tools)**

#### **Run a Scan via CLI**

sh

```
gvm-cli --gmp-username admin --gmp-password <password> socket --xml "<create_task><name>CLI Scan</name><target id='target-id'/><config id='daba56c8-73ec-11df-a475-002264764cea'/></create_task>"  
```

#### **Export Reports via CLI**

sh

```
gvm-cli --gmp-username admin --gmp-password <password> socket --xml "<get_reports report_id='report-id' format_id='a994b278-1f62-11e1-96ac-406186ea4fc5'/>" > report.pdf  
```

_(Format ID: PDF = `a994b278-1f62-11e1-96ac-406186ea4fc5`)_

***

### **7. Troubleshooting & Maintenance**

#### **Check OpenVAS Services**

sh

```
sudo gvm-status  
```

#### **Restart OpenVAS**

sh

```
sudo gvm-stop  
sudo gvm-start  
```

#### **Logs Location**

sh

```
/var/log/gvm/  
```

#### **Reset Admin Password**

sh

```
sudo runuser -u _gvm -- gvmd --user=admin --new-password=newpassword  
```

***

### **Quick Reference Table**

| **Task**               | **Action**                           |
| ---------------------- | ------------------------------------ |
| **Update Feeds**       | `sudo gvm-feed-update`               |
| **Start Scan**         | Web UI → Tasks → Start               |
| **Authenticated Scan** | Add credentials in **Target** config |
| **Export PDF Report**  | Reports → Export → PDF               |
| **Schedule Scan**      | Task → Schedule → Recurring          |
| **False Positive**     | Report → Override → False Positive   |

***

**Best Practices:**\
✔ Run **weekly automated scans** for critical networks.\
✔ Use **authenticated scans** for deeper vulnerability detection.\
✔ **Review false positives** to avoid clutter.\
✔ **Patch critical vulnerabilities** within 24-48 hours.

**For More:**

* [OpenVAS Official Docs](https://www.greenbone.net/en/documentation/)
* `man gvm-*` for CLI tools
