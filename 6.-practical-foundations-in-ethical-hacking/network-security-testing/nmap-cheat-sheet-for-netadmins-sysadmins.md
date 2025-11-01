# Nmap cheat sheet for netadmins/sysadmins

The ultimate reference for network exploration, security auditing, and system enumeration—tailored for netadmins and sysadmins to map networks, discover services, and assess vulnerabilities efficiently.

This cheat sheet covers:

✔ **Host discovery techniques**\
✔ **Port scanning & service detection**\
✔ **OS fingerprinting & script automation**\
✔ **Stealth & evasion tactics**

## **Nmap Cheat Sheet for NetAdmins & SysAdmins**

_Active Host Discovery, Port Scanning, and Enumeration_

***

### **1. Nmap Installation & Setup**

bash

```
# Install on Ubuntu/Debian
sudo apt install nmap

# Install on CentOS/RHEL
sudo yum install nmap
# or for newer versions:
sudo dnf install nmap

# Install on macOS
brew install nmap

# Install on Windows
# Download from: https://nmap.org/download.html

# Check installation and version
nmap --version

# Update Nmap (on Kali/Ubuntu/Debian)
sudo apt update && sudo apt upgrade nmap

# Update NSE scripts
nmap --script-updatedb
```

***

### **2. Host Discovery**

Find live hosts in a network without port scanning.

#### **Basic Ping Scan**

sh

```
nmap -sn 192.168.1.0/24  
```

* `-sn`: Disables port scanning (ping-only).

#### **ARP Scan (Local Network)**

sh

```
nmap -PR 192.168.1.0/24  
```

* `-PR`: ARP discovery (fastest for local networks).

#### **No Ping Scan (Skip Host Discovery)**

sh

```
nmap -Pn 192.168.1.100  
```

* `-Pn`: Treats all hosts as online (bypasses firewalls blocking ICMP).

#### **TCP SYN Ping Discovery**

sh

```
nmap -PS22,80,443 192.168.1.0/24  
```

* `-PS`: Sends SYN packets to specified ports (default: 80).

#### **UDP Ping Discovery**

sh

```
nmap -PU53,161 192.168.1.0/24  
```

* `-PU`: Sends UDP packets to check for responses.

#### **ICMP Echo & Timestamp Ping**

sh

```
nmap -PE -PP 192.168.1.0/24  
```

* `-PE`: ICMP Echo Request
* `-PP`: ICMP Timestamp Request

#### **List Scan (DNS Resolution Only)**

sh

```
nmap -sL 192.168.1.0/24  
```

* `-sL`: Lists hosts without scanning.

***

### **3. Port Scanning**

Identify open ports and services.

#### **Basic TCP SYN Scan (Stealthy)**

sh

```
nmap -sS 192.168.1.100  
```

* `-sS`: SYN scan (fast, doesn’t complete TCP handshake).

#### **TCP Connect Scan (Full Handshake)**

sh

```
nmap -sT 192.168.1.100  
```

* `-sT`: Completes TCP connection (noisier).

#### **UDP Scan (Slower but Essential)**

sh

```
nmap -sU 192.168.1.100  
```

* `-sU`: Scans UDP ports (use `-T4` for speed).

#### **Aggressive Scan (OS, Version, Scripts)**

sh

```
nmap -A 192.168.1.100  
```

* `-A`: Enables OS detection (`-O`), version detection (`-sV`), and script scanning (`-sC`).

#### **Fast Scan (Top 100 Ports)**

sh

```
nmap -F 192.168.1.100  
```

* `-F`: Scans top 100 ports (faster than default).

#### **Scan Specific Ports**

sh

```
nmap -p 22,80,443,3389 192.168.1.100  
nmap -p 1-1000 192.168.1.100  
nmap -p- 192.168.1.100  # All ports (1-65535)  
```

#### **Service Version Detection**

sh

```
nmap -sV 192.168.1.100  
```

* `-sV`: Probes services for version info.

#### **OS Detection**

sh

```
nmap -O 192.168.1.100  
```

* `-O`: Attempts OS fingerprinting.

***

### **4. Enumeration & Scripting**

Gather detailed info using NSE (Nmap Scripting Engine).

#### **Default Safe Scripts**

sh

```
nmap -sC 192.168.1.100  
```

* `-sC`: Runs default safe scripts.

#### **Run Specific Scripts**

sh

```
nmap --script=http-title,http-headers 192.168.1.100  
nmap --script=smb-enum-shares 192.168.1.100  
```

#### **Vulnerability Scanning**

sh

```
nmap --script=vuln 192.168.1.100  
```

* Runs vulnerability detection scripts.

#### **SMB Enumeration**

sh

```
nmap --script=smb-os-discovery,smb-enum-users 192.168.1.100  
```

#### **HTTP Enumeration**

sh

```
nmap --script=http-enum,http-robots.txt 192.168.1.100  
```

#### **DNS Enumeration**

sh

```
nmap --script=dns-brute example.com  
```

***

### **5. Performance & Output**

#### **Adjust Timing (Speed)**

sh

```
nmap -T0 (Paranoid)  
nmap -T1 (Sneaky)  
nmap -T2 (Polite)  
nmap -T3 (Normal)  
nmap -T4 (Aggressive)  
nmap -T5 (Insane)  
```

#### **Save Output**

sh

```
nmap -oN output.txt 192.168.1.100      # Normal  
nmap -oX output.xml 192.168.1.100      # XML  
nmap -oG output.gnmap 192.168.1.100    # Grepable  
nmap -oA output 192.168.1.100          # All formats  
```

***

### **6. Advanced Techniques**

#### **Spoof Source IP (Decoy Scan)**

sh

```
nmap -D RND:10 192.168.1.100  
```

* `-D`: Adds decoy IPs to confuse logging.

#### **Fragment Packets (Evasion)**

sh

```
nmap -f 192.168.1.100  
```

* `-f`: Splits packets into smaller fragments.

#### **Idle (Zombie) Scan**

sh

```
nmap -sI zombie-ip 192.168.1.100  
```

* Uses a third-party host to scan (stealthy).

***

### **Quick Reference Table**

| **Command**                        | **Description**                        |
| ---------------------------------- | -------------------------------------- |
| `nmap -sn 192.168.1.0/24`          | Ping sweep (host discovery)            |
| `nmap -sS 192.168.1.100`           | Stealth SYN scan                       |
| `nmap -sV -sC 192.168.1.100`       | Version detection + default scripts    |
| `nmap -A 192.168.1.100`            | Aggressive scan (OS, version, scripts) |
| `nmap -p 80,443 192.168.1.100`     | Scan specific ports                    |
| `nmap --script=vuln 192.168.1.100` | Vulnerability scan                     |

***

**Pro Tip:** Always ensure you have **proper authorization** before scanning networks.\
**For more:** `man nmap` or visit [nmap.org](https://nmap.org/)
