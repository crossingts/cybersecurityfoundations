---
description: >-
  This section is an introduction to the Cisco IOS CLI and basic device security
  configuration
---

# Cisco IOS CLI and basic device security

Welcome to the practical heart of network administration. In this section, we move from conceptual networking fundamentals to the essential hands-on skill of configuring and securing a network device. We will be using the Cisco IOS Command-Line Interface (CLI), the operating system that powers the vast majority of routers and switches worldwide. You will first learn how to physically connect to a device and access the CLI using a terminal emulator. We will then guide you through the CLI's structure, including its different command modes and shortcuts. More importantly, we will immediately apply these skills to the critical task of basic device security, where you will learn how to set passwords, encrypt them, and securely manage your device's configuration. This foundation is your first step toward managing network infrastructure and is a core competency for any cybersecurity professional tasked with protecting network assets.

## Topics covered in this section

* **What is the Cisco IOS CLI?**
* **Connecting to a Cisco device via the console port**
* **Terminal Emulator (PuTTY)**
* **CLI command modes**
  * **User EXEC mode**
  * **Privileged EXEC mode**
  * **Cisco IOS CLI shortcuts**
  * **Global configuration mode**
* **Command syntax conventions**
* **Basic device security**
  * **enable password command**
  * **show running-config and show startup-config commands**
  * **Saving the configuration**
  * **service password-encryption command**
  * **enable secret command**
* **Canceling commands**
* **Command review**
* **Key learnings**
* **Packet Tracer lab (basic device security)**

### What is the Cisco IOS CLI?

The Cisco IOS command-line interface (CLI) is the primary user interface used for configuring, monitoring, and maintaining Cisco devices. This user interface allows you to directly and simply execute Cisco IOS commands, whether using a router console or terminal, or using remote access methods. (cisco.com)

Cisco IOS is the operating system used on Cisco devices. IOS stands for Internetwork Operating System. CLI is the interface used to configure Cisco devices like routers, switches, and firewalls. The CLI is often compared to the GUI or Graphical User Interface, which is not discussed here.

### Connecting to a Cisco device via the console port

There are a couple of methods to connect to a Cisco device to configure it with the CLI. First, remotely via [Telnet or SSH](https://itnetworkingskills.wordpress.com/2023/04/12/how-configure-ssh-cisco-devices/). Second, locally via the console port. Here we will discuss connecting via the console port. Connecting to a Cisco device via the console port typically involves bringing your laptop to the device and connecting to the console port of the device.

This is a Cisco Catalyst switch. Notice the two console ports: one is an RJ45 (Registered Jack), the other is a USB Mini-B.&#x20;

<figure><img src="https://itnetworkingskills.wordpress.com/wp-content/uploads/2024/05/a0e21-rj45-cisco-catalyst.webp?w=1051" alt="RJ45-cisco-catalyst" height="676" width="1051"><figcaption><p>Image courtesy of Jeremy’s IT Lab (Free CCNA | Intro to the CLI | Day 4)</p></figcaption></figure>

Let’s say we’re going to connect to the RJ45 port. We will need the proper cable. A rollover cable (console cable) can be used to connect to the RJ45 console port on a Cisco device. A rollover cable has on one end an RJ45 connector and on the other end a DB9 connector. Most modern laptops do not have a serial port a DB9 connector can be plugged into. So you might need an adapter to connect to a USB port on a laptop.

This image shows the wiring in a rollover cable. Like in an Ethernet UTP cable there are eight pins on each end. Pin 1 on one end connects to Pin 8 on the other, Pin 2 to Pin 7, Pin 3 to Pin 6, and so on.

<figure><img src="https://itnetworkingskills.wordpress.com/wp-content/uploads/2024/05/52dad-rollover-cable-wiring.webp?w=1201" alt="rollover-cable-wiring" height="574" width="1201"><figcaption><p>Image courtesy of Jeremy’s IT Lab (Free CCNA | Intro to the CLI | Day 4)</p></figcaption></figure>

So we’ve connected a laptop/computer to a Cisco Catalyst device via the device’s RJ45 port.

### Terminal Emulator (PuTTY)

Once you have connected your computer to the device you can access the CLI using a Terminal Emulator. PuTTY is a popular choice. You can get PuTTY at[ ](https://www.google.com/url?q=http://putty.org\&sa=D\&source=editors\&ust=1694043778222797\&usg=AOvVaw0afc3nKW8nyq0IeiHdARxL)[putty.org](https://www.google.com/url?q=http://putty.org\&sa=D\&source=editors\&ust=1694043778222916\&usg=AOvVaw3KVjZjjLvW7-QiamfJvmYx)

<figure><img src="https://itnetworkingskills.wordpress.com/wp-content/uploads/2024/05/047a8-putty-cli.webp?w=1201" alt="PuTTY-CLI" height="529" width="1201"><figcaption><p>Image courtesy of Jeremy’s IT Lab (Free CCNA | Intro to the CLI | Day 4)</p></figcaption></figure>

We are using PuTTY for our current demonstration. Select Serial and click Open and you should be connected to the CLI. You should be able to connect with the default settings.

These settings match the defaults on Cisco devices. Try to remember the defaults for the CCNA test – the **speed or baud rate (9600), data bits (8), stop bits (1), parity (none), and flow control (none).**

Understanding data bits and stop bits is outside the scope of the CCNA, but the idea is that for each 8 bits of data 1 stop bit is sent to mark the end of the 8 bits. Parity is used to detect errors. Flow control pertains to the flow of data from transmitter to receiver.

Once you connect to the Cisco device (e.g., a Cisco ISR router) you will be greeted with a screen like this:&#x20;

<figure><img src="https://itnetworkingskills.wordpress.com/wp-content/uploads/2024/05/aa87b-cisco-device-login-screen.webp?w=1177" alt="cisco-device-login-screen" height="675" width="1177"><figcaption><p>Image courtesy of Jeremy’s IT Lab (Free CCNA | Intro to the CLI | Day 4)</p></figcaption></figure>

Since this is the first time booting the device, you are asked to enter the initial configuration dialogue. Answer no. As per the screen instructions, press the enter key (RETURN) to get started. Now you can start typing commands in the CLI.

The tasks discussed in this lesson can be done with **Packet Tracer** to an adequate approximation to real, physical Cisco devices being configured by a Terminal Emulator/PuTTY.

### CLI command modes

#### User EXEC mode

When you first enter the CLI, you will be by default in the user EXEC mode (also called user mode).

User EXEC mode is indicated by the greater than symbol, after the host name of the device:

Router>

The default host name for this device is Router. The name preceding the greater than symbol always indicates the host name of the device.

User EXEC mode is very limited. Users can look at some settings but cannot make any changes to the configuration. Usually you don’t do anything in this mode.

Let’s move on to a mode with a little more power to make changes to the device.

#### Privileged EXEC mode

If you enter the enable command in user mode, you will be placed in privileged EXEC mode.

Router>enable (press enter to enter privileged EXEC mode)

Router#

In privileged EXEC mode, a pound sign or hashtag is displayed.

Privileged EXEC mode provides complete access to view the device’s configuration, restart the device, change the time on the device, and save the current configuration file.

But it is not the mode in which you change the configuration.

#### Cisco IOS CLI shortcuts

Follows is a list of the commands available in user and privileged modes. The first list is from **User EXEC Mode** (indicated by the `Router>` prompt) and the second, longer list is from **Privileged EXEC Mode** (indicated by the `Router#` prompt, which you get after typing `enable`). You can use the question mark to view the commands available to you. For example: Router>? and Router#?

**User EXEC Mode Commands (`Router>?`)**

| Command      | Description                               |
| ------------ | ----------------------------------------- |
| `<1-99>`     | Session number to resume                  |
| `connect`    | Open a terminal connection                |
| `disable`    | Turn off privileged commands              |
| `disconnect` | Disconnect an existing network connection |
| `enable`     | Turn on privileged commands               |
| `exit`       | Exit from the EXEC                        |
| `logout`     | Exit from the EXEC                        |
| `ping`       | Send echo messages                        |
| `resume`     | Resume an active network connection       |
| `show`       | Show running system information           |
| `ssh`        | Open a secure shell link connection       |
| `telnet`     | Open a telnet connection                  |
| `terminal`   | Set terminal line parameters              |
| `traceroute` | Trace route to destination                |

**Privileged EXEC Mode Commands (`Router#?`)**

| Command      | Description                                                 |
| ------------ | ----------------------------------------------------------- |
| `<1-99>`     | Session number to resume                                    |
| `auto`       | Exec level Automation                                       |
| `clear`      | Reset functions                                             |
| `clock`      | Manage the system clock                                     |
| `configure`  | Enter configuration mode                                    |
| `connect`    | Open a terminal connection                                  |
| `copy`       | Copy from one file to another                               |
| `debug`      | Debugging functions (see also 'undobug')                    |
| `delete`     | Delete a file                                               |
| `dir`        | List files on a filesystem                                  |
| `disable`    | Turn off privileged commands                                |
| `disconnect` | Disconnect an existing network connection                   |
| `enable`     | Turn on privileged commands                                 |
| `erase`      | Erase a filesystem                                          |
| `exit`       | Exit from the EXEC                                          |
| `logout`     | Exit from the EXEC                                          |
| `mkdir`      | Create new directory                                        |
| `more`       | Display the contents of a file                              |
| `no`         | Disable debugging informations                              |
| `ping`       | Send echo messages                                          |
| `reload`     | Halt and perform a cold restart                             |
| `resume`     | Resume an active network connection                         |
| `rmdir`      | Remove existing directory                                   |
| `send`       | Send a message to other tty lines                           |
| `setup`      | Run the SETUP command facility                              |
| `show`       | Show running system information                             |
| `ssh`        | Open a secure shell client connection                       |
| `telnet`     | Open a telnet connection                                    |
| `terminal`   | Set terminal line parameters                                |
| `traceroute` | Trace route to destination                                  |
| `undebug`    | Disable debugging functions (see also 'debug')              |
| `vlan`       | Configure VLAN parameters                                   |
| `write`      | Write running configuration to memory, network, or terminal |

The tab key is a convenient feature of the CLI. If you press the tab key after typing “Router>en”, the CLI will complete the word and display the complete word on a new line:

Router>en

Router>enable

Router# (you’ve entered privileged EXEC mode)

You do not need to type the complete command. Hit enter after “Router>en” and you will be brought to privileged EXEC mode.

“en” was enough for the router to understand that what was meant by en was enable because enable was the only command that begins with en that can be entered in user mode. If we typed just e:

Router>e (and we press enter) we get a message:

% Ambiguous command: “e”

Router>&#x20;

There is more than one command that begins with e. We can view the commands that begin with e by using the question mark:

Router>e?

enable exit

Router>e

The shortest form of the enable command is en. The shortest for the exit command is ex.

#### Global configuration mode

Now let’s make some changes to the router configuration. We need to enter global configuration mode.

Router#configure terminal (the command to enter global configuration mode)

Or

Router#conf t (shortcut for configure terminal)

Router(config)# (now we are in global configuration mode)

In global configuration mode, config is inserted after the host name.

### Command syntax conventions&#x20;

Cisco IOS Command Reference uses certain conventions to present command syntax. Cisco IOS documentation uses the following command syntax conventions:

| Convention    | Description                                                                                                                                 |
| ------------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| **bold**      | Bold text indicates commands and keywords that you enter as shown.                                                                          |
| _italic_      | Italic text indicates arguments for which you supply values.                                                                                |
| \[x]          | Square brackets enclose an optional keyword or argument.                                                                                    |
| ...           | An ellipsis (three consecutive nonbolded periods without spaces) after a syntax element indicates that the element can be repeated.         |
| \|            | A vertical line, called a pipe, that is enclosed within braces or square brackets indicates a choice within a set of keywords or arguments. |
| \[x \| y]     | Square brackets enclosing keywords or arguments separated by a pipe indicate an optional choice.                                            |
| {x \| y}      | Braces enclosing keywords or arguments separated by a pipe indicate a required choice.                                                      |
| \[x {y \| z}] | Braces and a pipe within square brackets indicate a required choice within an optional element.                                             |

Cisco IOS Configuration Fundamentals Command Reference, Cisco Systems, Inc., 2010

### Basic device security

Next we look at how to configure basic device security using **enable password** and **enable secret** commands.

#### enable password command

We can protect access to privileged EXEC mode with a password, so that if a user enters the enable command from the user EXEC mode they are asked for the password. This can be done with the command **enable password** in global configuration mode.

To know what enable password command options are available, we type the enable password command followed by a question mark:

<figure><img src="https://itnetworkingskills.wordpress.com/wp-content/uploads/2024/05/39b75-enable-password-command-8.webp?w=1201" alt="enable-password-command" height="450" width="1201"><figcaption><p>Image courtesy of Jeremy’s IT Lab (Free CCNA | Intro to the CLI | Day 4)</p></figcaption></figure>

We get three possible options for password to enter in the command. We are going to use the middle option – the unencrypted cleartext password. “LINE” means you type a line which will become the password.

A closer look at the **enable password** command syntax (with configuration examples): [enable password – Command Reference (cisco.com)](https://www.cisco.com/E-Learning/bulk/public/tac/cim/cib/using_cisco_ios_software/cmdrefs/enable_password.htm)

We will type CCNA all capitals as the password. Passwords are case sensitive. We typed the question mark to know what command options exist. \<cr> means there are no other options. The only option is to press enter. We press enter to set the password. And the password is set.

To return to privileged EXEC mode, type exit:

Router(config)#exit&#x20;

Router#

From privileged EXEC mode, another exit command will log us out and back to the starting screen. Then if we press return, we are back in user mode. Now if we enter the enable command to enter privileged EXEC mode, we are asked for a password.

Router>enable

Password:&#x20;

Router#

We enter CCNA though it does not display for security reasons, but it is accepted and we are (back) in privileged EXEC mode.

If you enter the wrong password three times you will be denied access for having bad secrets:

Router>enable

Password:

Password:

Password:

% Bad secrets

\#**exit** takes you to the previous CLI command mode: e.g., from config-line to config (global configuration mode); from global configuration mode to privileged EXEC mode; from privileged EXEC mode back to the starting screen.

\#**end** takes you to privileged EXEC mode (e.g., from config-line). You can end your configuration session by using the Ctrl-Z key combination, using the end command, or using the Ctrl-C key combination. Cisco says the end command is the recommended way to indicate to the system that you are done with the current configuration session.

**To recap–**

<figure><img src="https://itnetworkingskills.wordpress.com/wp-content/uploads/2024/05/34c22-configure-terminal-command-9.webp?w=1201" alt="configure-terminal-command" height="506" width="1201"><figcaption><p>Image courtesy of Jeremy’s IT Lab (Free CCNA | Intro to the CLI | Day 4)</p></figcaption></figure>

* We used the enable command to enter privileged EXEC mode from user mode.
* From privileged EXEC mode we used configure terminal to enter global configuration mode.
* In global configuration mode, we used the command enable password CCNA to protect privileged EXEC mode with a password.
* Then we typed exit to return to privileged EXEC mode.
* And exit again to return to user EXEC mode.
* We typed enable again and entered the password CCNA and we were brought back to privileged EXEC mode.

#### show running-config and show startup-config commands

We have confirmed the function of the password, but let’s check the configuration file.

There are two separate configuration files kept on a Cisco device at once:

* **running-config** – the current active configuration file. As you enter commands in the CLI, you edit the active configuration.&#x20;
* **startup-config** – the configuration file that will be loaded upon restarting the device.&#x20;

Use the **show running-config** command in privileged EXEC mode to view the running configuration file. The IOS CLI will return several results among them the command we entered, i.e., enable password CCNA.

<figure><img src="https://itnetworkingskills.wordpress.com/wp-content/uploads/2024/05/80729-show-running-config.webp?w=1201" alt="show-running-config" height="561" width="1201"><figcaption><p>show running-config output (Packet Tracer)</p></figcaption></figure>

Use the **show startup-config** command in privileged EXEC mode to view the startup configuration file.

<figure><img src="https://itnetworkingskills.wordpress.com/wp-content/uploads/2024/05/24d53-show-startup-config.webp?w=1201" alt="show-startup-config" height="561" width="1201"><figcaption><p>show startup-config output (Packet Tracer)</p></figcaption></figure>

Note, if you did not yet save the running configuration you will get a response that startup config is not present.

#### Saving the configuration

Cisco IOS software is typically stored in disk/flash memory on Cisco routers and switches. The running configuration is stored in RAM (Random Access Memory). The startup configuration in Cisco devices is typically stored in NVRAM (Non-Volatile RAM).

There are three commands you can use from privileged EXEC mode to save the running configuration to make it the startup configuration.

<figure><img src="https://itnetworkingskills.wordpress.com/wp-content/uploads/2024/05/d3a77-saving-router-configuration-10.webp?w=1201" alt="saving-router-configuration" height="590" width="1201"><figcaption><p>Image courtesy of Jeremy’s IT Lab (Free CCNA | Intro to the CLI | Day 4)</p></figcaption></figure>

Now if we use the show startup-config command, the IOS CLI will display the same configuration as the show running-config command.

The CLI output of show running-config displays the enable password “CCNA” in plain text. This is a security risk. An unauthorized person may be able to use this knowledge to enter privileged EXEC mode and then global configuration mode and change the configuration of the router.

#### service password-encryption command

So how to level up the security? With the **service password-encryption** command in global configuration mode.

Router#conf t

Router(config)#**service password-encryption**

The service password-encryption command will encrypt passwords. If we run the command and enter the show running-config command again, we will see that “enable password CCNA” has become “enable password 7 08026F6028”. The 7 denotes the type of encryption applied to the password, a Cisco proprietary encryption algorithm.

<figure><img src="https://itnetworkingskills.wordpress.com/wp-content/uploads/2024/05/14295-service-password-encryption-11.webp?w=945" alt="service password-encryption" height="675" width="945"><figcaption><p>Image courtesy of Jeremy’s IT Lab (Free CCNA | Intro to the CLI | Day 4)</p></figcaption></figure>

The service password-encryption command is more secure than naught, but it is not especially secure and can be cracked using an online Cisco type 7 password cracker.

#### enable secret command

There is a more secure enable password for Cisco devices with stronger encryption, a method called **enable secret** command.

Router(config)#enable secret Cisco (here the password used is “Cisco”)

Then we can review the running configuration again, but we can do this from within global configuration mode.

Router(config)#do sh run (i.e., do show running-config)

Using “do” allows us to execute privileged EXEC mode commands like show running-config in other configuration levels.&#x20;

<figure><img src="https://itnetworkingskills.wordpress.com/wp-content/uploads/2024/05/91cae-enable-secret-command-12.webp?w=974" alt="enable-secret-command" height="676" width="974"><figcaption><p>Image courtesy of Jeremy’s IT Lab (Free CCNA | Intro to the CLI | Day 4)</p></figcaption></figure>

You can see the enable secret in the running configuration. The number 5 indicates MD5 type encryption which is much more secure than what we get with the service password-encryption command. The enable password command remains and is not replaced. If both commands (enable password and enable secret) are configured, the enable password will be ignored.&#x20;

The service password-encryption command has no effect on the enable secret command. The enable secret command is always encrypted whether or not you entered the service password-encryption command.&#x20;

So you should always use the enable secret and not the enable password, as it is always more secure.

Dive deeper into Cisco IOS user security configuration: [Configuring Security with Passwords, Privileges, and Logins (cisco.com)](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/sec_usr_cfg/configuration/15-sy/sec-usr-cfg-15-sy-book/sec-cfg-sec-4cli.html)

Jump to “Cisco IOS CLI Modes” (under Information About Configuring Security with Passwords, Privileges, and Logins) and to “Protecting Access to Privileged EXEC Mode” (under How to Configure Security with Passwords, Privileges, and Logins).

The section “Protecting Access to User EXEC Mode” covers topics (password-protected access to the vty line for remote access and to the console line for local access) addressed in the lesson [How to configure SSH on Cisco devices](https://itnetworkingskills.wordpress.com/2023/04/12/how-configure-ssh-cisco-devices/).

The following Cisco reference explains the command syntax of the **enable password** and **enable secret** commands (with configuration examples): [Cisco IOS Security Command Reference: Commands D to L](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/security/d1/sec-d1-cr-book/sec-cr-e1.html#wp3884449514)

Use context sensitive help (the question mark) to know what configuration options are available to you for the IOS version/device model you are using. For example,

Router(config)#enable secret ?

The **enable algorithm-type** command can be used to set the algorithm type used to hash a user password configured using the **enable secret** command. For example, the following command configures an enable secret and secures it with type 9 hashing (scrypt):

**enable algorithm-type scrypt secret** _password_&#x20;

### Canceling commands

How to cancel a command:&#x20;

Router(config)#**no service password-encryption**

Then verify:

Router(config)#**do show running-config**

Thus future passwords will no longer be encrypted. But passwords already encrypted will not be decrypted by disabling password-encryption. New passwords however will be in clear text.

### Command review

Router> \
→user EXEC mode

Router# \
→privileged EXEC mode

Router(config)# \
→global configuration mode

Router>**enable**\
→to enter privileged EXEC mode

Router#**configure terminal** \
→to enter global configuration mode

Router(config)#**enable password** _password_ \
→to configure a password to protect privileged EXEC mode

Router(config)#**service password-encryption** \
→to encrypt the enable password (and other passwords)

Router(config)#**enable secret** _password_\
→to configure a more secure enable password&#x20;

Router(config)#**do** _privileged-exec-level-command_\
→to execute a privileged EXEC level command from global configuration mode

Router(config)#**no** _command_\
→to remove a previously configured command

Router#**show running-config**\
→to display the current active configuration file

Router#**show startup-config**\
→to display the saved configuration file which will be loaded if the device is restarted

Router#**write** \
→to save the current running configuration and make it the startup configuration

Router#**write memory**\
→to save the current running configuration and make it the startup configuration

Router#**copy running-config startup-config**\
→to save the current running configuration and make it the startup configuration

### Key learnings

* The Cisco IOS CLI is the text-based command-line interface used to configure, manage, and troubleshoot Cisco networking devices.
* Initial access to a device for configuration is typically achieved by connecting a computer to the console port using a rollover cable.
* A Terminal Emulator program like PuTTY is required on the computer to establish the console connection and interact with the CLI.
* The CLI operates in distinct command modes, each providing a different level of access and functionality. The two primary modes are:
  * User EXEC Mode: Limited to basic monitoring commands (denoted by the `>` prompt).
  * Privileged EXEC Mode: Provides full access to view and manage all device functions (denoted by the `#` prompt).
* Global Configuration Mode is entered from Privileged EXEC mode and is where changes are made to the device's running configuration.
* The Cisco IOS CLI supports numerous shortcuts (like `Tab` for auto-complete and `?` for context-sensitive help) to improve efficiency and reduce errors.
* Implementing basic device security begins with setting passwords to control access to the device's modes.
* The `enable password` command sets a password to enter Privileged EXEC mode, but it is stored in plain text, making it insecure.
* The `enable secret` command is the secure alternative, as it encrypts the Privileged EXEC password using a strong cryptographic hash.
* The `service password-encryption` command provides a weaker encryption for other plaintext passwords in the configuration file.
* The `show running-config` command displays the current, active configuration in RAM.
* The `show startup-config` command displays the saved configuration stored in NVRAM, which is loaded on device boot.
* Configuration changes are temporary until they are permanently saved from RAM to NVRAM using the `copy running-config startup-config` command.
* Commands can be cancelled using the `no` keyword or interrupted using key combinations like `Ctrl-C`.

### Packet Tracer lab (basic device security)

[**Get the lab file (.pkt) from Google Drive (Jeremy McDowell's Free CCNA Online Course)**](https://drive.google.com/drive/folders/1PwK_jWqfUtOjV7gHt8ODutq9QA5cxCgi)**: Day 04 Lab - Basic Device Security.pkt**

The lab tasks involve doing some configurations on a router and a switch.

_1. Set the appropriate host names for each device, R1 and SW1._

To do so use the **hostname** command in global configuration mode.

First, access the device’s CLI (by clicking on the device icon in Packet Tracer and then selecting CLI).

Then enter privileged EXEC mode via the command Router>en (enable).

Then enter global configuration mode via the **configure terminal** command.

Router#conf t (configure terminal)

Router(config)#

Now execute the **hostname** command.

Router(config)#hostname R1&#x20;

R1(config)#&#x20;

The host name has changed to R1.

_2. Configure an unencrypted enable password of ‘CCNA’ on both devices_.

From global configuration mode enter the command: R1(config)#enable password CCNA

_3. Exit back to user EXEC mode and test the password_.

Exit twice back to user mode to check if the command was accepted.

R1(config)#exit

R1#exit

Now if we enter the enable command from user mode to enter enable mode (privileged EXEC mode), we are asked for a password.

R1>enable

Password:

R#

_4. View the password in the running configuration_.

Use the show running-config command in privileged EXEC mode to view the running configuration file.

R1#show running-config

_5. Ensure that the current password, and all future passwords, are encrypted_.

Run the service password-encryption command in global configuration mode.

R1#conf t

R1(config)#service password-encryption

_6. View the password in the running configuration_.

From global configuration mode, run the command:

R1(config)#do sh run

Now we see that “enable password CCNA” has become “enable password 7 08026F6028”.

_7. Configure a more secure, encrypted enable password of ‘Cisco’ on both devices_.

From global configuration mode:

R1(config)#enable secret Cisco&#x20;

_8. Exit back to user EXEC mode and then return to privileged EXEC mode. Which password do you have to use?_

Cisco.

_9. View the passwords in the running configuration._

What encryption type number is used for the encrypted ‘enable password’? 7

What encryption type number is used for the encrypted ‘enable secret’? 5

_10. Save the running configuration to the startup configuration_.

Run command:&#x20;

R1(config)#do write

Use R1(config)#do show startup-config to view the startup configuration file.

Follow the same procedures to configure the switch.

### References

[Free CCNA | Intro to the CLI | Day 4 | CCNA 200-301 Complete Course](https://www.youtube.com/watch?v=IYbtai7Nu2g\&list=PLxbwE86jKRgMpuZuLBivzlM8s2Dk5lXBQ\&index=8)

[Free CCNA | Basic Device Security | Day 4 Lab | CCNA 200-301 Complete Course](https://www.youtube.com/watch?v=SDocmq1c05s\&list=PLxbwE86jKRgMpuZuLBivzlM8s2Dk5lXBQ\&index=9)

[cisco.com. (n.d.). Cisco IOS Master Command List, All Releases](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/mcl/allreleasemcl/all-book.html)

[Cisco. (April 2010). Cisco IOS Configuration Fundamentals Command Reference](https://www.cisco.com/c/en/us/td/docs/ios/fundamentals/command/reference/cf_book.pdf)

[Destiny Erhabor. (Oct. 18, 2022). Linux Command Line Tutorial – How to Use Common Terminal Commands (freecodecamp.org)](https://www.freecodecamp.org/news/linux-command-line-tutorial/)

Odom, W. (2020). CCNA 200-301 Official Cert Guide, Volume 1. Cisco Press.

Odom, W. (2020). CCNA 200-301 Official Cert Guide, Volume 2. Cisco Press.

[Sean Douglas. (Nov 17, 2022). Top 5 Network Admin Cisco Commands Cheat Sheet (pluralsight)](https://www.pluralsight.com/blog/it-ops/cisco-commands-for-network-admin)
