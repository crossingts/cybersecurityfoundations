# Lab: Basic device security

### Packet Tracer lab: Basic device security

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
