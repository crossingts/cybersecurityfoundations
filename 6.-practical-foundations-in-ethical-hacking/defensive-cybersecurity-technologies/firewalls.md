# Firewalls

### Stateless vs stateful firewalls

**Stateless vs Stateful Firewalls Diagram**

```
Stateless Firewall:
  [Packet] → [Check Rules] → Allow/Drop

Stateful Firewall:
  [Packet] → [Check State Table] → [Update State] → Allow/Drop
          ↳ (e.g., "Is this a reply to an existing SSH session?")
```

Stateful and stateless firewalls serve different purposes in network security, each with its own advantages. Here’s a comparison highlighting the **advantages of stateful firewalls over stateless firewalls**:

**Advantages of Stateful Firewalls:**

Most modern firewalls (e.g., NGFW) are stateful by default due to their security advantages.

1. **Context-Aware Traffic Filtering**
   * Stateful firewalls track the **state** of active connections (e.g., TCP handshakes, UDP sessions), allowing them to make smarter decisions.
   * Example: Only allows inbound traffic if it’s part of an established outbound connection.
2. **Better Security Against Attacks**
   * Can detect and block malicious traffic that abuses protocol states (e.g., TCP SYN floods, session hijacking).
   * Prevents unauthorized traffic that doesn’t match an existing connection.
3. **Granular Control Over Sessions**
   * Can enforce policies based on connection state (e.g., allow only "established" or "related" traffic).
   * Supports dynamic rule adjustments (e.g., temporarily opening ports for FTP data connections).
4. **Protection Against Spoofing & DoS**
   * Recognizes abnormal traffic patterns (e.g., unexpected RST or FIN packets).
   * Can enforce rate limiting per connection.
5. **Supports Complex Protocols**
   * Handles protocols like FTP, SIP, and VoIP that use dynamic ports by tracking their control sessions.
6. **Logging & Monitoring**
   * Provides detailed logs of connection states, aiding in forensic analysis and troubleshooting.

**Why Stateful Filtering is Useful**

✅ **Simpler Rules**: No need to manually allow reply traffic.\
✅ **Security**: Blocks unsolicited/invalid packets (e.g., spoofed ACKs).\
✅ **Performance**: Faster than checking every packet against all rules.

**When Stateless Firewalls Are Better:**

Stateless firewalls (ACLs) are simpler and faster but lack intelligence. They are useful for:

* High-speed networks where performance is critical (e.g., backbone routers).
* Simple packet filtering based on static rules (e.g., IP/port blocking).
* Environments where connection tracking isn’t needed.


**Roots of Common Packet-Filtering Firewalls**

```
Linux Kernel:
  └─ Netfilter (Framework)
      ├─ iptables → firewalld/UFW (Frontends) (Legacy)
      └─ nftables (Modern Replacement)

BSD Kernel:
  └─ PF (OpenBSD) → Used in OPNsense/pfSense
  └─ ipfw (FreeBSD) → Legacy

Windows:
  └─ Windows Filtering Platform (WFP)
```

Windows Filtering Platform (WFP) is Microsoft’s built-in firewall (CLI: `netsh advfirewall`).

**Underlying Systems Summary Table**

| Firewall     | Underlying System | OS Family       | Notes                             |
| ------------ | ----------------- | --------------- | --------------------------------- |
| **iptables** | Netfilter (Linux) | Linux           | Legacy, replaced by nftables.     |
| **nftables** | Netfilter (Linux) | Linux           | Unifies IPv4/IPv6, better syntax. |
| **PF**       | BSD Kernel        | OpenBSD/FreeBSD | Powers OPNsense/pfSense.          |
| **ipfw**     | BSD Kernel        | FreeBSD/macOS   | Older, simpler than PF.           |
| **WFP**      | Windows Kernel    | Windows         | Native firewall for Windows.      |


### Web Application Firewalls (WAFs)

**WAF key characteristics:**

* Scope: Inspects payloads (e.g., "Block HTTP requests with SQLi").
* L7 Awareness: Understands HTTP, DNS, etc. (deep packet inspection)
* Performance Impact: High (parses full packets).

WAFs can be **host-based and network-based**, depending on deployment:

| Type                  | Example Tools                         | Deployment                                                      |
| --------------------- | ------------------------------------- | --------------------------------------------------------------- |
| **Host-Based WAF**    | ModSecurity (Apache/Nginx plugin)     | Runs on the web server (e.g., as a module).                     |
| **Network-Based WAF** | Cloudflare WAF, HAProxy + ModSecurity | Standalone appliance/cloud service (protects multiple servers). |

### Key takeaways

**Stateful Firewalls:** Open-source examples include iptables/nftables (Linux), PF (BSD), and OPNsense.
* **Use stateful firewalls** when you need **stronger security**, session awareness, and protection against modern threats.
* **Use stateless firewalls** for **raw speed** or when dealing with simple, static filtering.

**Firewall Roots:** Linux uses Netfilter (iptables/nftables), BSD uses PF/ipfw, Windows uses WFP.

**WAFs:** Can be host-based (ModSecurity) or network-based (Cloudflare WAF). Host WAF: Protects a single service (e.g., one NGINX instance). Network WAF: Protects all traffic before it reaches servers (e.g., a reverse proxy).

