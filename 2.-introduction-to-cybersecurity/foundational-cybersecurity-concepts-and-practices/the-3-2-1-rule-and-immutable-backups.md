# The 3-2-1 Rule and immutable backups

### The 3-2-1 Backup Rule: The Gold Standard of Data Protection

The 3-2-1 rule is a simple, time-tested strategy for ensuring your data can be recovered from almost any disaster. It's a foundational principle used by IT professionals and home users alike.

Here’s what each number means:

* **3: Keep at least THREE copies of your data.**
  * This includes your **primary (live) data** and **at least two backup copies**.
  * Why? If you only have your original and one backup, you have a single point of failure. If something happens to that one backup, you're out of luck. A second backup drastically reduces your risk.
* **2: Store your backups on TWO different types of media.**
  * "Media" refers to the physical device or storage technology you use.
  * Examples: An external hard drive (HDD/SSD), a NAS (Network-Attached Storage), cloud storage, or even magnetic tape (for enterprises).
  * Why? This protects against media-specific failures. If all your backups are on the same type of hard drive, a flaw in that model or a virus that targets that system could wipe them all out. Diversifying your media mitigates this risk.
* **1: Keep at least ONE backup copy OFFSITE.**
  * This means a copy that is physically separated from your primary location.
  * The most common modern solution is **cloud storage** (e.g., Backblaze, AWS, Azure). Historically, this meant taking tapes or drives to a safe deposit box or another office.
  * Why? This protects against local and regional disasters like fire, flood, theft, or a major power surge that could destroy all the equipment in your home or office.

**In a nutshell:** The 3-2-1 rule ensures you have multiple copies, on different devices, in different locations, making data loss highly unlikely.

***

### Immutable Backups: The "Write-Once, Read-Many" Vault

An immutable backup is a backup that **cannot be altered or deleted** by anyone for a predetermined period of time—not even by a system administrator or the backup software itself.

* **Immutability** means "unchangeable." Once the backup is written, it is locked down.
* Think of it like a legal document written in permanent ink and stored in a tamper-evident safe. You can look at it (read it), but you cannot change it or throw it away until the retention period expires.

**How is this achieved?**\
Modern backup solutions use features of storage systems (like Amazon S3 Object Lock or Azure Blob Storage Immutability Policies) or leverage Linux-based file system attributes to place a legal "hold" or compliance lock on the backup files.

**Why are Immutable Backups So Critical? The #1 Threat: Ransomware**

The 3-2-1 rule is excellent, but it has a vulnerability: **human error and malicious software.**

1. **Ransomware Evolution:** Modern ransomware doesn't just encrypt your live data. It actively seeks out your connected backups (external drives, NAS) to encrypt or delete them _first_. This is how they force you to pay the ransom.
2. **The Attack:** If a hacker gains access to your system, they could potentially gain access to your backup software and delete all your offsite cloud backups, completely defeating your 3-2-1 strategy.

**This is where immutability saves the day.**\
Even if a hacker has your admin credentials, they **cannot delete or encrypt an immutable backup.** The storage system itself will reject any command to alter the file until the immutability period (e.g., 7, 30, or 90 days) is over. This guarantees you have a "last-known-good" copy to recover from, making ransomware attacks ineffective.

**Other benefits of immutability:**

* **Accidental Deletion:** Prevents a well-meaning admin from accidentally deleting the wrong backup.
* **Compliance:** Meets strict regulatory requirements for data retention (e.g., SEC, FINRA, HIPAA) by proving data has not been tampered with.

***

### Putting It All Together: The Ultimate Modern Strategy

A robust, modern data protection strategy combines both concepts:

**The 3-2-1-1-0 Rule (An Enhanced Standard)**

This builds on the 3-2-1 rule by adding:

* **1: Keep at least one backup copy IMMUTABLE.** (This is the crucial addition).
* **0: Verify your backups to ensure you have ZERO errors.** (Automated recovery verification).

**Example Scenario for a Business:**

1. **Primary Data:** Files on the company server.
2. **Backup Copy 1 (On-site, different media):** A backup job to a dedicated NAS device.
3. **Backup Copy 2 (Off-site, immutable):** A backup job to a cloud provider like Wasabi or Backblaze B2, with Object Lock (immutability) enabled for 30 days.
4. **Backup Copy 3 (Optional, air-gapped):** A periodic backup to an external hard drive that is physically disconnected and stored in a safe.

If ransomware infects the network, it may encrypt the primary server and the on-site NAS backup. However, the immutable cloud backup remains untouched and un-deletable. The company can then recover all its data from that cloud copy without paying the ransom.

#### Summary

| Concept              | Purpose                                                       | Key Benefit                                                               |
| -------------------- | ------------------------------------------------------------- | ------------------------------------------------------------------------- |
| **3-2-1 Rule**       | To ensure redundancy and geographic separation of backups.    | Protects against hardware failure, local disaster, and accidental loss.   |
| **Immutable Backup** | To make backups tamper-proof and un-deletable for a set time. | Protects against ransomware, malicious insiders, and accidental deletion. |

For any critical data, you should **not** choose between the 3-2-1 rule and immutability. You should use **both** to create a defense-in-depth strategy that is resilient against both random accidents and targeted malicious attacks.
