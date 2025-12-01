---
hidden: true
---

# Buffer overflows deep dive

#### **How Buffer Overflows Lead to Arbitrary Code Execution**

When excess data overflows into adjacent memory spaces, attackers can **hijack a program’s execution flow** and run malicious code. Here’s a step-by-step breakdown of how this happens:

### **1. Understanding Key Memory Structures**

#### **Stack Layout in Memory**

When a function is called, the program allocates a **stack frame** containing:

* **Local variables** (e.g., buffers, integers).
* **Return address** (where the CPU should go after the function finishes).
* **Saved base pointer** (for restoring the stack after the function ends).

text

```
[ High Memory Address ]
----------------------
|   Function Args    |
----------------------
|   Return Address   | ← What attackers overwrite  
----------------------
|   Saved Base Ptr   |
----------------------
|   Local Variables  | ← Buffer overflow starts here  
----------------------
[ Low Memory Address ]
```

### **2. How Attackers Exploit the Overflow**

#### **Step 1: Overflowing the Buffer**

* A vulnerable program (e.g., a network service) reads input into a fixed-size buffer **without bounds checking**.
*   Example:

    c

    ```
    void vulnerable() {
        char buffer[10];  // Only holds 10 bytes
        gets(buffer);     // No length check → Overflow possible
    }
    ```
* If an attacker sends **20 bytes**, the extra 10 bytes spill into adjacent memory.

#### **Step 2: Overwriting the Return Address**

* The **return address** (stored just after local variables) tells the CPU where to resume execution after the function ends.
* By overflowing the buffer, an attacker can **replace the return address** with a **malicious address**.

text

```
Before Overflow:
----------------------
|   Return Address   | → Points to `main()`  
----------------------
|   buffer[10]       | → "AAAAAAAAAA"  
----------------------

After Overflow (with 20 bytes):
----------------------
|   Return Address   | → Now points to attacker’s shellcode  
----------------------
|   buffer[10]       | → "AAAAAAAAAABBBBBBBBBB"  
----------------------
```

#### **Step 3: Redirecting Execution to Malicious Code**

* The attacker ensures the **overwritten return address** points to:
  * **Shellcode** (malicious machine code) embedded in the buffer.
  * **Existing code** (via **Return-Oriented Programming (ROP)** if defenses like DEP are enabled.
* When the function returns, the CPU jumps to the attacker’s code instead of the legitimate program flow.

#### **Step 4: Executing Arbitrary Code**

* The **shellcode** (often written in assembly) performs actions like:
  * Spawning a shell (`/bin/sh` or `cmd.exe`).
  * Downloading and running malware.
  * Escalating privileges (e.g., gaining **root/admin access**).

### **3. Real-World Exploitation Example**

#### **Scenario: Exploiting a Network Service**

1. **Attacker sends a malicious payload** (e.g., 500 bytes to a 100-byte buffer).
2. **Payload structure:**
   * First 100 bytes: Fill the buffer (`"A" * 100`).
   * Next 4 bytes: Overwrite return address (e.g., `0xdeadbeef`).
   * Remaining bytes: **Shellcode** (e.g., machine code to open a shell).
3. **When the function returns:**
   * The CPU jumps to `0xdeadbeef`, executing the shellcode.
   * The attacker gains **remote control** over the system.

### **4. Modern Protections & How Attackers Bypass Them**

| Protection                                    | How It Works                                         | How Attackers Bypass It                               |
| --------------------------------------------- | ---------------------------------------------------- | ----------------------------------------------------- |
| **DEP (Data Execution Prevention)**           | Blocks code execution in stack/heap.                 | **ROP**: Chaining existing code snippets ("gadgets"). |
| **ASLR (Address Space Layout Randomization)** | Randomizes memory addresses.                         | **Memory leaks** to find base addresses.              |
| **Stack Canaries**                            | Detects overflow before return address is corrupted. | **Brute-forcing** or leaking the canary.              |

### **5. Why Is This So Dangerous?**

* **Remote Code Execution (RCE):** Attackers can run any command on the victim’s machine.
* **Privilege Escalation:** Exploiting a service running as `root` grants full system control.
* **Persistence:** Malware can install backdoors for long-term access.

#### **Conclusion**

By overflowing a buffer and overwriting the return address, attackers **hijack a program’s execution** and force it to run malicious code. Despite modern defenses (DEP, ASLR), advanced techniques like **ROP** keep buffer overflow exploits relevant in cybersecurity.
