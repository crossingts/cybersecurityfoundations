---
hidden: true
---

# Repeaters vs hubs vs bridges vs switches

### Hubs vs. Switches: Key Differences

Hubs and switches are both networking devices that connect multiple devices in a LAN, but they operate very differently at the **data link layer (Layer 2)** of the OSI model.

**Key Technical Differences**

| Feature                  | Hub (Dumb Device)                                                         | Switch (Intelligent Device)                                            |
| ------------------------ | ------------------------------------------------------------------------- | ---------------------------------------------------------------------- |
| **Operation**            | Operates at **Layer 1 (Physical)**                                        | Operates at **Layer 2 (Data Link)**                                    |
| **Traffic Handling**     | Broadcasts all incoming data to **all ports** (flooding)                  | Forwards traffic **only to the destination port** using MAC addresses  |
| **Collision Domain**     | **Single collision domain** (all devices share bandwidth)                 | **Per-port collision domain** (isolates traffic, full-duplex possible) |
| **Bandwidth Usage**      | **Shared bandwidth** (e.g., 10Mbps hub divides bandwidth among all ports) | **Dedicated bandwidth per port** (e.g., 100Mbps per port)              |
| **Performance**          | **Slower** (due to collisions and unnecessary traffic)                    | **Faster** (efficient forwarding, no unnecessary broadcasts)           |
| **MAC Address Learning** | **No** (does not track devices)                                           | **Yes** (maintains a MAC address table for forwarding decisions)       |
| **Security**             | **Less secure** (all devices see all traffic)                             | **More secure** (isolates traffic between ports)                       |
| **Use Case**             | **Obsolete** (used in early networks)                                     | **Modern standard** (used in all current networks)                     |

#### **What Can Switches Do That Hubs Cannot?**

1. **MAC Address Learning & Forwarding** – Switches maintain a **MAC address table** to send frames only to the correct port, while hubs blindly broadcast.
2. **Full-Duplex Communication** – Switches allow simultaneous two-way communication (send & receive at the same time), whereas hubs operate in **half-duplex** (collisions occur).
3. **Collision Avoidance** – Switches eliminate collisions via **per-port segmentation**, unlike hubs, which suffer from **CSMA/CD (Carrier Sense Multiple Access with Collision Detection)**.
4. **VLAN Support** – Switches can segment networks into **VLANs** (Virtual LANs), while hubs cannot.
5. **Traffic Optimization** – Switches reduce unnecessary traffic, improving efficiency, whereas hubs waste bandwidth.

#### **Conclusion**

Switches are **vastly superior** to hubs in speed, efficiency, and security. Hubs are **obsolete** in modern networks due to their **broadcast nature** and **shared bandwidth limitations**.

### Hubs vs. Bridges vs. Switches: Key Differences

Here’s an expanded comparison table that includes **bridges**, which sit between hubs and switches in terms of functionality.

| Feature              | **Hub (Layer 1)**                                       | **Bridge (Layer 2)**                                | **Switch (Layer 2, Advanced)**                           |
| -------------------- | ------------------------------------------------------- | --------------------------------------------------- | -------------------------------------------------------- |
| **OSI Layer**        | Physical (Layer 1)                                      | Data Link (Layer 2)                                 | Data Link (Layer 2)                                      |
| **Traffic Handling** | Broadcasts to **all ports** (flooding)                  | Forwards based on **MAC addresses** (filtering)     | Forwards based on **MAC table**, per-port forwarding     |
| **Collision Domain** | **Single collision domain** (all ports share bandwidth) | **Divides collision domains** (2 or more segments)  | **Per-port collision domain** (full-duplex possible)     |
| **Bandwidth Usage**  | **Shared** (e.g., 10Mbps divided among all ports)       | **Semi-dedicated** (reduces unnecessary traffic)    | **Dedicated per port** (e.g., 100Mbps per port)          |
| **MAC Learning**     | **No** (dumb device)                                    | **Yes** (maintains a simple MAC table)              | **Yes** (maintains a full MAC table for all ports)       |
| **Ports**            | Typically **4–12 ports**                                | Usually **2 ports** (connects two network segments) | **4–48+ ports** (scalable)                               |
| **Performance**      | **Slow** (collisions, broadcasts)                       | **Moderate** (reduces collisions but limited ports) | **Fast** (no collisions, optimized forwarding)           |
| **Security**         | **None** (all traffic visible to all devices)           | **Basic filtering** (isolates segments)             | **Better isolation** (per-port forwarding, VLAN support) |
| **Use Case**         | **Obsolete** (historical use)                           | **Legacy segmentation** (older networks)            | **Modern standard** (all Ethernet networks)              |

#### **Key Takeaways:**

* **Hubs** = **Dumb repeaters** (no intelligence, all traffic broadcasted).
* **Bridges** = **Basic traffic filters** (split collision domains, simple MAC learning).
* **Switches** = **Advanced bridges** (full MAC tables, dedicated bandwidth, VLANs, high port density).

Bridges were an early improvement over hubs but were later replaced by **switches**, which offer **more ports, faster forwarding, and better scalability**.

### Repeaters vs. Hubs vs. Bridges vs. Switches: Key Differences

| Feature              | **Repeater (L1)**                                | **Hub (L1)**                                            | **Bridge (L2)**                                     | **Switch (L2, Advanced)**                                |
| -------------------- | ------------------------------------------------ | ------------------------------------------------------- | --------------------------------------------------- | -------------------------------------------------------- |
| **OSI Layer**        | Physical (L1)                                    | Physical (L1)                                           | Data Link (L2)                                      | Data Link (L2)                                           |
| **Function**         | **Regenerates signals** (extends cable reach)    | **Multi-port repeater** (broadcasts to all ports)       | **Connects two network segments** (filters by MAC)  | **Multi-port bridge** (intelligent forwarding)           |
| **Traffic Handling** | **No filtering** (boosts signal only)            | **Broadcasts to all ports** (no intelligence)           | **Forwards based on MAC table (2 ports only)**      | **Forwards based on full MAC table (per-port)**          |
| **Collision Domain** | **Extends collision domain** (no isolation)      | **Single collision domain** (all ports share bandwidth) | **Splits collision domains** (two segments)         | **Per-port collision domain** (full-duplex possible)     |
| **Bandwidth Usage**  | **No improvement** (just extends signal)         | **Shared** (e.g., 10Mbps divided among all ports)       | **Reduces unnecessary traffic** (basic filtering)   | **Dedicated per port** (e.g., 100Mbps per port)          |
| **MAC Learning**     | **No** (dumb signal booster)                     | **No** (dumb device)                                    | **Yes** (basic MAC table for two ports)             | **Yes** (full MAC table for all ports)                   |
| **Ports**            | **2 ports** (in/out)                             | **4–12 ports** (multi-port repeater)                    | **2 ports** (links two hubs/segments)               | **4–48+ ports** (scalable)                               |
| **Performance**      | **No speed improvement** (just extends range)    | **Slow** (collisions, broadcasts)                       | **Moderate** (reduces collisions but limited ports) | **Fast** (no collisions, optimized forwarding)           |
| **Security**         | **None** (raw signal passthrough)                | **None** (all traffic visible to all devices)           | **Basic filtering** (isolates segments)             | **Better isolation** (per-port forwarding, VLAN support) |
| **Use Case**         | **Extending cable runs** (e.g., Ethernet, fiber) | **Obsolete** (historical use)                           | **Legacy segmentation** (older networks)            | **Modern standard** (all Ethernet networks)              |

#### **Key Takeaways**

1. **Repeaters** extend signals but **do nothing for traffic efficiency**.
2. **Hubs** are just **multi-port repeaters**—they flood all traffic, creating congestion.
3. **Bridges** improve on hubs by **splitting collision domains** but are limited to 2 ports.
4. **Switches** are **scalable, high-performance bridges** with per-port forwarding.

***

Repeaters regenerate signals, allowing devices to communicate across great distances by extending the physical reach of a network (e.g., allowing Ethernet to go beyond the standard 100m limit).

Connecting hosts directly to each other does not scale. Hubs connect multiple devices together, solving the scaling problem. Hubs are multi-port repeaters. A hub facilitates scaling communication between additional hosts. A hub will duplicate a packet and send it out to all ports on the hub. Everybody receives everybody else’s data. A bridge sits in between hub-connected hosts, connecting two hubs. Bridges only have two ports – each facing a different hub. Bridges learn which hosts are on which side of the bridge, which allows bridges to contain communication/channel packets to their relative networks. Bridges allow packets to traverse to the other side of the bridge when needed.

#### **Rewritten Explanation for Accuracy & Clarity**

**Repeaters (Signal Regeneration)**

* **Function:** Regenerate and retransmit signals to extend the physical reach of a network (e.g., allowing Ethernet to go beyond the standard 100m limit).
* **Limitation:** Do **not** filter or interpret data—just amplify/rebuild the signal.
* **Example:** Used in long-distance cabling (e.g., fiber optic repeaters).

**Hubs (Multi-Port Repeaters)**

* **Function:** A **hub is essentially a multi-port repeater**—it connects multiple hosts in a single collision domain.
* **How it works:**
  * When a host sends a packet, the hub **duplicates it and floods it out all ports**.
  * **No MAC learning** → Every device sees all traffic (inefficient & insecure).
* **Problem:** Does **not scale well** due to collisions and wasted bandwidth.

**Bridges (Early Traffic Filtering)**

* **Function:** Connects **two separate hub-based segments** (only two ports).
* **How it works:**
  * Learns which MAC addresses are on each side.
  * **Filters traffic**—only forwards packets **if the destination is on the other segment**.
  * Reduces unnecessary broadcasts (improves performance vs. hubs).
* **Limitation:** Low port count (only 2 ports) → Replaced by switches.

**Switches (Advanced Bridges)**

* **Function:** A **multi-port bridge** with dedicated bandwidth per port.
* **Advantages over bridges/hubs:**
  * Maintains a **full MAC address table** for all ports.
  * **Forwards traffic only to the destination port** (no flooding unless unknown).
  * Supports **full-duplex** (no collisions) and **VLANs**.
