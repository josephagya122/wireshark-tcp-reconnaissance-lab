# Lab Analysis: TCP Port Reconnaissance & Network Stack Response Triage

## 1. Overview & Objective
This lab capture demonstrates foundational network reconnaissance techniques and local TCP stack behavior. The objective was to capture, filter, and analyze half-open connection attempts (`SYN` scans) and evaluate the target host's response handling using Wireshark on a local loopback interface.

---

## 2. Packet Analysis Breakdown

### Phase 1: TCP SYN Reconnaissance (Half-Open Probing)
* **Wireshark Filter Used:** `tcp.flags.syn == 1 && tcp.flags.ack == 0`[cite: 12]
* **Observation:** The capture logs multiple outgoing connection requests originating from source ports `51095` and `51096` targeting sequential destination ports `80` and `81` on `127.0.0.1`[cite: 12].
* **Packet Characteristics:** Each packet displays the `[SYN]` flag set with `Seq=0`, `Win=65535`, and zero payload length (`Len=0`)[cite: 12]. This matches the classic fingerprint of an active port scan attempting to discover listening services without completing the full 3-way handshake.

### Phase 2: Host Response & Port Status Determination
* **Wireshark Filter Used:** `tcp.flags.reset == 1`[cite: 13]
* **Observation:** In response to the incoming `SYN` packets, the local network stack immediately replies with `[RST, ACK]` (Reset-Acknowledgement) packets originating from ports `80` and `81` back to the source ephemeral ports[cite: 13].
* **Technical Meaning:** Because no active daemon or web service was actively bound to listen on ports `80` or `81` during this specific probe sequence, the operating system's TCP stack correctly rejects the connection, signaling that the port is closed.

---

## 3. SOC Analyst Relevance & Triage Value

From a Security Operations Center (SOC) perspective, identifying these packet patterns is critical for early threat detection:
* **Attack Technique Identification:** This traffic signature maps directly to **MITRE ATT&CK T1046 (Network Service Discovery)**, where threat actors or automated worms sweep ports to map internal or external attack surfaces.
* **SIEM / IDS Detection Engineering:** Security analysts use these exact flag combinations (`SYN` without `ACK` followed by high-frequency RST responses) to write signature rules in Snort, Suricata, or detection queries in Splunk to flag internal host scanning behavior.
* **Baseline Triage:** Understanding loopback behavior versus external interface telemetry prevents false-positive escalation during local software debugging.

---

## 4. GitHub Sanitization Guidance: Do You Need to Block IPs?

> [!NOTE]
> **No IP or port redaction is required for this specific dataset.**

* **Why?** The captured traffic utilizes `127.0.0.1` (IPv4 Loopback)[cite: 12, 13]. Loopback addresses are standard across all operating systems and contain zero sensitive internal network architecture, public IP assets, or confidential user data. 
* **General GitHub Best Practice:** Always ensure that when publishing captures from production or corporate networks, you sanitize public IP addresses, internal RFC 1918 subnets (`10.x.x.x`, `192.168.x.x`), hostnames, and MAC addresses. For local lab portfolios using `127.0.0.1`, your data is 100% safe to share publicly.
