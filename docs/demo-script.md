# NetTrace 5-Minute Technical Demo Script

This script provides a structured walkthrough that a student or engineer can use to present NetTrace to an interviewer, lecturer, or engineering team.

---

## Part 1: Problem Statement & Value Proposition (0:00 - 1:00)

> "Wireshark is an exceptional packet inspection tool, but raw packet dumps often overwhelm junior engineers and investigators. When an outage occurs, teams struggle to quickly answer: *Which TCP handshakes failed? Which DNS queries timed out? Did any host sweep the subnet?*
>
> NetTrace is an offline packet troubleshooting toolkit. It takes raw `.pcap` or `.pcapng` files and translates them into understandable, evidence-backed diagnostics without hallucinating data or relying on black-box AI."

---

## Part 2: Baseline vs Incident Demonstration (1:00 - 2:30)

1. **Demonstrate Clean Baseline:**
   - Open NetTrace at `http://127.0.0.1:5173`.
   - Go to **Captures & Upload** and click **1-Click Load** on **Normal Baseline Traffic**.
   - Show the **Overview Dashboard**:
     > "Notice how the dashboard computes real protocol distributions from the 10 captured frames: clean DNS resolution for `example.local`, followed by a 3-way handshake to port 80, HTTP GET request, and graceful FIN/ACK teardown.
     > Because all exchanges succeeded, the Diagnostic Findings count is exactly zero. A key design principle of NetTrace is that benign traffic is never flagged as suspicious to make the UI look busy."

2. **Demonstrate Incident Capture:**
   - Go to **Captures & Upload** and click **1-Click Load** on **Incident Troubleshooting**.
   - Show the updated **Overview Dashboard**:
     > "Now we load an incident capture with 42 frames. The dashboard immediately surfaces 6 diagnostic findings spanning TCP, DNS, and traffic anomalies."

---

## Part 3: Deep Dive into Diagnostic Evidence (2:30 - 4:00)

1. **Inspect Findings & Packet Links:**
   - Navigate to **Findings & Diagnostics**.
   - Highlight the **Incomplete TCP Handshake**:
     > "Here is an Incomplete Handshake finding between `192.168.1.105` and `10.0.0.99:443`. Notice the clear separation of concerns:
     > 1. **Observed Fact:** The client sent a SYN at packet #1, but no SYN-ACK was received.
     > 2. **Possible Explanations:** Unreachable host, packet dropping firewall, or asymmetric capture.
     > 3. **Limitations:** We explicitly warn that an absent packet in a capture does not prove the server is dead—the capture might have ended prematurely."
   - Click the **#1 SYN** button:
     > "Clicking the evidence tag opens our Evidence Inspector, showing the exact frame timestamp, decoded IP TTL, and TCP sequence number."

2. **Inspect DNS Diagnostics:**
   - Show the **DNS NXDOMAIN** and **SERVFAIL** findings.
   - Jump to **DNS Analysis** page to demonstrate paired queries and responses with computed round-trip latencies.

3. **Inspect Scan Detection:**
   - Show the **Port-Scan Pattern**:
     > "Host `192.168.1.200` contacted 18 distinct ports on `10.0.0.50`. Our heuristic flagged this based on configurable thresholds. We document all probed ports and link directly to the supporting packet numbers."

---

## Part 4: Reports, Persistence & Verification (4:00 - 5:00)

1. **Report Export:**
   - Navigate to **Reports & Export**.
   - Click **Open in New Tab** on the **Interactive HTML Report** to showcase the self-contained report.
   - Click **Download PDF** to show the ReportLab multi-page executive summary.

2. **Closing:**
   - Conclude:
     > "NetTrace is built with FastAPI, Scapy, SQLite, React, and TypeScript. It has 100% passing backend and frontend test suites, runs completely offline on Windows and Linux, and never fabricates network statistics."
