# NetTrace User Guide

NetTrace empowers students, engineers, and technical investigators to analyze network packet captures and extract diagnostic insights.

---

## Quick Navigation

1. [Starting the Application](#1-starting-the-application)
2. [Uploading & Analyzing a Capture](#2-uploading--analyzing-a-capture)
3. [Exploring the Overview Dashboard](#3-exploring-the-overview-dashboard)
4. [Using the Packet Explorer](#4-using-the-packet-explorer)
5. [Investigating Conversations in Flow Explorer](#5-investigating-conversations-in-flow-explorer)
6. [Analyzing DNS Traffic](#6-analyzing-dns-traffic)
7. [Reviewing Diagnostic Findings & Evidence](#7-reviewing-diagnostic-findings--evidence)
8. [Exporting Reports](#8-exporting-reports)
9. [Adjusting Heuristic Settings](#9-adjusting-heuristic-settings)

---

## 1. Starting the Application

On Windows:
```powershell
.\scripts\start.ps1
```

On Linux / macOS:
```bash
./scripts/start.sh
```

Open your browser to:
- **Dashboard:** [http://127.0.0.1:5173](http://127.0.0.1:5173)
- **API Documentation:** [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

---

## 2. Uploading & Analyzing a Capture

1. Navigate to **Captures & Upload** in the left sidebar.
2. Drag and drop your `.pcap` or `.pcapng` file into the upload zone, or click to browse.
3. Alternatively, click **1-Click Load** on one of the pre-bundled lab samples:
   - **Normal Baseline Traffic:** Demonstrates a clean session with 0 findings.
   - **Incident Troubleshooting:** Demonstrates multi-symptom diagnostics (incomplete handshakes, resets, scans, DNS errors).
4. The backend streams the file, extracts layers, calculates flow metrics, and redirects you to the **Overview Dashboard**.

---

## 3. Exploring the Overview Dashboard

The Overview Dashboard surfaces:
- **Volume Metrics:** Analyzed packet count, total captured bytes, session duration.
- **Protocol Distribution Chart:** Proportion of TCP, UDP, DNS, HTTP, ICMP, and ARP frames.
- **Throughput Over Time:** Area chart showing packet intensity across the capture window.
- **Top Endpoints Table:** Communicating IP addresses ranked by transmitted volume.
- **Findings by Severity:** Distribution of Informational, Low, Medium, and High findings.

---

## 4. Using the Packet Explorer & Display-Filter Engine

1. Navigate to **Packet Explorer** (or press `Ctrl+K` from any page to use the Global Search bar).
2. **Display-Filter Toolbar:**
   - Enter Wireshark-style display filter expressions in the top `Filter:` bar with live syntax validation, autocomplete suggestions, **Saved Filters**, **Recent Filters**, and **Prev/Next** packet navigation.
   - Use **Quick-Filter Buttons** (`DNS`, `TCP`, `UDP`, `ICMP`, `HTTP`, `TLS`, `SYN`, `TCP Resets (RST)`) or open the **Filter Builder** if you prefer structured dropdowns and conversation (`Peer A <-> Peer B`) selectors.
   - Use the separate **Text Search** input to search summary/payload strings independently of the display filter.
   - Click any IP address, port, or protocol badge in the table (or any decoded field in the inspector) to add `==` or `!=` filter clauses with one click.
   - Select multiple packets using checkboxes (or export the active filter view) to download packet metadata as **CSV** or **JSON**.
3. **3-Pane Packet Inspector:**
   - Clicking any packet row opens the docked bottom 3-pane inspector:
     1. **Decoded Protocol-Layer Tree (Left):** Expandable layers (`Frame`, `Ethernet II`, `IPv4/IPv6`, `TCP/UDP/ICMP`, `DNS`, `HTTP`, `TLS`). Clicking a layer or field highlights its corresponding bytes in the hex viewer.
     2. **Synchronized Hexadecimal & ASCII Byte View (Center):** 16-byte rows with offset, hex, and printable ASCII columns, highlighting the selected layer/field byte range (`[byte_start, byte_end)`).
     3. **Packet Information & Evidence Links (Right):** Frame timing, TCP flag bit decoder, linked diagnostic findings, and 1-click links to **Flow Explorer** and **Communication Topology**.

### Display-Filter Grammar & Field Registry

NetTrace implements a safe, deterministic tokenizer and recursive-descent AST parser (`backend/app/services/display_filter.py` and `frontend/src/lib/displayFilter.ts`) — **never** `eval` or `exec`.

- **Logical Operators (in precedence order):**
  1. Parentheses: `( ... )`
  2. Logical NOT: `!` or `not`
  3. Logical AND: `&&` or `and`
  4. Logical OR: `||` or `or`
- **Comparison Operators:** `==`, `!=`, `>`, `>=`, `<`, `<=`, `contains`
- **Protocol Existence Primitives:** `tcp`, `udp`, `dns`, `icmp`, `arp`, `http`, `tls`, `ip`, `ipv4`, `ipv6`
- **Supported Fields Registry:**
  - **Addressing:** `ip.addr` (matches `src_ip` or `dst_ip`), `ip.src`, `ip.dst`, `ip.ttl`, `eth.src`, `eth.dst`
  - **Ports:** `tcp.port` (TCP `src_port` or `dst_port`), `tcp.srcport`, `tcp.dstport`, `udp.port` (UDP `src_port` or `dst_port`), `udp.srcport`, `udp.dstport`, `port` (any transport port)
  - **TCP Header & Flags:** `tcp.flags`, `tcp.flags.syn`, `tcp.flags.ack`, `tcp.flags.reset` (or `tcp.flags.rst`), `tcp.flags.fin`, `tcp.flags.push` (or `tcp.flags.psh`), `tcp.seq`, `tcp.ack`, `tcp.window_size`
  - **Frame Metadata:** `frame.number`, `frame.len`, `frame.protocols`, `info`
  - **DNS / HTTP / ICMP:** `dns.qry.name`, `dns.rcode`, `http.host`, `http.request.method`, `http.request.uri`, `icmp.type`, `icmp.code`

### Documented Differences from Wireshark's Display-Filter Language

- **Supported Subset:** NetTrace supports the documented field registry and operators listed above rather than Wireshark's 300,000+ dissector fields. Unknown field names fail validation immediately with a descriptive error message rather than being silently ignored.
- **Inequality (`!=`) Semantics on Missing Fields:** In Wireshark, `ip.addr != 1.2.3.4` can unexpectedly match because `ip.addr` evaluates both source and destination independently. In NetTrace, `ip.addr != X` evaluates cleanly to `src_ip != X AND dst_ip != X` on IP packets, and any comparison (`==` or `!=`) on a protocol-specific field (such as `tcp.port != 80`) evaluates to `False` on packets that do not carry that protocol (e.g., UDP or ARP packets).
- **No Bitmask Slice or Macro Syntax:** Bitwise masking (`tcp[13] & 0x02 != 0`), CIDR subnet masks (`192.168.1.0/24`), and regex matching (`matches` / `~`) are not part of the NetTrace grammar; use `tcp.flags.syn == 1` or `contains` instead.

---

## 5. Investigating Conversations in Flow Explorer

1. Navigate to **Flow Explorer**.
2. Inspect bidirectional conversations grouped by endpoint pairs.
3. Review inferred TCP states: `ESTABLISHED`, `INCOMPLETE_HANDSHAKE`, `RESET`, or `CLOSED_CLEAN`.
4. Observe handshake round-trip latency (`handshake_latency_ms`) computed between the initial `SYN` and `SYN-ACK`.
5. Click the **#SYN** button to jump directly to the initiating handshake packet in the Evidence Inspector.

---

## 6. Analyzing DNS Traffic

1. Navigate to **DNS Analysis**.
2. Inspect DNS transactions paired by transaction ID, query name, client, and server.
3. Filter by response codes:
   - `NOERROR` (0): Successful resolution with resolved IP answers.
   - `NXDOMAIN` (3): Non-existent domain names.
   - `SERVFAIL` (2): Server resolution failure or DNSSEC validation error.
   - `UNANSWERED`: Queries that received no observed response frame.
4. Click on **#Q** or **#R** buttons to inspect the query or response packet frames.

---

## 7. Reviewing Diagnostic Findings & Evidence

1. Navigate to **Findings & Diagnostics**.
2. Filter findings by **Severity** or **Category** (TCP, DNS, SCAN, ANOMALY).
3. Each finding card presents:
   - **Observed Facts:** Factual, objective summary of the event.
   - **Packet Evidence:** Numbered tags linking to the exact frames.
   - **Possible Explanations:** Plausible technical causes.
   - **Recommendations:** Next troubleshooting steps.
   - **Observation Limitations:** Explains why capture constraints could affect interpretation.

---

## 8. Exporting Reports

1. Navigate to **Reports & Export**.
2. Download or view:
   - **Interactive HTML:** Self-contained dark-themed report viewable in any browser.
   - **Executive PDF:** Formatted document rendered via ReportLab.
   - **Structured JSON:** Machine-readable JSON export for SIEM or automated pipelines.

---

## 9. Adjusting Heuristic Settings

1. Navigate to **Settings & About**.
2. Adjust detection parameters:
   - Port-scan threshold (default 15 ports).
   - Host-scan threshold (default 10 targets).
   - Connection burst threshold (default 20 packets).
   - Burst window duration (default 2.0s).
   - Repeated DNS query threshold (default 5 queries).
   - Periodic connection minimum count & coefficient of variation.
3. Click **Save Detector Settings**. Settings are persisted to SQLite and apply to subsequent analyses.

---

## 10. Exploring Communication Topology

1. Navigate to **Topology** in the left sidebar.
2. The **Communication Topology** graph visualizes observed IP conversations and Layer 2 hints from the active capture. It is **not** a map of physical cabling or router wiring.
3. **How to read the graph:**
   - **Nodes:** Each host node corresponds to a distinct IP endpoint in the capture, sized by captured byte volume.
     - **Cyan (`#06b6d4`):** Local / private / link-local endpoints.
     - **Blue (`#3b82f6`):** Remote / public endpoints.
     - **Amber (`#f59e0b` with dashed outline):** Inferred Layer 2 gateway (`gw:<mac>`).
     - **Slate (`#64748b`):** Multicast or unknown scope endpoints.
     - **Outer Severity Ring:** Endpoints associated with diagnostic findings display a colored ring matching their highest finding severity.
   - **Edges:** Solid lines represent observed IP conversations aggregated across flows (`normal` = slate, `reset` = rose, `incomplete` = amber, `scan` = purple).
   - **What Dashed Means:** Every **dashed** element (dashed gateway node outline, dashed Layer 2 adjacency edges, or `"inferred"` role/hop badges in the inspector) represents a heuristic inference rather than a directly observed L3 endpoint or flow. Hover over any dashed item or `"inferred"` badge to inspect its explicit `basis` explanation.
4. Click any node or edge to inspect MAC addresses, traffic volume, TTL hop estimates, flow state breakdowns, and linked findings, or click **View packets** / **View flows** to jump directly to filtered views.

