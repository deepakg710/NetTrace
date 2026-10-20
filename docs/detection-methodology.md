# NetTrace Detection Methodology

NetTrace applies evidence-based protocol heuristics to offline packet captures. It distinguishes:
1. **Observed Facts:** Directly verifiable frame attributes (flags, timestamps, byte lengths).
2. **Interpretations:** Heuristic condition classifications.
3. **Possible Explanations:** Plausible technical causes (both benign and adversarial).
4. **Recommended Steps:** Concrete investigation procedures.
5. **Observation Limitations:** Recording boundaries, asymmetric paths, and capture filters.

---

## 1. TCP Diagnostics

### A. Incomplete Handshakes (`TCP_INCOMPLETE_HANDSHAKE`)
- **Mechanism:** Detects a client sending a TCP `SYN` without an observed `SYN-ACK` response within the capture session.
- **Severity:** Low.
- **Confidence:** High (factual record of absence).
- **Limitations:** An absent response does not prove the server failed or is down; the capture may have started late, ended early, or captured traffic on a unidirectional tap.

### B. Connection Resets (`TCP_RESET_OBSERVED`)
- **Mechanism:** Inspects TCP frames for the `RST` flag. Correlates with destination port and prior conversation context.
- **Severity:** Medium (if &ge; 3 RSTs) or Low (single RST).
- **Confidence:** High.
- **Limitations:** RST packets are a standard operating system teardown mechanism for closed ports, unhandled keepalives, or non-lingering socket closures.

### C. Retransmission Candidates (`TCP_RETRANSMISSION_HEURISTIC`)
- **Mechanism:** Identifies segments with identical `(src_ip, dst_ip, src_port, dst_port, seq, payload_len > 0)` occurring with an inter-packet delay &Delta;t > 0.05s.
- **Severity:** Medium if frequent; Low otherwise.
- **Confidence:** Medium.
- **Limitations:** Switched port mirrors (SPAN), network interface offloads (LRO/TSO), or packet capture buffer duplication can produce identical frames on wire without actual network packet loss.

### D. Repeated Connection Attempts (`TCP_REPEATED_CONNECTION_ATTEMPTS`)
- **Mechanism:** Detects &ge; 3 `SYN` attempts from the same source to the same destination endpoint without a completing handshake.
- **Severity:** Medium.
- **Confidence:** High.
- **Limitations:** Legitimate clients automatically retry connections during temporary network congestion or service restarts.

---

## 2. DNS Diagnostics

### A. Non-Existent Domain (`DNS_NXDOMAIN_OBSERVED`)
- **Mechanism:** Pairs a DNS query with an authoritative response containing RCODE 3 (`NXDOMAIN`).
- **Severity:** Low.
- **Confidence:** High.
- **Limitations:** Authoritative confirmation that the record does not exist. Commonly caused by client typographical errors or search suffix misconfigurations.

### B. Server Failure (`DNS_SERVFAIL_OBSERVED`)
- **Mechanism:** Identifies DNS responses with RCODE 2 (`SERVFAIL`).
- **Severity:** Medium.
- **Confidence:** High.
- **Limitations:** Indicates recursive resolver timeout, authoritative zone delegation errors, or DNSSEC cryptographic validation failure.

### C. Unanswered DNS Queries (`DNS_UNANSWERED_QUERY`)
- **Mechanism:** Correlates transactions by `(transaction_id, client_ip, server_ip, query_name)`. Detects queries lacking an answering frame.
- **Severity:** Medium if repeated; Low otherwise.
- **Confidence:** Medium.
- **Limitations:** Packet capture duration, interface drop counters, or firewall rules dropping UDP 53 can prevent recording of responses.

---

## 3. Traffic Anomalies & Scan Detection

### A. Port-Scan Pattern (`PORT_SCAN_HEURISTIC`)
- **Threshold:** Single source IP contacting &ge; 15 distinct destination ports on a single host (configurable).
- **Severity:** Medium.
- **Confidence:** High.
- **Limitations:** Network health checks, vulnerability scans, and multi-service administrative agents can trigger this pattern legitimately.

### B. Host-Scan Pattern (`HOST_SCAN_HEURISTIC`)
- **Threshold:** Single source IP contacting &ge; 10 distinct destination IPs across the capture window (configurable).
- **Severity:** Medium.
- **Confidence:** High.
- **Limitations:** Common for DNS resolvers, NTP peers, and CDN edge clients.

### C. High-Rate Connection Bursts (`CONNECTION_BURST_DETECTION`)
- **Threshold:** &ge; 20 packets within a 2.0-second sliding window (configurable).
- **Severity:** Low.
- **Confidence:** Medium.
- **Limitations:** Parallel asset downloads in modern web browsers (HTTP/1.1 multi-socket and HTTP/2) naturally produce burst patterns.

### D. Periodic Connection Candidates (`PERIODIC_CONNECTION_HEURISTIC`)
- **Threshold:** &ge; 4 connections between same endpoints with Coefficient of Variation $CV = \frac{\sigma}{\mu} \le 0.2$ (configurable).
- **Formula:**
  $$\mu = \frac{1}{N-1} \sum_{i=1}^{N-1} (t_{i+1} - t_i)$$
  $$\sigma = \sqrt{\frac{1}{N-1} \sum_{i=1}^{N-1} ((t_{i+1} - t_i) - \mu)^2}$$
  $$CV = \frac{\sigma}{\mu}$$
- **Severity:** Low.
- **Confidence:** Medium.
- **Limitations:** Periodic polling is ubiquitous in NTP, SNMP, cron jobs, and application health probes. NetTrace labels these as periodic candidates, not malware beaconing.

---

## 4. Topology Inference

NetTrace's **Communication Topology** separates directly observed facts (IP endpoints, aggregated flows, DNS client/server roles) from heuristic inferences. Every inferred item is marked `inferred: true` with a documented `basis` string and rendered with dashed visual styling.

### A. Gateway MAC Inference
- **Heuristic:** When Layer 2 Ethernet frames are present (`l2_available: true`), NetTrace maps unicast source/destination MAC addresses to observed IP addresses (excluding broadcast `ff:ff:ff:ff:ff:ff`, zero, and multicast MACs). If a single unicast MAC address carries traffic for **&ge; 3 distinct IP addresses**, including **at least 1 remote (global) IP**, it is classified as an inferred gateway MAC.
  - If a single local IP node exclusively owns that MAC address, the `gateway` role (`inferred: true`) is attached to that node.
  - Otherwise, a virtual node `gw:<mac>` (`kind: "inferred_gateway"`) and dashed `inferred_l2` edges (with `packets: 0, bytes: 0`) are added between local hosts using that MAC, `gw:<mac>`, and the remote IPs routed through that MAC.
- **Limitations:** NAT gateways, L2/L3 load balancers, virtual switches, proxy ARP, or MAC spoofing can cause a single MAC to appear across multiple IPs without being a traditional default router. Captures without Ethernet headers (e.g., raw IP `DLT_RAW`, loopback, or Linux cooked `DLT_LINUX_SLL` captures) lack full L2 MAC pairs and disable gateway inference.

### B. TTL Hop-Distance Estimation
- **Heuristic:** For each source IP with observed IPv4 `TTL` values, NetTrace takes the maximum observed TTL (`max_ttl`) and assumes the initial operating-system TTL is the smallest value in `{64, 128, 255}` that is $\ge \text{max\_ttl}$. Estimated hop distance is computed as:
  $$\text{hops} = \text{assumed\_initial\_ttl} - \text{max\_ttl}$$
- **Limitations:** Different operating systems, custom sysctl tuning, intermediate middleboxes/firewalls that rewrite TTLs, asymmetric routing paths, and encapsulated VPN/tunnel traffic can invalidate the initial-TTL assumption.

### C. Endpoint Role Attribution
- **Observed Roles (`inferred: false`):**
  - `dns_server` / `dns_client`: Derived directly from observed DNS transaction `server_ip` and `client_ip` fields.
  - `involved_in_finding`: Assigned when an IP is listed in a diagnostic finding's evidence without directional scan attribution.
- **Inferred Roles (`inferred: true`):**
  - `scanner` / `scan_target`: Derived only from scan rules with deterministic `[src, dst...]` ordering (`PORT_SCAN_HEURISTIC`, `HOST_SCAN_HEURISTIC`).
- **Limitations:** Capture point bias (vantage point of the sniffer), NAT translation, application proxies, and encrypted tunnels can obscure the true origin or destination of traffic.

