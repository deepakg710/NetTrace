# NetTrace Sample Packet Captures

This directory contains deterministic, synthetically generated packet captures designed for local testing, automated test fixtures, and live demonstration without exposing production or user data.

## Available Samples

### 1. `normal_traffic.pcap` (10 packets)
- **Scenario:** Clean, non-anomalous baseline network interaction.
- **Protocols:** DNS (UDP), HTTP (TCP).
- **Observable Events:**
  - Client (`192.168.1.100`) queries resolver (`192.168.1.1`) for `example.local`.
  - DNS response returns `NOERROR` with `10.0.0.80`.
  - Complete TCP 3-way handshake (`SYN` \u2192 `SYN-ACK` \u2192 `ACK`) to port 80.
  - HTTP `GET /index.html` request and `200 OK` response.
  - Graceful connection termination via `FIN-ACK` exchange.
- **Expected Findings:** 0 diagnostic anomaly findings. Serves as baseline to confirm the dashboard does not flag benign traffic.

### 2. `incident_troubleshooting.pcap` (42 packets)
- **Scenario:** Multi-symptom network incident capture demonstrating protocol diagnostic capabilities.
- **Observable Diagnostic Conditions:**
  - **Incomplete Handshake:** Host `192.168.1.105` sends `SYN` to `10.0.0.99:443`, but no response is recorded within the observation window.
  - **Connection Reset (RST):** Closed port interaction on `10.0.0.80:8080` returning `RST-ACK`.
  - **Retransmission Candidate:** Same sequence number and payload sent twice from `192.168.1.105:49154` to `10.0.0.80:80`.
  - **DNS NXDOMAIN:** Query for `bad-host-typo.internal` returning RCODE 3.
  - **DNS SERVFAIL:** Query for `broken-zone.example` returning RCODE 2.
  - **Unanswered DNS Query:** Query for `telemetry.service.io` sent to `8.8.8.8` with no corresponding reply packet in the capture.
  - **Port Scan:** Single host (`192.168.1.200`) probes 18 distinct ports on `10.0.0.50` within a short window.
  - **Repeated Connection Attempts:** Host `192.168.1.105` retries `SYN` attempts to `10.0.0.99:22` four times.
  - **Periodic Connections:** 5 connections spaced at regular 1.0-second intervals between `192.168.1.105` and `10.0.0.80:9000`.

## Generating or Regenerating Samples
Run:
```powershell
python samples/generate_samples.py
```
or in Linux:
```bash
python3 samples/generate_samples.py
```
