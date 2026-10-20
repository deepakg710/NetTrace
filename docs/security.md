# NetTrace Security Architecture & Threat Model

## Threat Model Overview

Uploaded packet capture files (`.pcap`, `.pcapng`) are untrusted binary inputs. Historically, packet parsers have been vulnerable to memory corruption, integer overflows, and infinite loops when processing maliciously crafted frames.

NetTrace establishes defense-in-depth protections tailored for offline desktop and laboratory use.

---

## 1. File Validation & Ingestion Controls

- **Magic Byte Inspection:** File extensions (`.pcap`, `.pcapng`) must match strict header magic bytes:
  - Microsecond PCAP: `0xa1b2c3d4` or `0xd4c3b2a1`
  - Nanosecond PCAP: `0xa1b23c4d` or `0x4d3cb2a1`
  - PCAPNG: Section Header Block `0x0a0d0d0a`
- **File Size Ceiling:** Default configurable upload limit of 100 MB enforced before streaming bytes to disk.
- **Path Traversal Defense:** Uploaded filenames are sanitized (`re.sub(r"[^a-zA-Z0-9_\-\.]", "_", clean_name)`) and stored under non-deterministic UUID prefixes in a dedicated storage directory (`backend/data/uploads`). Files cannot escape the intended directory tree.

---

## 2. Parser Resilience & Memory Management

- **Streaming Ingestion:** Packets are parsed iteratively via Scapy's `PcapReader` rather than loading the entire capture file into memory as Python objects.
- **Malformed Packet Isolation:** Corrupted frames raise internal parser exceptions that are caught per packet. Instead of aborting the capture analysis, NetTrace logs a warning and marks the capture status as `partial`.
- **Bounded Result Sets:** API endpoints (Packets, Flows, DNS) require strict pagination with a maximum `page_size` of 500 records.

---

## 3. Data Privacy & Output Sanitization

- **Local-Only Guarantee:** NetTrace binds to `127.0.0.1` by default. No telemetry, third-party analytics, or cloud AI services are consulted.
- **Payload Masking:** To safeguard sensitive passwords, tokens, or personal identifiers present in raw network traffic, NetTrace does not store or render unparsed binary packet payloads. Only protocol headers and metadata are extracted.
- **XSS Prevention in Reports:** All strings embedded into the generated HTML reports (filenames, query domains, user agent strings) are HTML-escaped using Python's `html.escape`.

---

## 4. Operational Boundaries

- **Offline Mode Only:** NetTrace does not perform live network sniffing or promiscuous mode capture. It requires no administrative/root privileges on Windows or Linux.
- **Cleanup Guarantee:** Deleting a capture removes the on-disk PCAP file and triggers cascading SQLite database cleanup for all related packet, flow, endpoint, DNS, and finding records.
