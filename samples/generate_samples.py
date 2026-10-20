import time
import json
from pathlib import Path
from scapy.all import (
    Ether, IP, TCP, UDP, DNS, DNSQR, DNSRR, wrpcap, Raw
)

def generate_samples(output_dir: Path):
    output_dir.mkdir(parents=True, exist_ok=True)
    base_time = 1700000000.0  # Stable deterministic epoch timestamp

    # =========================================================================
    # SAMPLE 1: normal_traffic.pcap
    # =========================================================================
    normal_pkts = []
    t = base_time

    # 1. DNS Resolution for example.local (Success: NOERROR)
    dns_q = Ether() / IP(src="192.168.1.100", dst="192.168.1.1") / UDP(sport=43210, dport=53) / \
            DNS(id=0x1234, qr=0, qd=DNSQR(qname="example.local", qtype="A"))
    dns_q.time = t
    normal_pkts.append(dns_q)
    t += 0.015

    dns_r = Ether() / IP(src="192.168.1.1", dst="192.168.1.100") / UDP(sport=53, dport=43210) / \
            DNS(id=0x1234, qr=1, rcode=0,
                qd=DNSQR(qname="example.local", qtype="A"),
                an=DNSRR(rrname="example.local", type="A", rdata="10.0.0.80", ttl=300))
    dns_r.time = t
    normal_pkts.append(dns_r)
    t += 0.020

    # 2. Clean TCP 3-Way Handshake
    # Client -> Server SYN
    syn = Ether() / IP(src="192.168.1.100", dst="10.0.0.80") / \
          TCP(sport=54321, dport=80, flags="S", seq=1000, window=65535)
    syn.time = t
    normal_pkts.append(syn)
    t += 0.010

    # Server -> Client SYN-ACK
    syn_ack = Ether() / IP(src="10.0.0.80", dst="192.168.1.100") / \
              TCP(sport=80, dport=54321, flags="SA", seq=5000, ack=1001, window=65535)
    syn_ack.time = t
    normal_pkts.append(syn_ack)
    t += 0.008

    # Client -> Server ACK
    ack = Ether() / IP(src="192.168.1.100", dst="10.0.0.80") / \
          TCP(sport=54321, dport=80, flags="A", seq=1001, ack=5001, window=65535)
    ack.time = t
    normal_pkts.append(ack)
    t += 0.005

    # 3. HTTP Request & Response
    http_req_data = b"GET /index.html HTTP/1.1\r\nHost: example.local\r\nUser-Agent: NetTraceDemo/1.0\r\n\r\n"
    http_req = Ether() / IP(src="192.168.1.100", dst="10.0.0.80") / \
               TCP(sport=54321, dport=80, flags="PA", seq=1001, ack=5001, window=65535) / Raw(load=http_req_data)
    http_req.time = t
    normal_pkts.append(http_req)
    t += 0.012

    http_resp_data = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 13\r\n\r\nHello, World!"
    http_resp = Ether() / IP(src="10.0.0.80", dst="192.168.1.100") / \
                TCP(sport=80, dport=54321, flags="PA", seq=5001, ack=1001 + len(http_req_data), window=65535) / Raw(load=http_resp_data)
    http_resp.time = t
    normal_pkts.append(http_resp)
    t += 0.005

    # 4. Clean TCP Teardown (FIN/ACK)
    c_fin = Ether() / IP(src="192.168.1.100", dst="10.0.0.80") / \
            TCP(sport=54321, dport=80, flags="FA", seq=1001 + len(http_req_data), ack=5001 + len(http_resp_data), window=65535)
    c_fin.time = t
    normal_pkts.append(c_fin)
    t += 0.005

    s_fin = Ether() / IP(src="10.0.0.80", dst="192.168.1.100") / \
            TCP(sport=80, dport=54321, flags="FA", seq=5001 + len(http_resp_data), ack=c_fin.seq + 1, window=65535)
    s_fin.time = t
    normal_pkts.append(s_fin)
    t += 0.004

    c_ack = Ether() / IP(src="192.168.1.100", dst="10.0.0.80") / \
            TCP(sport=54321, dport=80, flags="A", seq=c_fin.seq + 1, ack=s_fin.seq + 1, window=65535)
    c_ack.time = t
    normal_pkts.append(c_ack)

    normal_path = output_dir / "normal_traffic.pcap"
    wrpcap(str(normal_path), normal_pkts)
    print(f"Generated normal capture: {normal_path} ({len(normal_pkts)} packets)")

    # =========================================================================
    # SAMPLE 2: incident_troubleshooting.pcap
    # =========================================================================
    incident_pkts = []
    t = base_time + 100.0

    # 1. Incomplete TCP Handshake (SYN sent, no SYN-ACK returned)
    inc_syn = Ether() / IP(src="192.168.1.105", dst="10.0.0.99") / \
              TCP(sport=49152, dport=443, flags="S", seq=2000, window=65535)
    inc_syn.time = t
    incident_pkts.append(inc_syn)
    t += 0.05

    # 2. TCP Connection Reset (RST received on closed port)
    rst_syn = Ether() / IP(src="192.168.1.105", dst="10.0.0.80") / \
              TCP(sport=49153, dport=8080, flags="S", seq=3000, window=65535)
    rst_syn.time = t
    incident_pkts.append(rst_syn)
    t += 0.01

    rst_pkt = Ether() / IP(src="10.0.0.80", dst="192.168.1.105") / \
              TCP(sport=8080, dport=49153, flags="RA", seq=0, ack=3001, window=0)
    rst_pkt.time = t
    incident_pkts.append(rst_pkt)
    t += 0.05

    # 3. TCP Retransmission Candidates (identical seq & payload sent twice)
    payload_data = b"POST /api/telemetry HTTP/1.1\r\nContent-Length: 16\r\n\r\nstatus=retransmit"
    ret1 = Ether() / IP(src="192.168.1.105", dst="10.0.0.80") / \
           TCP(sport=49154, dport=80, flags="PA", seq=4000, ack=1000, window=65535) / Raw(load=payload_data)
    ret1.time = t
    incident_pkts.append(ret1)
    t += 0.25  # 250ms later retransmission

    ret2 = Ether() / IP(src="192.168.1.105", dst="10.0.0.80") / \
           TCP(sport=49154, dport=80, flags="PA", seq=4000, ack=1000, window=65535) / Raw(load=payload_data)
    ret2.time = t
    incident_pkts.append(ret2)
    t += 0.10

    # 4. DNS NXDOMAIN Response
    nx_q = Ether() / IP(src="192.168.1.105", dst="192.168.1.1") / UDP(sport=52000, dport=53) / \
           DNS(id=0x55aa, qr=0, qd=DNSQR(qname="bad-host-typo.internal", qtype="A"))
    nx_q.time = t
    incident_pkts.append(nx_q)
    t += 0.015

    nx_r = Ether() / IP(src="192.168.1.1", dst="192.168.1.105") / UDP(sport=53, dport=52000) / \
           DNS(id=0x55aa, qr=1, rcode=3, qd=DNSQR(qname="bad-host-typo.internal", qtype="A"))  # NXDOMAIN
    nx_r.time = t
    incident_pkts.append(nx_r)
    t += 0.05

    # 5. DNS SERVFAIL Response
    sf_q = Ether() / IP(src="192.168.1.105", dst="192.168.1.1") / UDP(sport=52001, dport=53) / \
           DNS(id=0x55ab, qr=0, qd=DNSQR(qname="broken-zone.example", qtype="A"))
    sf_q.time = t
    incident_pkts.append(sf_q)
    t += 0.015

    sf_r = Ether() / IP(src="192.168.1.1", dst="192.168.1.105") / UDP(sport=53, dport=52001) / \
           DNS(id=0x55ab, qr=1, rcode=2, qd=DNSQR(qname="broken-zone.example", qtype="A"))  # SERVFAIL
    sf_r.time = t
    incident_pkts.append(sf_r)
    t += 0.05

    # 6. Unanswered DNS Query (no response packet recorded)
    unans_q = Ether() / IP(src="192.168.1.105", dst="8.8.8.8") / UDP(sport=52002, dport=53) / \
              DNS(id=0x77bb, qr=0, qd=DNSQR(qname="telemetry.service.io", qtype="A"))
    unans_q.time = t
    incident_pkts.append(unans_q)
    t += 0.10

    # 7. Repeated Connection Attempts (3+ SYNs to same unresponsive destination)
    for _ in range(4):
        rep_syn = Ether() / IP(src="192.168.1.105", dst="10.0.0.99") / \
                  TCP(sport=49160, dport=22, flags="S", seq=5000, window=65535)
        rep_syn.time = t
        incident_pkts.append(rep_syn)
        t += 0.30

    # 8. Port-Scan Pattern (Scanner contacting 18 distinct ports on 10.0.0.50)
    scan_ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 8080]
    for p in scan_ports:
        scan_syn = Ether() / IP(src="192.168.1.200", dst="10.0.0.50") / \
                   TCP(sport=50000 + p, dport=p, flags="S", seq=6000 + p, window=1024)
        scan_syn.time = t
        incident_pkts.append(scan_syn)
        t += 0.005

    # 9. Periodic Connection Candidates (5 connections with regular 1.0s interval)
    for i in range(5):
        p_syn = Ether() / IP(src="192.168.1.105", dst="10.0.0.80") / \
                TCP(sport=55000 + i, dport=9000, flags="S", seq=7000 + i, window=65535)
        p_syn.time = t
        incident_pkts.append(p_syn)
        p_rst = Ether() / IP(src="10.0.0.80", dst="192.168.1.105") / \
                TCP(sport=9000, dport=55000 + i, flags="RA", seq=0, ack=7001 + i, window=0)
        p_rst.time = t + 0.005
        incident_pkts.append(p_rst)
        t += 1.0

    incident_path = output_dir / "incident_troubleshooting.pcap"
    wrpcap(str(incident_path), incident_pkts)
    print(f"Generated incident capture: {incident_path} ({len(incident_pkts)} packets)")

    # =========================================================================
    # SAMPLE MANIFEST
    # =========================================================================
    manifest = {
        "version": "1.0",
        "description": "Deterministic, synthetic lab packet captures for NetTrace verification",
        "samples": [
            {
                "file": "normal_traffic.pcap",
                "format": "pcap",
                "total_packets": len(normal_pkts),
                "expected_findings": 0,
                "description": "Clean baseline network traffic with successful DNS resolution and complete HTTP TCP handshake/teardown.",
                "verification_checks": [
                    "DNS NOERROR response for example.local (10.0.0.80)",
                    "TCP 3-way handshake established between 192.168.1.100:54321 and 10.0.0.80:80",
                    "HTTP GET and HTTP 200 OK exchanged",
                    "Clean FIN/ACK connection termination",
                    "Zero suspicious scan or failure findings"
                ]
            },
            {
                "file": "incident_troubleshooting.pcap",
                "format": "pcap",
                "total_packets": len(incident_pkts),
                "expected_findings_categories": ["TCP", "DNS", "SCAN", "ANOMALY"],
                "description": "Multi-symptom network incident capture with handshakes, resets, DNS failures, and scan patterns.",
                "verification_checks": [
                    "Incomplete TCP Handshake (192.168.1.105:49152 -> 10.0.0.99:443)",
                    "Connection Reset (10.0.0.80:8080 -> 192.168.1.105)",
                    "Retransmission candidate (Seq 4000 from 192.168.1.105)",
                    "DNS NXDOMAIN response for bad-host-typo.internal",
                    "DNS SERVFAIL response for broken-zone.example",
                    "Unanswered DNS query for telemetry.service.io (to 8.8.8.8)",
                    "Port scan pattern (192.168.1.200 -> 10.0.0.50 on 18 ports)",
                    "Repeated connection attempts (192.168.1.105 -> 10.0.0.99:22)",
                    "Periodic connection candidate (192.168.1.105 -> 10.0.0.80:9000 at 1.0s interval)"
                ]
            }
        ]
    }

    manifest_path = output_dir / "sample_manifest.json"
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    print(f"Generated manifest: {manifest_path}")

if __name__ == "__main__":
    import sys
    out_dir = Path(__file__).resolve().parent
    generate_samples(out_dir)
