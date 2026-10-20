import uuid
from typing import List, Dict, Any
from collections import defaultdict
from app.services.packet_parser import ParsedPacketData

def analyze_tcp_diagnostics(packets: List[ParsedPacketData], flows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []

    # 1. Incomplete Handshakes
    incomplete_flows = [f for f in flows if f.get("state") == "INCOMPLETE_HANDSHAKE"]
    for f in incomplete_flows:
        syn_pkt_num = f.get("details", {}).get("syn_packet")
        pkts = [syn_pkt_num] if syn_pkt_num else f.get("packet_numbers", [])[:5]
        findings.append({
            "id": uuid.uuid4().hex,
            "category": "TCP",
            "severity": "Low",
            "confidence": "High",
            "title": f"Incomplete TCP Handshake: {f['src_ip']}:{f['src_port']} \u2192 {f['dst_ip']}:{f['dst_port']}",
            "observed_facts": (
                f"Client sent TCP SYN (Packet #{syn_pkt_num or 'unknown'}) at timestamp {f['start_time']:.4f}, "
                f"but no corresponding SYN-ACK response was observed within the capture window."
            ),
            "supporting_packet_numbers": pkts,
            "timestamps": [f["start_time"]],
            "endpoints": [f["src_ip"], f["dst_ip"]],
            "ports": [f["src_port"], f["dst_port"]],
            "rule_name": "TCP_INCOMPLETE_HANDSHAKE",
            "threshold_val": "SYN without SYN-ACK observed",
            "explanations": (
                "Possible explanations: (1) Remote host is offline or port is closed with packet dropping; "
                "(2) Intermediate firewall or security group dropped the SYN packet; "
                "(3) Packet capture interface was positioned where return traffic was routed asymmetrically; "
                "(4) Capture ended before the remote server could respond."
            ),
            "recommendations": (
                "Verify whether the destination host is listening on the targeted port. "
                "Check intermediate network firewalls and routing tables for asymmetric routing. "
                "Inspect related ICMP Destination/Port Unreachable messages if present."
            ),
            "limitations": (
                "An absent response in a capture does not prove the remote server failed to respond. "
                "The capture may begin late, end early, or capture filter rules may have omitted return traffic."
            )
        })

    # 2. Connection Resets (RST)
    rst_packets: List[ParsedPacketData] = []
    for pkt in packets:
        if pkt.details.get("tcp") and "RST" in pkt.details["tcp"]["flags"]:
            rst_packets.append(pkt)

    if rst_packets:
        # Group by flow/destination
        rst_by_dst = defaultdict(list)
        for p in rst_packets:
            rst_by_dst[(p.src_ip, p.dst_ip, p.dst_port)].append(p)

        for (src, dst, dport), pkts in rst_by_dst.items():
            pkt_nums = [p.packet_number for p in pkts]
            ts_list = [p.timestamp for p in pkts]
            findings.append({
                "id": uuid.uuid4().hex,
                "category": "TCP",
                "severity": "Medium" if len(pkts) >= 3 else "Low",
                "confidence": "High",
                "title": f"TCP Connection Reset Observed: {src} \u2192 {dst}:{dport} ({len(pkts)} RST packet{'s' if len(pkts)>1 else ''})",
                "observed_facts": (
                    f"Observed {len(pkts)} TCP RST packet(s) sent from {src} to {dst}:{dport}. "
                    f"First RST at packet #{pkt_nums[0]} (t={ts_list[0]:.4f})."
                ),
                "supporting_packet_numbers": pkt_nums[:15],
                "timestamps": ts_list[:15],
                "endpoints": [src, dst],
                "ports": [dport],
                "rule_name": "TCP_RESET_OBSERVED",
                "threshold_val": f"RST count >= 1 (observed {len(pkts)})",
                "explanations": (
                    "Possible explanations: (1) Destination port is closed or listening process was terminated; "
                    "(2) An active connection was aborted abruptly by an application or OS timeout; "
                    "(3) An intermediate stateful firewall or proxy rejected the connection; "
                    "(4) Sequence number mismatch or half-open socket condition."
                ),
                "recommendations": (
                    "Check server application logs for abrupt socket crashes or timeout disconnects. "
                    "Confirm if port is open and actively monitored by the intended daemon. "
                    "Do not assume malicious activity without corresponding unauthorized traffic patterns."
                ),
                "limitations": (
                    "RST packets are a normal TCP teardown mechanism in many operating systems "
                    "when non-lingering sockets are closed or unhandled packets arrive on closed ports."
                )
            })

    # 3. Retransmission Candidates
    # Heuristic: Same (src_ip, dst_ip, src_port, dst_port, seq, payload_len > 0) seen within 0.01s - 5.0s
    seq_tracker: Dict[Tuple[str, str, int, int, int, int], List[ParsedPacketData]] = defaultdict(list)
    for pkt in packets:
        tcp_info = pkt.details.get("tcp")
        if tcp_info and tcp_info.get("payload_len", 0) > 0:
            key = (pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port, tcp_info["seq"], tcp_info["payload_len"])
            seq_tracker[key].append(pkt)

    retrans_pairs = {k: v for k, v in seq_tracker.items() if len(v) > 1}
    if retrans_pairs:
        all_retrans_pkts = []
        for v in retrans_pairs.values():
            all_retrans_pkts.extend(v[1:])  # The repeated occurrences

        pkt_nums = [p.packet_number for p in all_retrans_pkts]
        ts_list = [p.timestamp for p in all_retrans_pkts]
        affected_eps = list(set([p.src_ip for p in all_retrans_pkts] + [p.dst_ip for p in all_retrans_pkts]))

        findings.append({
            "id": uuid.uuid4().hex,
            "category": "TCP",
            "severity": "Medium" if len(all_retrans_pkts) > 5 else "Low",
            "confidence": "Medium",
            "title": f"TCP Retransmission Candidates Detected ({len(all_retrans_pkts)} instance{'s' if len(all_retrans_pkts)>1 else ''})",
            "observed_facts": (
                f"Observed {len(all_retrans_pkts)} packet(s) matching previous sequence number and payload length "
                f"from the same source to destination. Example packets: #{pkt_nums[:5]}."
            ),
            "supporting_packet_numbers": pkt_nums[:20],
            "timestamps": ts_list[:20],
            "endpoints": affected_eps[:5],
            "ports": [p.dst_port for p in all_retrans_pkts if p.dst_port][:5],
            "rule_name": "TCP_RETRANSMISSION_HEURISTIC",
            "threshold_val": "Repeated Seq# & PayloadLen > 0",
            "explanations": (
                "Possible explanations: (1) Network congestion causing dropped packets; "
                "(2) Buffer overrun at the receiver or intermediate switch; "
                "(3) Duplicate capture artifact caused by span/mirror port configuration."
            ),
            "recommendations": (
                "Inspect network switch interface counters for packet discards and CRC errors. "
                "Check TCP RTT and window sizes to evaluate path MTU and latency issues."
            ),
            "limitations": (
                "Capture duplication, NIC segmentation offload (TSO/LRO), packet aggregation, "
                "or duplicate port mirroring taps can generate identical packets on wire without real network loss."
            )
        })

    # 4. Repeated Connection Attempts (SYN flood / retry heuristic)
    syn_counts = defaultdict(list)
    for pkt in packets:
        tcp_info = pkt.details.get("tcp")
        if tcp_info and "SYN" in tcp_info["flags"] and "ACK" not in tcp_info["flags"]:
            syn_counts[(pkt.src_ip, pkt.dst_ip, pkt.dst_port)].append(pkt)

    for (src, dst, dport), pkts in syn_counts.items():
        if len(pkts) >= 3:
            pkt_nums = [p.packet_number for p in pkts]
            ts_list = [p.timestamp for p in pkts]
            duration = ts_list[-1] - ts_list[0]
            findings.append({
                "id": uuid.uuid4().hex,
                "category": "TCP",
                "severity": "Medium",
                "confidence": "High",
                "title": f"Repeated TCP Connection Attempts: {src} \u2192 {dst}:{dport} ({len(pkts)} SYNs)",
                "observed_facts": (
                    f"Host {src} sent {len(pkts)} SYN packets to {dst}:{dport} across {duration:.2f}s "
                    f"without receiving a stabilizing handshake. Packet numbers: {pkt_nums[:10]}."
                ),
                "supporting_packet_numbers": pkt_nums[:15],
                "timestamps": ts_list[:15],
                "endpoints": [src, dst],
                "ports": [dport],
                "rule_name": "TCP_REPEATED_CONNECTION_ATTEMPTS",
                "threshold_val": f">= 3 SYNs to same dest without completion (observed {len(pkts)})",
                "explanations": (
                    "Possible explanations: (1) Client retry backoff mechanism attempting to reach an unresponsive service; "
                    "(2) Firewall dropping initial SYN requests; "
                    "(3) Port scanning or automated health-check probe."
                ),
                "recommendations": (
                    "Check if the service on {dst}:{dport} is active and accepting connections. "
                    "Review routing or firewall drop logs between {src} and {dst}."
                ),
                "limitations": (
                    "Legitimate network clients retry connections upon transient network timeout."
                )
            })

    return findings
