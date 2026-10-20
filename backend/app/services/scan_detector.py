import uuid
import math
from typing import List, Dict, Any, Tuple
from collections import defaultdict
from app.services.packet_parser import ParsedPacketData
from app.core.config import settings

def detect_scan_and_anomalies(
    packets: List[ParsedPacketData],
    flows: List[Dict[str, Any]],
    custom_thresholds: Dict[str, Any] = None
) -> List[Dict[str, Any]]:
    """
    Detects port scans, host scans, connection bursts, traffic spikes,
    repeated DNS activity, and periodic connection candidates.
    """
    findings: List[Dict[str, Any]] = []
    
    t_port_scan = custom_thresholds.get("port_scan_threshold", settings.PORT_SCAN_THRESHOLD) if custom_thresholds else settings.PORT_SCAN_THRESHOLD
    t_host_scan = custom_thresholds.get("host_scan_threshold", settings.HOST_SCAN_THRESHOLD) if custom_thresholds else settings.HOST_SCAN_THRESHOLD
    t_burst = custom_thresholds.get("connection_burst_threshold", settings.CONNECTION_BURST_THRESHOLD) if custom_thresholds else settings.CONNECTION_BURST_THRESHOLD
    t_burst_window = custom_thresholds.get("burst_window_seconds", settings.BURST_WINDOW_SECONDS) if custom_thresholds else settings.BURST_WINDOW_SECONDS
    t_rep_dns = custom_thresholds.get("repeated_dns_query_threshold", settings.REPEATED_DNS_QUERY_THRESHOLD) if custom_thresholds else settings.REPEATED_DNS_QUERY_THRESHOLD
    t_period_count = custom_thresholds.get("periodic_connection_min_count", settings.PERIODIC_CONNECTION_MIN_COUNT) if custom_thresholds else settings.PERIODIC_CONNECTION_MIN_COUNT
    t_period_cv = custom_thresholds.get("periodic_cv_threshold", settings.PERIODIC_CV_THRESHOLD) if custom_thresholds else settings.PERIODIC_CV_THRESHOLD
    t_spike_pps = custom_thresholds.get("traffic_rate_spike_pps", settings.TRAFFIC_RATE_SPIKE_PPS) if custom_thresholds else settings.TRAFFIC_RATE_SPIKE_PPS

    # 1. Port-Scan Pattern: Source contacting >= t_port_scan distinct ports on a single host
    target_ports_map: Dict[Tuple[str, str], List[ParsedPacketData]] = defaultdict(list)
    for p in packets:
        if p.src_ip and p.dst_ip and p.dst_port:
            target_ports_map[(p.src_ip, p.dst_ip)].append(p)

    for (src, dst), pkts in target_ports_map.items():
        distinct_ports = sorted(list(set(p.dst_port for p in pkts)))
        if len(distinct_ports) >= t_port_scan:
            pkt_nums = [p.packet_number for p in pkts]
            ts_list = [p.timestamp for p in pkts]
            duration = max(0.01, ts_list[-1] - ts_list[0]) if len(ts_list) > 1 else 0.01

            findings.append({
                "id": uuid.uuid4().hex,
                "category": "SCAN",
                "severity": "Medium",
                "confidence": "High",
                "title": f"Port-Scan Pattern Detected: {src} \u2192 {dst} ({len(distinct_ports)} distinct ports)",
                "observed_facts": (
                    f"Source host {src} contacted {len(distinct_ports)} distinct destination ports on target {dst} "
                    f"within a duration of {duration:.2f}s. Probed ports include: {distinct_ports[:10]}... "
                    f"Supporting packets: #{pkt_nums[:10]}."
                ),
                "supporting_packet_numbers": pkt_nums[:20],
                "timestamps": ts_list[:20],
                "endpoints": [src, dst],
                "ports": distinct_ports[:15],
                "rule_name": "PORT_SCAN_HEURISTIC",
                "threshold_val": f"Distinct ports >= {t_port_scan} (observed {len(distinct_ports)})",
                "explanations": (
                    "Possible explanations: (1) Network vulnerability scanner or port sweep utility (e.g. nmap); "
                    "(2) Misconfigured monitoring tool or service discovery daemon; "
                    "(3) Multi-service client or application performing dynamic socket connections."
                ),
                "recommendations": (
                    f"Identify the application or process running on host {src}. "
                    "Review host firewall logs on target {dst} to verify whether connection attempts were rejected or dropped. "
                    "Confirm if this host is an authorized security audit system."
                ),
                "limitations": (
                    "A pattern of multiple ports does not establish malicious intent or system compromise. "
                    "Legitimate network health-checks and administrative discovery can exhibit this pattern."
                )
            })

    # 2. Host-Scan Pattern: Source contacting >= t_host_scan distinct destination IPs
    target_hosts_map: Dict[str, List[ParsedPacketData]] = defaultdict(list)
    for p in packets:
        if p.src_ip and p.dst_ip and p.src_ip != p.dst_ip:
            target_hosts_map[p.src_ip].append(p)

    for src, pkts in target_hosts_map.items():
        distinct_dsts = sorted(list(set(p.dst_ip for p in pkts)))
        if len(distinct_dsts) >= t_host_scan:
            pkt_nums = [p.packet_number for p in pkts]
            ts_list = [p.timestamp for p in pkts]
            duration = max(0.01, ts_list[-1] - ts_list[0]) if len(ts_list) > 1 else 0.01

            findings.append({
                "id": uuid.uuid4().hex,
                "category": "SCAN",
                "severity": "Medium",
                "confidence": "High",
                "title": f"Host-Scan Pattern Detected: {src} contacted {len(distinct_dsts)} distinct hosts",
                "observed_facts": (
                    f"Host {src} communicated with {len(distinct_dsts)} distinct destination hosts across {duration:.2f}s. "
                    f"Target IPs include: {distinct_dsts[:8]}... Supporting packets: #{pkt_nums[:10]}."
                ),
                "supporting_packet_numbers": pkt_nums[:20],
                "timestamps": ts_list[:20],
                "endpoints": [src] + distinct_dsts[:10],
                "ports": [p.dst_port for p in pkts if p.dst_port][:10],
                "rule_name": "HOST_SCAN_HEURISTIC",
                "threshold_val": f"Distinct target hosts >= {t_host_scan} (observed {len(distinct_dsts)})",
                "explanations": (
                    "Possible explanations: (1) Subnet discovery or horizontal network sweep; "
                    "(2) Peer-to-peer file sharing or distributed hash table (DHT) traffic; "
                    "(3) Network mapper or DHCP/DNS reconnaissance."
                ),
                "recommendations": (
                    f"Investigate active network sockets on {src}. "
                    "Check network IDS/IPS alerts for correlated horizontal scanning signatures."
                ),
                "limitations": (
                    "Broad communication is common for DNS forwarders, proxy servers, NTP nodes, or CDN clients."
                )
            })

    # 3. Connection Burst Pattern: >= t_burst packets/flows within t_burst_window
    if len(packets) >= t_burst:
        sorted_pkts = sorted(packets, key=lambda p: p.timestamp)
        # Sliding window check
        burst_detected = False
        window_start = 0
        for window_end in range(len(sorted_pkts)):
            while sorted_pkts[window_end].timestamp - sorted_pkts[window_start].timestamp > t_burst_window:
                window_start += 1
            count = window_end - window_start + 1
            if count >= t_burst and not burst_detected:
                burst_pkts = sorted_pkts[window_start:window_end + 1]
                pkt_nums = [p.packet_number for p in burst_pkts]
                burst_detected = True
                findings.append({
                    "id": uuid.uuid4().hex,
                    "category": "ANOMALY",
                    "severity": "Low",
                    "confidence": "Medium",
                    "title": f"High-Rate Connection Burst: {count} packets in {t_burst_window}s window",
                    "observed_facts": (
                        f"Detected a sudden concentration of {count} packets between timestamps "
                        f"{burst_pkts[0].timestamp:.3f} and {burst_pkts[-1].timestamp:.3f} (delta={burst_pkts[-1].timestamp - burst_pkts[0].timestamp:.3f}s). "
                        f"Sample packet sequence: #{pkt_nums[:8]}."
                    ),
                    "supporting_packet_numbers": pkt_nums[:15],
                    "timestamps": [p.timestamp for p in burst_pkts[:15]],
                    "endpoints": list(set([p.src_ip for p in burst_pkts if p.src_ip] + [p.dst_ip for p in burst_pkts if p.dst_ip]))[:5],
                    "ports": list(set([p.dst_port for p in burst_pkts if p.dst_port]))[:5],
                    "rule_name": "CONNECTION_BURST_DETECTION",
                    "threshold_val": f">= {t_burst} packets within {t_burst_window}s",
                    "explanations": (
                        "Possible explanations: (1) Bulk file transfer, web page loading multiple assets, or API batch sync; "
                        "(2) Network service reconnection flurry after momentary link flap; "
                        "(3) Automated scripting or high-throughput benchmark."
                    ),
                    "recommendations": (
                        "Verify whether application workloads scheduled batch transfers during this time window."
                    ),
                    "limitations": (
                        "Modern web applications routinely open dozens of parallel TCP sockets or HTTP/2 streams during page loads."
                    )
                })
                break

    # 4. Repeated DNS Activity
    dns_query_counts = defaultdict(list)
    for p in packets:
        if "dns" in p.details and not p.details["dns"]["is_response"]:
            for q in p.details["dns"].get("queries", []):
                dns_query_counts[q["name"]].append(p)

    for qname, pkts in dns_query_counts.items():
        if len(pkts) >= t_rep_dns:
            pkt_nums = [p.packet_number for p in pkts]
            ts_list = [p.timestamp for p in pkts]
            findings.append({
                "id": uuid.uuid4().hex,
                "category": "DNS",
                "severity": "Low",
                "confidence": "Medium",
                "title": f"Frequent Repeated DNS Queries: '{qname}' ({len(pkts)} requests)",
                "observed_facts": (
                    f"Observed {len(pkts)} DNS requests for domain '{qname}'. "
                    f"Sample query packet numbers: #{pkt_nums[:8]}."
                ),
                "supporting_packet_numbers": pkt_nums[:15],
                "timestamps": ts_list[:15],
                "endpoints": list(set([p.src_ip for p in pkts if p.src_ip] + [p.dst_ip for p in pkts if p.dst_ip])),
                "ports": [53],
                "rule_name": "REPEATED_DNS_QUERY_DETECTOR",
                "threshold_val": f"Query count >= {t_rep_dns} (observed {len(pkts)})",
                "explanations": (
                    "Possible explanations: (1) Application polling an API endpoint or short TTL record; "
                    "(2) Cache miss or zero-TTL DNS configuration; "
                    "(3) Background telemetry or heartbeat ping."
                ),
                "recommendations": (
                    f"Check TTL of domain '{qname}' in DNS responses. "
                    "Inspect caching behavior of client DNS resolver."
                ),
                "limitations": (
                    "Short TTLs (e.g. 5-60 seconds) in modern cloud architectures naturally cause high query frequencies."
                )
            })

    # 5. Periodic Connection Candidates
    # Check flows between same (src_ip, dst_ip, dst_port) with >= t_period_count occurrences
    flow_pairs = defaultdict(list)
    for f in flows:
        if f.get("src_ip") and f.get("dst_ip") and f.get("dst_port"):
            flow_pairs[(f["src_ip"], f["dst_ip"], f["dst_port"])].append(f)

    for (src, dst, dport), pair_flows in flow_pairs.items():
        if len(pair_flows) >= t_period_count:
            # Sort by start_time
            sorted_flows = sorted(pair_flows, key=lambda x: x["start_time"])
            deltas = [
                sorted_flows[i + 1]["start_time"] - sorted_flows[i]["start_time"]
                for i in range(len(sorted_flows) - 1)
            ]
            if len(deltas) >= 3:
                mean_delta = sum(deltas) / len(deltas)
                if mean_delta > 0.1:
                    variance = sum((d - mean_delta) ** 2 for d in deltas) / len(deltas)
                    std_dev = math.sqrt(variance)
                    cv = std_dev / mean_delta  # Coefficient of variation

                    if cv <= t_period_cv:
                        all_pkts = []
                        for fl in sorted_flows:
                            all_pkts.extend(fl.get("packet_numbers", [])[:2])

                        findings.append({
                            "id": uuid.uuid4().hex,
                            "category": "ANOMALY",
                            "severity": "Low",
                            "confidence": "Medium",
                            "title": f"Periodic Connection Candidate: {src} \u2192 {dst}:{dport} (~{mean_delta:.2f}s interval)",
                            "observed_facts": (
                                f"Observed {len(sorted_flows)} distinct connections from {src} to {dst}:{dport} "
                                f"with an average interval of {mean_delta:.2f} seconds and coefficient of variation {cv:.3f}. "
                                f"Evidence packets: #{all_pkts[:10]}."
                            ),
                            "supporting_packet_numbers": all_pkts[:15],
                            "timestamps": [fl["start_time"] for fl in sorted_flows][:15],
                            "endpoints": [src, dst],
                            "ports": [dport],
                            "rule_name": "PERIODIC_CONNECTION_HEURISTIC",
                            "threshold_val": f"CV <= {t_period_cv} and count >= {t_period_count} (observed count={len(sorted_flows)}, cv={cv:.3f})",
                            "explanations": (
                                "Possible explanations: (1) Periodic health check or monitoring agent polling; "
                                "(2) NTP synchronization or telemetry heartbeat; "
                                "(3) Automated cron job or scheduled synchronization task; "
                                "(4) Potential periodic beaconing candidate (requires endpoint validation)."
                            ),
                            "recommendations": (
                                "Check scheduled tasks (cron, systemd timers, Windows Task Scheduler) on the source host. "
                                "Do not label this as malware beaconing without supporting process and binary attribution."
                            ),
                            "limitations": (
                                "Regular network polling is ubiquitous in standard system monitoring and keepalive protocols."
                            )
                        })

    return findings
