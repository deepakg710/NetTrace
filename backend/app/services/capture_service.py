import json
import time
from pathlib import Path
from typing import Dict, Any, List
from collections import defaultdict
from sqlalchemy.orm import Session

from app.models.models import Capture, Packet, Flow, Endpoint, DNSRecord, Finding, DetectorSetting
from app.services.packet_parser import stream_parse_pcap, ParsedPacketData
from app.services.flow_analyzer import analyze_flows
from app.services.tcp_analyzer import analyze_tcp_diagnostics
from app.services.dns_analyzer import analyze_dns_activity
from app.services.scan_detector import detect_scan_and_anomalies
from app.core.logging import logger

def _is_unicast_mac(mac: str) -> bool:
    if not mac or not isinstance(mac, str):
        return False
    m = mac.strip().lower()
    if m in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
        return False
    parts = m.split(":")
    if len(parts) != 6:
        return False
    try:
        first_octet = int(parts[0], 16)
        return (first_octet & 1) == 0
    except ValueError:
        return False

def get_current_thresholds(db: Session) -> Dict[str, Any]:
    thresholds = {}
    settings_records = db.query(DetectorSetting).all()
    for s in settings_records:
        try:
            thresholds[s.key] = json.loads(s.value_json)
        except Exception:
            pass
    return thresholds

def process_and_analyze_capture(capture_id: str, db: Session) -> Capture:
    """
    Executes full offline PCAP parsing, protocol analysis, flow tracking,
    TCP/DNS troubleshooting, and anomaly detection.
    """
    capture = db.query(Capture).filter(Capture.id == capture_id).first()
    if not capture:
        raise ValueError(f"Capture {capture_id} not found.")

    filepath = Path(capture.filename)
    if not filepath.exists():
        capture.status = "failed"
        capture.error_message = f"File not found on disk: {filepath}"
        db.commit()
        return capture

    capture.status = "analyzing"
    db.commit()

    try:
        packets: List[ParsedPacketData] = []
        all_warnings: List[str] = []
        protocol_counts: Dict[str, int] = defaultdict(int)
        protocol_bytes: Dict[str, int] = defaultdict(int)
        total_captured_bytes = 0
        endpoints_data: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
            "packet_count": 0, "byte_count": 0,
            "sent_packets": 0, "recv_packets": 0,
            "sent_bytes": 0, "recv_bytes": 0,
            "first_seen": None, "last_seen": None,
            "protocols": set(), "flows": set()
        })
        l2_available = False
        ip_macs_sets: Dict[str, set] = defaultdict(set)
        mac_ips_sets: Dict[str, set] = defaultdict(set)
        ip_ttls_data: Dict[str, Dict[str, int]] = {}

        # 1. Stream parse packets
        for pkt in stream_parse_pcap(filepath):
            packets.append(pkt)
            if pkt.warnings:
                all_warnings.extend(pkt.warnings)
            
            protocol_counts[pkt.protocol] += 1
            protocol_bytes[pkt.protocol] += pkt.length
            total_captured_bytes += pkt.length

            # L2 / TTL topology hints
            layers_tree = pkt.details.get("layers_tree", []) if pkt.details else []
            for layer in layers_tree:
                if layer.get("name") == "Ethernet II":
                    l2_available = True
                    fields = layer.get("fields", {})
                    eth_src = fields.get("Source MAC", "")
                    eth_dst = fields.get("Destination MAC", "")
                    if pkt.src_ip and pkt.src_ip != "unknown" and _is_unicast_mac(eth_src):
                        m_src = eth_src.strip().lower()
                        ip_macs_sets[pkt.src_ip].add(m_src)
                        mac_ips_sets[m_src].add(pkt.src_ip)
                    if pkt.dst_ip and pkt.dst_ip != "unknown" and _is_unicast_mac(eth_dst):
                        m_dst = eth_dst.strip().lower()
                        ip_macs_sets[pkt.dst_ip].add(m_dst)
                        mac_ips_sets[m_dst].add(pkt.dst_ip)

            if pkt.src_ip and pkt.src_ip != "unknown" and pkt.details and "ip_ttl" in pkt.details:
                try:
                    ttl_val = int(pkt.details["ip_ttl"])
                    if pkt.src_ip not in ip_ttls_data:
                        ip_ttls_data[pkt.src_ip] = {"min": ttl_val, "max": ttl_val, "samples": 1}
                    else:
                        t_entry = ip_ttls_data[pkt.src_ip]
                        t_entry["min"] = min(t_entry["min"], ttl_val)
                        t_entry["max"] = max(t_entry["max"], ttl_val)
                        t_entry["samples"] += 1
                except (ValueError, TypeError):
                    pass

            # Endpoints tracking
            if pkt.src_ip and pkt.src_ip != "unknown":
                ep_s = endpoints_data[pkt.src_ip]
                ep_s["packet_count"] += 1
                ep_s["byte_count"] += pkt.length
                ep_s["sent_packets"] += 1
                ep_s["sent_bytes"] += pkt.length
                ep_s["protocols"].add(pkt.protocol)
                ep_s["first_seen"] = pkt.timestamp if ep_s["first_seen"] is None else min(ep_s["first_seen"], pkt.timestamp)
                ep_s["last_seen"] = pkt.timestamp if ep_s["last_seen"] is None else max(ep_s["last_seen"], pkt.timestamp)

            if pkt.dst_ip and pkt.dst_ip != "unknown":
                ep_d = endpoints_data[pkt.dst_ip]
                ep_d["packet_count"] += 1
                ep_d["byte_count"] += pkt.length
                ep_d["recv_packets"] += 1
                ep_d["recv_bytes"] += pkt.length
                ep_d["protocols"].add(pkt.protocol)
                ep_d["first_seen"] = pkt.timestamp if ep_d["first_seen"] is None else min(ep_d["first_seen"], pkt.timestamp)
                ep_d["last_seen"] = pkt.timestamp if ep_d["last_seen"] is None else max(ep_d["last_seen"], pkt.timestamp)

        total_packet_count = len(packets)
        if total_packet_count == 0:
            capture.status = "completed"
            capture.packet_count = 0
            capture.duration_seconds = 0.0
            capture.metadata_json = json.dumps({
                "total_bytes": 0,
                "protocol_counts": {},
                "protocol_bytes": {},
                "topology_hints": {
                    "l2_available": False,
                    "ip_macs": {},
                    "mac_ips": {},
                    "ip_ttls": {}
                },
                "warnings": ["Capture file contains 0 readable packets."]
            })
            db.commit()
            return capture

        start_time = packets[0].timestamp
        end_time = packets[-1].timestamp
        duration = max(0.0, round(end_time - start_time, 4))
        first_ts = start_time

        # 2. Persist Packets in batches
        batch_size = 500
        packet_models = []
        for p in packets:
            p_rel = round(p.timestamp - first_ts, 4)
            packet_models.append(Packet(
                capture_id=capture.id,
                packet_number=p.packet_number,
                timestamp=p.timestamp,
                rel_time=p_rel,
                src_ip=p.src_ip,
                dst_ip=p.dst_ip,
                src_port=p.src_port,
                dst_port=p.dst_port,
                protocol=p.protocol,
                length=p.length,
                original_length=p.original_length,
                tcp_flags=p.tcp_flags,
                info=p.info[:500],
                details_json=json.dumps(p.details)
            ))
            if len(packet_models) >= batch_size:
                db.bulk_save_objects(packet_models)
                packet_models.clear()
        if packet_models:
            db.bulk_save_objects(packet_models)
            packet_models.clear()

        # 3. Analyze Flows
        flow_results = analyze_flows(packets)
        flow_models = []
        for f in flow_results:
            flow_models.append(Flow(
                capture_id=capture.id,
                flow_id=f["flow_id"],
                protocol=f["protocol"],
                src_ip=f["src_ip"],
                src_port=f["src_port"],
                dst_ip=f["dst_ip"],
                dst_port=f["dst_port"],
                packet_count=f["packet_count"],
                byte_count=f["byte_count"],
                src_to_dst_packets=f["src_to_dst_packets"],
                dst_to_src_packets=f["dst_to_src_packets"],
                src_to_dst_bytes=f["src_to_dst_bytes"],
                dst_to_src_bytes=f["dst_to_src_bytes"],
                start_time=f["start_time"],
                end_time=f["end_time"],
                duration=f["duration"],
                state=f["state"],
                handshake_latency_ms=f["handshake_latency_ms"],
                retransmissions_count=f["retransmissions_count"],
                details_json=json.dumps(f["details"])
            ))
        if flow_models:
            db.bulk_save_objects(flow_models)

        # 4. Analyze DNS
        dns_records, dns_findings = analyze_dns_activity(packets)
        dns_models = []
        for d in dns_records:
            dns_models.append(DNSRecord(
                capture_id=capture.id,
                transaction_id=d["transaction_id"],
                query_name=d["query_name"],
                query_type=d["query_type"],
                client_ip=d["client_ip"],
                server_ip=d["server_ip"],
                query_time=d["query_time"],
                response_time=d["response_time"],
                rcode=d["rcode"],
                is_answered=d["is_answered"],
                latency_ms=d["latency_ms"],
                query_packet_number=d["query_packet_number"],
                response_packet_number=d["response_packet_number"],
                answers_json=json.dumps(d["answers"])
            ))
        if dns_models:
            db.bulk_save_objects(dns_models)

        # 5. Persist Endpoints
        endpoint_models = []
        for ip, edata in endpoints_data.items():
            endpoint_models.append(Endpoint(
                capture_id=capture.id,
                ip_address=ip,
                packet_count=edata["packet_count"],
                byte_count=edata["byte_count"],
                sent_packets=edata["sent_packets"],
                recv_packets=edata["recv_packets"],
                sent_bytes=edata["sent_bytes"],
                recv_bytes=edata["recv_bytes"],
                first_seen=edata["first_seen"] or 0.0,
                last_seen=edata["last_seen"] or 0.0,
                protocols_json=json.dumps(sorted(list(edata["protocols"]))),
                flows_count=0
            ))
        if endpoint_models:
            db.bulk_save_objects(endpoint_models)

        # 6. Analyze TCP Diagnostics
        tcp_findings = analyze_tcp_diagnostics(packets, flow_results)

        # 7. Scan and Anomaly Detection
        custom_thresholds = get_current_thresholds(db)
        scan_findings = detect_scan_and_anomalies(packets, flow_results, custom_thresholds)

        # 8. Persist Findings
        all_findings = tcp_findings + dns_findings + scan_findings
        finding_models = []
        for fd in all_findings:
            finding_models.append(Finding(
                id=fd["id"],
                capture_id=capture.id,
                category=fd["category"],
                severity=fd["severity"],
                confidence=fd["confidence"],
                title=fd["title"],
                observed_facts=fd["observed_facts"],
                supporting_packet_numbers_json=json.dumps(fd.get("supporting_packet_numbers", [])),
                timestamps_json=json.dumps(fd.get("timestamps", [])),
                endpoints_json=json.dumps(fd.get("endpoints", [])),
                ports_json=json.dumps(fd.get("ports", [])),
                rule_name=fd["rule_name"],
                threshold_val=str(fd["threshold_val"]),
                explanations=fd["explanations"],
                recommendations=fd["recommendations"],
                limitations=fd["limitations"]
            ))
        if finding_models:
            db.bulk_save_objects(finding_models)

        # TCP Stats
        tcp_flows = [f for f in flow_results if f["protocol"] == "TCP"]
        tcp_stats = {
            "total_tcp_flows": len(tcp_flows),
            "established_flows": sum(1 for f in tcp_flows if f["state"] == "ESTABLISHED"),
            "completed_handshakes": sum(1 for f in tcp_flows if f["state"] in ("ESTABLISHED", "CLOSED_CLEAN")),
            "incomplete_handshakes": sum(1 for f in tcp_flows if f["state"] == "INCOMPLETE_HANDSHAKE"),
            "resets_observed": sum(1 for f in tcp_flows if f["state"] == "RESET"),
            "clean_closes": sum(1 for f in tcp_flows if f["state"] == "CLOSED_CLEAN"),
        }

        # DNS Stats
        dns_stats = {
            "total_dns_records": len(dns_records),
            "answered_queries": sum(1 for d in dns_records if d["is_answered"]),
            "unanswered_queries": sum(1 for d in dns_records if not d["is_answered"]),
            "nxdomain_count": sum(1 for d in dns_records if d["rcode"] == "NXDOMAIN"),
            "servfail_count": sum(1 for d in dns_records if d["rcode"] == "SERVFAIL"),
        }

        # Findings Aggregates
        findings_by_severity = defaultdict(int)
        findings_by_category = defaultdict(int)
        for fd in all_findings:
            findings_by_severity[fd["severity"]] += 1
            findings_by_category[fd["category"]] += 1

        # Top 10 endpoints & flows
        top_endpoints = sorted(
            [{"ip": ip, "packets": d["packet_count"], "bytes": d["byte_count"]} for ip, d in endpoints_data.items()],
            key=lambda x: x["bytes"], reverse=True
        )[:10]

        top_flows = sorted(
            [{
                "flow_id": f["flow_id"],
                "protocol": f["protocol"],
                "src": f"{f['src_ip']}:{f['src_port']}" if f.get("src_port") else f['src_ip'],
                "dst": f"{f['dst_ip']}:{f['dst_port']}" if f.get("dst_port") else f['dst_ip'],
                "packets": f["packet_count"],
                "bytes": f["byte_count"],
                "state": f["state"],
                "duration": f["duration"]
            } for f in flow_results],
            key=lambda x: x["bytes"], reverse=True
        )[:10]

        # Compute Directional Traffic Over Time (for dual-shade throughput charts)
        dominant_ip = top_endpoints[0]["ip"] if top_endpoints else None
        interval = max(1.0, duration / 25) if duration > 25 else 1.0
        time_buckets = defaultdict(lambda: {"packets": 0, "bytes": 0, "sent": 0, "received": 0})
        for p in packets:
            b_idx = int((p.timestamp - start_time) / interval)
            time_buckets[b_idx]["packets"] += 1
            time_buckets[b_idx]["bytes"] += p.length
            if dominant_ip and p.src_ip == dominant_ip:
                time_buckets[b_idx]["sent"] += 1
            else:
                time_buckets[b_idx]["received"] += 1

        traffic_over_time = []
        num_buckets = max(1, int(duration / interval) + 1)
        for i in range(num_buckets):
            traffic_over_time.append({
                "time_offset": round(i * interval, 1),
                "packets": time_buckets[i]["packets"],
                "bytes": time_buckets[i]["bytes"],
                "sent": time_buckets[i]["sent"],
                "received": time_buckets[i]["received"]
            })

        # Recent findings preview for dashboard
        recent_findings = [
            {
                "id": f["id"],
                "category": f["category"],
                "severity": f["severity"],
                "title": f["title"],
                "rule_name": f["rule_name"],
                "packet_numbers": f.get("supporting_packet_numbers", [])[:5],
                "timestamp": f.get("timestamps", [0])[0] if f.get("timestamps") else 0
            }
            for f in all_findings[:8]
        ]

        topology_hints = {
            "l2_available": l2_available,
            "ip_macs": {ip: sorted(list(macs))[:50] for ip, macs in ip_macs_sets.items()},
            "mac_ips": {mac: sorted(list(ips))[:50] for mac, ips in mac_ips_sets.items()},
            "ip_ttls": dict(ip_ttls_data)
        }

        summary_meta = {
            "total_bytes": total_captured_bytes,
            "total_endpoints": len(endpoints_data),
            "protocol_counts": dict(protocol_counts),
            "protocol_bytes": dict(protocol_bytes),
            "traffic_over_time": traffic_over_time,
            "tcp_stats": tcp_stats,
            "dns_stats": dns_stats,
            "findings_by_severity": dict(findings_by_severity),
            "findings_by_category": dict(findings_by_category),
            "top_endpoints": top_endpoints,
            "top_flows": top_flows,
            "recent_findings": recent_findings,
            "topology_hints": topology_hints,
            "warnings": all_warnings[:20]
        }

        capture.status = "partial" if all_warnings else "completed"
        capture.packet_count = total_packet_count
        capture.start_time = start_time
        capture.end_time = end_time
        capture.duration_seconds = duration
        capture.metadata_json = json.dumps(summary_meta)
        db.commit()
        db.refresh(capture)
        return capture

    except Exception as e:
        logger.exception(f"Error analyzing capture {capture_id}: {e}")
        capture.status = "failed"
        capture.error_message = str(e)
        db.commit()
        db.refresh(capture)
        return capture
