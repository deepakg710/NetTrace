import uuid
from typing import List, Dict, Any, Tuple
from collections import defaultdict
from app.services.packet_parser import ParsedPacketData

def analyze_dns_activity(packets: List[ParsedPacketData]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Correlates DNS queries with responses and detects DNS diagnostic issues.
    Returns: (dns_records_list, findings_list)
    """
    dns_packets = [p for p in packets if "dns" in p.details]
    
    # Separate queries and responses
    queries: Dict[Tuple[str, str, str, str], List[ParsedPacketData]] = defaultdict(list)
    responses: Dict[Tuple[str, str, str, str], List[ParsedPacketData]] = defaultdict(list)

    for p in dns_packets:
        dns_info = p.details["dns"]
        tx_id = dns_info["id"]
        q_list = dns_info.get("queries", [])
        qname = q_list[0]["name"] if q_list else "unknown"
        
        if dns_info["is_response"]:
            # In response: src is server, dst is client
            key = (tx_id, p.dst_ip, p.src_ip, qname)
            responses[key].append(p)
        else:
            # In query: src is client, dst is server
            key = (tx_id, p.src_ip, p.dst_ip, qname)
            queries[key].append(p)

    dns_records: List[Dict[str, Any]] = []
    findings: List[Dict[str, Any]] = []

    # Correlate
    matched_responses = set()

    for key, q_pkts in queries.items():
        tx_id, client_ip, server_ip, qname = key
        resp_pkts = responses.get(key, [])
        
        for i, q_pkt in enumerate(q_pkts):
            resp_pkt = resp_pkts[i] if i < len(resp_pkts) else None
            
            if resp_pkt:
                matched_responses.add((resp_pkt.packet_number))
                dns_resp_info = resp_pkt.details["dns"]
                rcode = dns_resp_info["rcode"]
                latency_ms = round(max(0.0, (resp_pkt.timestamp - q_pkt.timestamp) * 1000), 2)
                answers = dns_resp_info.get("answers", [])
                
                dns_records.append({
                    "transaction_id": tx_id,
                    "query_name": qname,
                    "query_type": q_pkt.details["dns"]["queries"][0]["type"] if q_pkt.details["dns"].get("queries") else "A",
                    "client_ip": client_ip,
                    "server_ip": server_ip,
                    "query_time": q_pkt.timestamp,
                    "response_time": resp_pkt.timestamp,
                    "rcode": rcode,
                    "is_answered": True,
                    "latency_ms": latency_ms,
                    "query_packet_number": q_pkt.packet_number,
                    "response_packet_number": resp_pkt.packet_number,
                    "answers": answers
                })
            else:
                dns_records.append({
                    "transaction_id": tx_id,
                    "query_name": qname,
                    "query_type": q_pkt.details["dns"]["queries"][0]["type"] if q_pkt.details["dns"].get("queries") else "A",
                    "client_ip": client_ip,
                    "server_ip": server_ip,
                    "query_time": q_pkt.timestamp,
                    "response_time": None,
                    "rcode": "UNANSWERED",
                    "is_answered": False,
                    "latency_ms": None,
                    "query_packet_number": q_pkt.packet_number,
                    "response_packet_number": None,
                    "answers": []
                })

    # Add orphan responses if any
    for key, r_pkts in responses.items():
        for r_pkt in r_pkts:
            if r_pkt.packet_number not in matched_responses:
                dns_resp_info = r_pkt.details["dns"]
                qname = dns_resp_info.get("queries", [{}])[0].get("name", "unknown")
                dns_records.append({
                    "transaction_id": dns_resp_info["id"],
                    "query_name": qname,
                    "query_type": dns_resp_info["queries"][0]["type"] if dns_resp_info.get("queries") else "A",
                    "client_ip": r_pkt.dst_ip,
                    "server_ip": r_pkt.src_ip,
                    "query_time": r_pkt.timestamp,
                    "response_time": r_pkt.timestamp,
                    "rcode": dns_resp_info["rcode"],
                    "is_answered": True,
                    "latency_ms": 0.0,
                    "query_packet_number": r_pkt.packet_number,
                    "response_packet_number": r_pkt.packet_number,
                    "answers": dns_resp_info.get("answers", [])
                })

    # Diagnostic Findings Generation

    # 1. NXDOMAIN findings
    nxdomains = [r for r in dns_records if r["rcode"] == "NXDOMAIN"]
    if nxdomains:
        nx_by_domain = defaultdict(list)
        for r in nxdomains:
            nx_by_domain[r["query_name"]].append(r)

        for dname, recs in nx_by_domain.items():
            query_pkts = [r["query_packet_number"] for r in recs]
            resp_pkts = [r["response_packet_number"] for r in recs if r["response_packet_number"]]
            all_pkts = sorted(list(set(query_pkts + resp_pkts)))
            client_ips = list(set(r["client_ip"] for r in recs))
            server_ips = list(set(r["server_ip"] for r in recs))

            findings.append({
                "id": uuid.uuid4().hex,
                "category": "DNS",
                "severity": "Low",
                "confidence": "High",
                "title": f"DNS Non-Existent Domain (NXDOMAIN): '{dname}' ({len(recs)} occurrence{'s' if len(recs)>1 else ''})",
                "observed_facts": (
                    f"DNS server ({', '.join(server_ips)}) returned authoritative NXDOMAIN (RCODE 3) for domain '{dname}' "
                    f"requested by {', '.join(client_ips)}. Evidence packets: {all_pkts[:10]}."
                ),
                "supporting_packet_numbers": all_pkts[:15],
                "timestamps": [r["query_time"] for r in recs][:15],
                "endpoints": client_ips + server_ips,
                "ports": [53],
                "rule_name": "DNS_NXDOMAIN_OBSERVED",
                "threshold_val": f"NXDOMAIN response count = {len(recs)}",
                "explanations": (
                    "Possible explanations: (1) Typo in host/service configuration or application URI; "
                    "(2) Decommissioned internal hostname or stale local search domain suffix; "
                    "(3) Malware attempting domain generation algorithm (DGA) lookups (only if accompanied by suspicious automated patterns)."
                ),
                "recommendations": (
                    f"Check configuration files on host {client_ips[0]} referencing '{dname}'. "
                    "Verify internal DNS search suffix and split-horizon DNS resolver configuration."
                ),
                "limitations": (
                    "NXDOMAIN is an authoritative protocol response confirming the record does not exist in the zone. "
                    "It is not evidence of malicious intent on its own."
                )
            })

    # 2. SERVFAIL findings
    servfails = [r for r in dns_records if r["rcode"] == "SERVFAIL"]
    if servfails:
        sf_by_domain = defaultdict(list)
        for r in servfails:
            sf_by_domain[r["query_name"]].append(r)

        for dname, recs in sf_by_domain.items():
            all_pkts = sorted(list(set([r["query_packet_number"] for r in recs] + [r["response_packet_number"] for r in recs if r["response_packet_number"]])))
            findings.append({
                "id": uuid.uuid4().hex,
                "category": "DNS",
                "severity": "Medium",
                "confidence": "High",
                "title": f"DNS Server Failure (SERVFAIL): '{dname}' ({len(recs)} occurrence{'s' if len(recs)>1 else ''})",
                "observed_facts": (
                    f"DNS resolver returned SERVFAIL (RCODE 2) when resolving '{dname}'. "
                    f"Packets: {all_pkts[:10]}."
                ),
                "supporting_packet_numbers": all_pkts[:15],
                "timestamps": [r["query_time"] for r in recs][:15],
                "endpoints": list(set([r["client_ip"] for r in recs] + [r["server_ip"] for r in recs])),
                "ports": [53],
                "rule_name": "DNS_SERVFAIL_OBSERVED",
                "threshold_val": f"SERVFAIL count = {len(recs)}",
                "explanations": (
                    "Possible explanations: (1) Upstream recursive DNS resolver failure or timeout; "
                    "(2) DNSSEC validation failure on authoritative domain records; "
                    "(3) Broken zone delegation or unreachable authoritative nameservers."
                ),
                "recommendations": (
                    "Check DNSSEC validation status using `delv` or `dig +dnssec`. "
                    "Verify network connectivity between the recursive resolver and authoritative nameservers."
                ),
                "limitations": (
                    "SERVFAIL indicates resolver-side or delegation failure, not a negative record answer."
                )
            })

    # 3. Unanswered DNS Queries
    unanswered = [r for r in dns_records if not r["is_answered"]]
    if unanswered:
        unans_by_server = defaultdict(list)
        for r in unanswered:
            unans_by_server[(r["client_ip"], r["server_ip"])].append(r)

        for (client, srv), recs in unans_by_server.items():
            pkts = [r["query_packet_number"] for r in recs]
            dnames = list(set(r["query_name"] for r in recs))
            findings.append({
                "id": uuid.uuid4().hex,
                "category": "DNS",
                "severity": "Medium" if len(recs) >= 3 else "Low",
                "confidence": "Medium",
                "title": f"Unanswered DNS Queries: {client} \u2192 {srv} ({len(recs)} query candidate{'s' if len(recs)>1 else ''})",
                "observed_facts": (
                    f"Client {client} sent {len(recs)} DNS query packet(s) to server {srv} "
                    f"for domain(s) ({', '.join(dnames[:3])}) with no corresponding response packet observed in the capture. "
                    f"Evidence packets: {pkts[:10]}."
                ),
                "supporting_packet_numbers": pkts[:15],
                "timestamps": [r["query_time"] for r in recs][:15],
                "endpoints": [client, srv],
                "ports": [53],
                "rule_name": "DNS_UNANSWERED_QUERY",
                "threshold_val": f"Unanswered query count = {len(recs)}",
                "explanations": (
                    "Possible explanations: (1) DNS server {srv} is unreachable or offline; "
                    "(2) UDP port 53 traffic is blocked by a local or egress firewall; "
                    "(3) Packet capture stopped before the DNS response packet was transmitted; "
                    "(4) Capture filter or network interface only captured outgoing traffic."
                ),
                "recommendations": (
                    f"Verify basic IP reachability to DNS server {srv} with ping/traceroute. "
                    f"Test DNS resolution with `nslookup example.com {srv}`. "
                    "Confirm if UDP 53 egress rules are permitted in network security groups."
                ),
                "limitations": (
                    "Do not assume that a missing response means the DNS server is down. "
                    "Capture filters, asymmetric routing, or short observation windows can easily miss responses."
                )
            })

    return dns_records, findings
