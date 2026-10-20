import json
import ipaddress
from typing import Dict, Any, List, Optional, Set
from collections import defaultdict
from sqlalchemy.orm import Session

from app.models.models import Capture, Endpoint, Flow, DNSRecord, Finding
from app.schemas.schemas import (
    TopologyResponse,
    TopologyNodeSchema,
    TopologyEdgeSchema,
    TopologyRoleSchema,
    TopologyHopEstimateSchema,
)

SEVERITY_RANK = {
    "Critical": 5,
    "High": 4,
    "Medium": 3,
    "Low": 2,
    "Informational": 1,
}

RELIABLE_SCAN_RULES = {"PORT_SCAN_HEURISTIC", "HOST_SCAN_HEURISTIC"}


def classify_ip_scope(ip_str: str) -> str:
    try:
        addr = ipaddress.ip_address(ip_str)
        if addr.is_multicast:
            return "multicast"
        if addr.is_private or addr.is_link_local or addr.is_loopback:
            return "local"
        if addr.is_global:
            return "remote"
        return "unknown"
    except ValueError:
        return "unknown"


def derive_node_classification(kind: str, scope: str, roles: List[TopologyRoleSchema]) -> str:
    if kind == "inferred_gateway":
        return "Inferred Gateway"
    role_names = {r.role for r in roles}
    if "gateway" in role_names:
        return "Gateway (Inferred)"
    if "dns_server" in role_names:
        return "Public DNS Server" if scope == "remote" else "DNS Server"
    if "scanner" in role_names:
        return "Scanner Host (Inferred)"
    if "scan_target" in role_names:
        return "Target Server (Inferred)"
    if "dns_client" in role_names:
        return "Local Client" if scope == "local" else "DNS Client"
    if scope == "local":
        return "Private Host"
    if scope == "remote":
        return "Remote Host"
    if scope == "multicast":
        return "Multicast Group"
    return "Observed Endpoint"


def compute_hop_estimate(ttl_entry: Dict[str, int]) -> Optional[TopologyHopEstimateSchema]:
    if not ttl_entry or "max" not in ttl_entry:
        return None
    max_ttl = int(ttl_entry["max"])
    if max_ttl <= 0:
        return None
    candidates = [x for x in (64, 128, 255) if x >= max_ttl]
    assumed_initial = min(candidates) if candidates else 255
    hops = max(0, assumed_initial - max_ttl)
    return TopologyHopEstimateSchema(
        hops=hops,
        observed_ttl=max_ttl,
        assumed_initial_ttl=assumed_initial,
        inferred=True,
        basis=f"Initial TTL assumed to be the smallest of 64/128/255 >= observed max TTL ({max_ttl})",
    )


def build_topology_from_records(
    capture_id: str,
    meta: Dict[str, Any],
    endpoints: List[Endpoint],
    flows: List[Flow],
    dns_records: List[DNSRecord],
    findings: List[Finding],
    max_nodes: int = 150,
    protocol_filter: Optional[str] = None,
    findings_only: bool = False,
) -> TopologyResponse:
    notes: List[str] = []
    hints = meta.get("topology_hints")
    hints_available = isinstance(hints, dict)
    l2_available = bool(hints.get("l2_available", False)) if hints_available else False
    ip_macs: Dict[str, List[str]] = hints.get("ip_macs", {}) if hints_available else {}
    mac_ips: Dict[str, List[str]] = hints.get("mac_ips", {}) if hints_available else {}
    ip_ttls: Dict[str, Dict[str, int]] = hints.get("ip_ttls", {}) if hints_available else {}

    if not hints_available:
        notes.append(
            "Topology hints (MAC/TTL) were not recorded when this capture was originally analyzed. "
            "Re-analyze this capture to enable Layer 2 and TTL inference."
        )
    elif not l2_available:
        notes.append("No Ethernet layer in this capture; MAC-based gateway inference unavailable.")

    # 1. DNS server/client counts
    dns_server_counts: Dict[str, int] = defaultdict(int)
    dns_client_counts: Dict[str, int] = defaultdict(int)
    for d in dns_records:
        if d.server_ip and d.server_ip != "unknown":
            dns_server_counts[d.server_ip] += 1
        if d.client_ip and d.client_ip != "unknown":
            dns_client_counts[d.client_ip] += 1

    # 2. Findings mapping per IP and per IP-pair
    ip_findings: Dict[str, List[Finding]] = defaultdict(list)
    ip_scan_roles: Dict[str, List[TopologyRoleSchema]] = defaultdict(list)
    parsed_findings: List[Dict[str, Any]] = []

    for f in findings:
        try:
            f_eps = json.loads(f.endpoints_json or "[]")
        except Exception:
            f_eps = []
        parsed_findings.append({"model": f, "endpoints": f_eps, "endpoints_set": set(f_eps)})

        for ip in f_eps:
            ip_findings[ip].append(f)

        if f.rule_name in RELIABLE_SCAN_RULES and len(f_eps) >= 1:
            scanner_ip = f_eps[0]
            ip_scan_roles[scanner_ip].append(
                TopologyRoleSchema(
                    role="scanner",
                    inferred=True,
                    basis=f.title,
                )
            )
            for target_ip in f_eps[1:]:
                ip_scan_roles[target_ip].append(
                    TopologyRoleSchema(
                        role="scan_target",
                        inferred=True,
                        basis=f.title,
                    )
                )

    # 3. Build host nodes from Endpoint rows
    nodes_map: Dict[str, TopologyNodeSchema] = {}
    for ep in endpoints:
        ip = ep.ip_address
        try:
            protos = json.loads(ep.protocols_json or "[]")
        except Exception:
            protos = []

        scope = classify_ip_scope(ip)
        macs = ip_macs.get(ip, [])
        hop_est = compute_hop_estimate(ip_ttls.get(ip, {}))

        roles: List[TopologyRoleSchema] = []
        seen_roles = set()

        if ip in dns_server_counts:
            c = dns_server_counts[ip]
            roles.append(
                TopologyRoleSchema(
                    role="dns_server",
                    inferred=False,
                    basis=f"Appears as server_ip in {c} DNS transaction{'s' if c != 1 else ''}",
                )
            )
            seen_roles.add("dns_server")

        if ip in dns_client_counts:
            c = dns_client_counts[ip]
            roles.append(
                TopologyRoleSchema(
                    role="dns_client",
                    inferred=False,
                    basis=f"Appears as client_ip in {c} DNS transaction{'s' if c != 1 else ''}",
                )
            )
            seen_roles.add("dns_client")

        for sr in ip_scan_roles.get(ip, []):
            if sr.role not in seen_roles:
                roles.append(sr)
                seen_roles.add(sr.role)

        ep_finding_models = ip_findings.get(ip, [])
        f_ids = [fm.id for fm in ep_finding_models]

        if ep_finding_models and not ("scanner" in seen_roles or "scan_target" in seen_roles):
            roles.append(
                TopologyRoleSchema(
                    role="involved_in_finding",
                    inferred=False,
                    basis=f"Referenced in {len(ep_finding_models)} diagnostic finding{'s' if len(ep_finding_models) != 1 else ''} ({ep_finding_models[0].title})",
                )
            )
            seen_roles.add("involved_in_finding")

        max_sev: Optional[str] = None
        if ep_finding_models:
            max_sev = max(
                (fm.severity for fm in ep_finding_models),
                key=lambda s: SEVERITY_RANK.get(s, 0),
            )

        classification = derive_node_classification("host", scope, roles)

        nodes_map[ip] = TopologyNodeSchema(
            id=ip,
            kind="host",
            scope=scope,
            classification=classification,
            packets=ep.packet_count,
            bytes=ep.byte_count,
            sent_packets=ep.sent_packets or 0,
            recv_packets=ep.recv_packets or 0,
            sent_bytes=ep.sent_bytes or 0,
            recv_bytes=ep.recv_bytes or 0,
            first_seen=ep.first_seen,
            last_seen=ep.last_seen,
            flows_count=ep.flows_count or 0,
            distinct_peers=0,
            protocols=protos,
            macs=macs,
            roles=roles,
            hop_estimate=hop_est,
            finding_ids=f_ids,
            max_severity=max_sev,
        )

    if hints_available and not ip_ttls and len(nodes_map) > 0:
        notes.append("No IPv4 TTL values observed; hop distance estimation unavailable.")

    # 4. Build observed edges from Flow rows grouped by unordered IP pair
    pair_flows: Dict[tuple, List[Flow]] = defaultdict(list)
    peer_sets: Dict[str, Set[str]] = defaultdict(set)
    ip_flow_counts: Dict[str, int] = defaultdict(int)

    for fl in flows:
        if not fl.src_ip or not fl.dst_ip or fl.src_ip == "unknown" or fl.dst_ip == "unknown":
            continue
        if fl.src_ip not in nodes_map or fl.dst_ip not in nodes_map:
            continue
        pair = tuple(sorted([fl.src_ip, fl.dst_ip]))
        pair_flows[pair].append(fl)
        peer_sets[fl.src_ip].add(fl.dst_ip)
        peer_sets[fl.dst_ip].add(fl.src_ip)
        ip_flow_counts[fl.src_ip] += 1
        if fl.dst_ip != fl.src_ip:
            ip_flow_counts[fl.dst_ip] += 1

    for ip, peers in peer_sets.items():
        if ip in nodes_map:
            nodes_map[ip].distinct_peers = len(peers)
            nodes_map[ip].flows_count = max(nodes_map[ip].flows_count, ip_flow_counts[ip])

    edges_list: List[TopologyEdgeSchema] = []
    for (ip1, ip2), fl_list in pair_flows.items():
        edge_id = f"{ip1}|{ip2}"
        protos_set = set()
        ports_set = set()
        states_count: Dict[str, int] = defaultdict(int)
        total_pkts = 0
        total_bytes = 0

        # Track directionality relative to sorted (source=ip1, target=ip2)
        s_to_t_pkts = 0
        t_to_s_pkts = 0
        s_to_t_bytes = 0
        t_to_s_bytes = 0
        init_counts: Dict[str, int] = defaultdict(int)
        edge_first_seen: Optional[float] = None
        edge_last_seen: Optional[float] = None
        sample_pkts: List[int] = []
        seen_sample_pkts: Set[int] = set()

        for fl in fl_list:
            if fl.protocol:
                protos_set.add(fl.protocol)
            if fl.dst_port is not None:
                ports_set.add(int(fl.dst_port))
            states_count[fl.state] += 1
            total_pkts += fl.packet_count
            total_bytes += fl.byte_count
            init_counts[fl.src_ip] += 1

            if fl.src_ip == ip1:
                s_to_t_pkts += fl.src_to_dst_packets or 0
                t_to_s_pkts += fl.dst_to_src_packets or 0
                s_to_t_bytes += fl.src_to_dst_bytes or 0
                t_to_s_bytes += fl.dst_to_src_bytes or 0
            else:
                t_to_s_pkts += fl.src_to_dst_packets or 0
                s_to_t_pkts += fl.dst_to_src_packets or 0
                t_to_s_bytes += fl.src_to_dst_bytes or 0
                s_to_t_bytes += fl.dst_to_src_bytes or 0

            if fl.start_time is not None:
                if edge_first_seen is None or fl.start_time < edge_first_seen:
                    edge_first_seen = fl.start_time
            if fl.end_time is not None:
                if edge_last_seen is None or fl.end_time > edge_last_seen:
                    edge_last_seen = fl.end_time

            try:
                det = json.loads(fl.details_json or "{}")
            except Exception:
                det = {}
            for k in ("syn_packet", "syn_ack_packet", "rst_packet"):
                val = det.get(k)
                if isinstance(val, int) and val > 0 and val not in seen_sample_pkts:
                    seen_sample_pkts.add(val)
                    sample_pkts.append(val)
            for t_item in det.get("timeline", [])[:5]:
                pnum = t_item.get("packet_number") if isinstance(t_item, dict) else None
                if isinstance(pnum, int) and pnum > 0 and pnum not in seen_sample_pkts:
                    seen_sample_pkts.add(pnum)
                    sample_pkts.append(pnum)

        initiator_ip = ip1 if init_counts[ip1] >= init_counts[ip2] else ip2
        responder_ip = ip2 if initiator_ip == ip1 else ip1
        bidirectional = s_to_t_pkts > 0 and t_to_s_pkts > 0

        # Finding <-> edge link: finding's endpoints_json must contain BOTH ip1 and ip2
        edge_f_ids: List[str] = []
        has_scan_finding = False
        for pf in parsed_findings:
            eps_set = pf["endpoints_set"]
            if ip1 in eps_set and ip2 in eps_set:
                edge_f_ids.append(pf["model"].id)
                if pf["model"].category == "SCAN":
                    has_scan_finding = True

        # Status priority: reset -> incomplete -> scan -> normal
        if states_count.get("RESET", 0) > 0:
            status_str = "reset"
        elif states_count.get("INCOMPLETE_HANDSHAKE", 0) > 0:
            status_str = "incomplete"
        elif has_scan_finding:
            status_str = "scan"
        else:
            status_str = "normal"

        edges_list.append(
            TopologyEdgeSchema(
                id=edge_id,
                source=ip1,
                target=ip2,
                initiator=initiator_ip,
                responder=responder_ip,
                bidirectional=bidirectional,
                kind="observed",
                inferred=False,
                basis=None,
                protocols=sorted(list(protos_set)),
                ports=sorted(list(ports_set))[:20],
                flow_count=len(fl_list),
                packets=total_pkts,
                bytes=total_bytes,
                src_to_dst_packets=s_to_t_pkts,
                dst_to_src_packets=t_to_s_pkts,
                src_to_dst_bytes=s_to_t_bytes,
                dst_to_src_bytes=t_to_s_bytes,
                first_seen=edge_first_seen,
                last_seen=edge_last_seen,
                sample_packet_numbers=sorted(sample_pkts)[:12],
                states=dict(states_count),
                status=status_str,
                finding_ids=edge_f_ids,
            )
        )

    # 5. Gateway inference (only if l2_available)
    if l2_available and mac_ips:
        for mac, mapped_ips in mac_ips.items():
            valid_ips = [ip for ip in mapped_ips if ip in nodes_map]
            if len(valid_ips) >= 3:
                remote_ips = [ip for ip in valid_ips if nodes_map[ip].scope == "remote"]
                local_ips = [ip for ip in valid_ips if nodes_map[ip].scope == "local"]
                if len(remote_ips) >= 1:
                    basis_text = (
                        f"MAC {mac} carried traffic for {len(valid_ips)} distinct IPs "
                        f"including {len(remote_ips)} remote address{'es' if len(remote_ips) != 1 else ''}"
                    )
                    # Check if a single local IP node owns this MAC alone (e.g. router LAN IP)
                    local_owners = [
                        ip for ip in local_ips if ip_macs.get(ip) == [mac]
                    ]
                    if len(local_owners) == 1:
                        gw_ip = local_owners[0]
                        existing_roles = {r.role for r in nodes_map[gw_ip].roles}
                        if "gateway" not in existing_roles:
                            nodes_map[gw_ip].roles.append(
                                TopologyRoleSchema(
                                    role="gateway",
                                    inferred=True,
                                    basis=basis_text,
                                )
                            )
                            nodes_map[gw_ip].classification = derive_node_classification(
                                nodes_map[gw_ip].kind,
                                nodes_map[gw_ip].scope,
                                nodes_map[gw_ip].roles,
                            )
                    else:
                        gw_id = f"gw:{mac}"
                        all_local_hosts = [
                            ip for ip, n in nodes_map.items()
                            if n.kind == "host" and n.scope == "local"
                        ]
                        nodes_map[gw_id] = TopologyNodeSchema(
                            id=gw_id,
                            kind="inferred_gateway",
                            scope="local",
                            classification="Inferred Gateway",
                            packets=0,
                            bytes=0,
                            sent_packets=0,
                            recv_packets=0,
                            sent_bytes=0,
                            recv_bytes=0,
                            first_seen=None,
                            last_seen=None,
                            flows_count=0,
                            distinct_peers=len(all_local_hosts) + len(remote_ips),
                            protocols=[],
                            macs=[mac],
                            roles=[
                                TopologyRoleSchema(
                                    role="gateway",
                                    inferred=True,
                                    basis=basis_text,
                                )
                            ],
                            hop_estimate=None,
                            finding_ids=[],
                            max_severity=None,
                        )
                        for l_ip in all_local_hosts:
                            s_ip, t_ip = sorted([l_ip, gw_id])
                            edges_list.append(
                                TopologyEdgeSchema(
                                    id=f"{s_ip}|{t_ip}",
                                    source=s_ip,
                                    target=t_ip,
                                    initiator=l_ip,
                                    responder=gw_id,
                                    bidirectional=False,
                                    kind="inferred_l2",
                                    inferred=True,
                                    basis=basis_text,
                                    protocols=[],
                                    ports=[],
                                    flow_count=0,
                                    packets=0,
                                    bytes=0,
                                    states={},
                                    status="normal",
                                    finding_ids=[],
                                )
                            )
                        for r_ip in remote_ips:
                            s_ip, t_ip = sorted([gw_id, r_ip])
                            edges_list.append(
                                TopologyEdgeSchema(
                                    id=f"{s_ip}|{t_ip}",
                                    source=s_ip,
                                    target=t_ip,
                                    initiator=gw_id,
                                    responder=r_ip,
                                    bidirectional=False,
                                    kind="inferred_l2",
                                    inferred=True,
                                    basis=basis_text,
                                    protocols=[],
                                    ports=[],
                                    flow_count=0,
                                    packets=0,
                                    bytes=0,
                                    states={},
                                    status="normal",
                                    finding_ids=[],
                                )
                            )

    all_nodes = list(nodes_map.values())

    # 6. Apply Filters (protocol, findings_only)
    if protocol_filter:
        pf_lower = protocol_filter.strip().lower()
        edges_list = [
            e for e in edges_list
            if any(pf_lower in p.lower() for p in e.protocols)
        ]
        connected_ids = set()
        for e in edges_list:
            connected_ids.add(e.source)
            connected_ids.add(e.target)
        all_nodes = [n for n in all_nodes if n.id in connected_ids]

    if findings_only:
        all_nodes = [n for n in all_nodes if len(n.finding_ids) > 0]
        kept_ids = {n.id for n in all_nodes}
        edges_list = [
            e for e in edges_list
            if e.source in kept_ids and e.target in kept_ids
        ]

    # 7. Apply Truncation (sort by bytes desc, always keep nodes with findings first)
    total_nodes = len(all_nodes)
    truncated = False
    omitted_nodes = 0

    all_nodes.sort(key=lambda n: (1 if len(n.finding_ids) > 0 else 0, n.bytes), reverse=True)

    if total_nodes > max_nodes:
        truncated = True
        omitted_nodes = total_nodes - max_nodes
        all_nodes = all_nodes[:max_nodes]
        kept_ids = {n.id for n in all_nodes}
        edges_list = [
            e for e in edges_list
            if e.source in kept_ids and e.target in kept_ids
        ]
        notes.append(
            f"Topology truncated to {max_nodes} nodes (omitted {omitted_nodes} lower-volume endpoints)."
        )

    total_capture_packets = int(meta.get("total_packets") or sum(ep.sent_packets for ep in endpoints) or sum(ep.packet_count for ep in endpoints))
    total_capture_bytes = int(meta.get("total_bytes") or sum(ep.sent_bytes for ep in endpoints) or sum(ep.byte_count for ep in endpoints))

    proto_pkts: Dict[str, int] = defaultdict(int)
    proto_bytes: Dict[str, int] = defaultdict(int)
    if not protocol_filter and not findings_only and isinstance(meta.get("protocol_counts"), dict) and meta.get("protocol_counts"):
        for k, v in meta["protocol_counts"].items():
            proto_pkts[str(k)] += int(v or 0)
        for k, v in (meta.get("protocol_bytes") or {}).items():
            proto_bytes[str(k)] += int(v or 0)
    else:
        for e in edges_list:
            if e.kind == "inferred_l2" or e.inferred:
                continue
            primary_proto = e.protocols[0] if e.protocols else "IP"
            proto_pkts[primary_proto] += int(e.packets or 0)
            proto_bytes[primary_proto] += int(e.bytes or 0)

    return TopologyResponse(
        capture_id=capture_id,
        hints_available=hints_available,
        l2_available=l2_available,
        truncated=truncated,
        total_nodes=total_nodes,
        omitted_nodes=omitted_nodes,
        total_flows=len(flows),
        total_packets=total_capture_packets,
        total_bytes=total_capture_bytes,
        protocol_packets=dict(proto_pkts),
        protocol_bytes=dict(proto_bytes),
        nodes=all_nodes,
        edges=edges_list,
        notes=notes,
    )


def get_capture_topology(
    db: Session,
    capture: Capture,
    max_nodes: int = 150,
    protocol: Optional[str] = None,
    findings_only: bool = False,
) -> TopologyResponse:
    try:
        meta = json.loads(capture.metadata_json or "{}")
    except Exception:
        meta = {}
    if "total_packets" not in meta and capture.packet_count:
        meta["total_packets"] = capture.packet_count

    endpoints = db.query(Endpoint).filter(Endpoint.capture_id == capture.id).all()
    flows = db.query(Flow).filter(Flow.capture_id == capture.id).all()
    dns_records = db.query(DNSRecord).filter(DNSRecord.capture_id == capture.id).all()
    findings = db.query(Finding).filter(Finding.capture_id == capture.id).all()

    return build_topology_from_records(
        capture_id=capture.id,
        meta=meta,
        endpoints=endpoints,
        flows=flows,
        dns_records=dns_records,
        findings=findings,
        max_nodes=max_nodes,
        protocol_filter=protocol,
        findings_only=findings_only,
    )
