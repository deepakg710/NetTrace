import csv
import io
import json
from typing import Optional, List, Dict
from fastapi import APIRouter, Depends, Query, HTTPException, status, Response
from sqlalchemy.orm import Session
from sqlalchemy import or_, and_

from app.database.session import get_db
from app.models.models import Capture, Packet, Flow, Endpoint, DNSRecord, Finding
from app.schemas.schemas import (
    PacketSchema, PacketListResponse,
    PacketFacetItem, PortFacetItem, PacketFacetsResponse,
    FilterValidationResponse,
    FlowSchema, FlowListResponse,
    EndpointSchema,
    DNSItemSchema, DNSListResponse,
    TopologyResponse
)
from app.services.topology_service import get_capture_topology
from app.services.display_filter import (
    parse_display_filter,
    compile_to_sqlalchemy,
    evaluate_packet_dict,
    DisplayFilterError,
)

WELL_KNOWN_PORTS = {
    20: "FTP-Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP-Server",
    68: "DHCP-Client",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
}

router = APIRouter(prefix="/captures/{capture_id}", tags=["Analyses"])


@router.get("/filter-validate", response_model=FilterValidationResponse)
def validate_display_filter_endpoint(
    capture_id: str,
    expr: str = Query(""),
):
    cleaned = expr.strip()
    if not cleaned:
        return FilterValidationResponse(valid=True, expression="")
    try:
        parse_display_filter(cleaned)
        return FilterValidationResponse(valid=True, expression=cleaned)
    except DisplayFilterError as err:
        return FilterValidationResponse(
            valid=False,
            expression=cleaned,
            error=err.message,
            position=err.position,
        )


@router.get("/packets-facets", response_model=PacketFacetsResponse)
def get_packet_facets(capture_id: str, db: Session = Depends(get_db)):
    packets = db.query(
        Packet.protocol,
        Packet.src_ip,
        Packet.dst_ip,
        Packet.src_port,
        Packet.dst_port,
        Packet.tcp_flags,
        Packet.length
    ).filter(Packet.capture_id == capture_id).all()

    proto_counts = {}
    ip_counts = {}
    port_counts = {}
    flag_counts = {}
    min_len = 0
    max_len = 0
    rst_count = 0
    syn_only_count = 0

    for idx, p in enumerate(packets):
        if p.protocol:
            proto_counts[p.protocol] = proto_counts.get(p.protocol, 0) + 1
        if p.src_ip:
            ip_counts[p.src_ip] = ip_counts.get(p.src_ip, 0) + 1
        if p.dst_ip and p.dst_ip != p.src_ip:
            ip_counts[p.dst_ip] = ip_counts.get(p.dst_ip, 0) + 1
        elif p.dst_ip and not p.src_ip:
            ip_counts[p.dst_ip] = ip_counts.get(p.dst_ip, 0) + 1
        if p.src_port is not None:
            port_counts[p.src_port] = port_counts.get(p.src_port, 0) + 1
        if p.dst_port is not None and p.dst_port != p.src_port:
            port_counts[p.dst_port] = port_counts.get(p.dst_port, 0) + 1
        if p.tcp_flags:
            flag_counts[p.tcp_flags] = flag_counts.get(p.tcp_flags, 0) + 1
            if "RST" in p.tcp_flags:
                rst_count += 1
            if p.tcp_flags.strip() == "SYN":
                syn_only_count += 1
        length_val = p.length or 0
        if idx == 0:
            min_len = length_val
            max_len = length_val
        else:
            if length_val < min_len:
                min_len = length_val
            if length_val > max_len:
                max_len = length_val

    protocols = [
        PacketFacetItem(value=k, count=v)
        for k, v in sorted(proto_counts.items(), key=lambda x: (-x[1], x[0]))
    ]
    ips = [
        PacketFacetItem(value=k, count=v)
        for k, v in sorted(ip_counts.items(), key=lambda x: (-x[1], x[0]))[:40]
    ]
    ports = [
        PortFacetItem(
            port=k,
            service=WELL_KNOWN_PORTS.get(k, "Custom / Ephemeral" if k >= 1024 else "System Port"),
            count=v
        )
        for k, v in sorted(port_counts.items(), key=lambda x: (-x[1], x[0]))[:40]
    ]
    tcp_flags = [
        PacketFacetItem(value=k, count=v)
        for k, v in sorted(flag_counts.items(), key=lambda x: (-x[1], x[0]))
    ]

    # Map packet numbers to findings for badge indicators & build evidence-backed guided suggestions
    findings = db.query(Finding).filter(Finding.capture_id == capture_id).all()
    finding_packets: Dict[str, List[Dict[str, str]]] = {}
    guided_suggestions: List[Dict[str, str]] = []

    for fd in findings:
        p_nums = json.loads(fd.supporting_packet_numbers_json or "[]")
        eps = json.loads(fd.endpoints_json or "[]")
        for pnum in p_nums:
            key = str(pnum)
            if key not in finding_packets:
                finding_packets[key] = []
            finding_packets[key].append({
                "id": fd.id,
                "title": fd.title,
                "severity": fd.severity,
                "category": fd.category,
            })
        if eps:
            guided_suggestions.append({
                "label": f"Investigate {fd.category}: {fd.title[:42]}",
                "filter": f"ip.addr == {eps[0]}",
                "reason": fd.observed_facts[:120],
            })

    if rst_count > 0:
        guided_suggestions.append({
            "label": f"Inspect {rst_count} TCP Reset frame(s)",
            "filter": "tcp.flags.reset == 1",
            "reason": f"Observed {rst_count} TCP RST packets indicating refused ports or aborted sessions.",
        })
    if proto_counts.get("DNS", 0) > 0:
        guided_suggestions.append({
            "label": f"Review {proto_counts['DNS']} DNS resolution packets",
            "filter": "dns",
            "reason": "Inspect domain name queries, response codes (NXDOMAIN/SERVFAIL), and latency.",
        })
    if ips:
        top_ip = ips[0]
        guided_suggestions.append({
            "label": f"Isolate top talker {top_ip.value} ({top_ip.count} pkts)",
            "filter": f"ip.addr == {top_ip.value}",
            "reason": f"Endpoint {top_ip.value} is involved in {top_ip.count} captured frames.",
        })

    return PacketFacetsResponse(
        capture_id=capture_id,
        total_packets=len(packets),
        protocols=protocols,
        ips=ips,
        ports=ports,
        tcp_flags=tcp_flags,
        min_length=min_len,
        max_length=max_len,
        finding_packets=finding_packets,
        guided_suggestions=guided_suggestions[:6],
    )


def _apply_packet_filters(
    query,
    display_filter: Optional[str] = None,
    protocol: Optional[str] = None,
    ip: Optional[str] = None,
    src_ip: Optional[str] = None,
    dst_ip: Optional[str] = None,
    exclude_ip: Optional[str] = None,
    port: Optional[int] = None,
    src_port: Optional[int] = None,
    dst_port: Optional[int] = None,
    packet_number: Optional[int] = None,
    tcp_flag: Optional[str] = None,
    min_length: Optional[int] = None,
    max_length: Optional[int] = None,
    peer_a: Optional[str] = None,
    peer_b: Optional[str] = None,
    search: Optional[str] = None,
):
    ast_node = None
    if display_filter and display_filter.strip():
        try:
            ast_node = parse_display_filter(display_filter.strip())
            sql_expr = compile_to_sqlalchemy(ast_node)
            query = query.filter(sql_expr)
        except DisplayFilterError as err:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=err.message,
            )

    if protocol:
        query = query.filter(Packet.protocol.ilike(f"%{protocol}%"))
    if ip:
        query = query.filter(or_(Packet.src_ip == ip, Packet.dst_ip == ip))
    if src_ip:
        query = query.filter(Packet.src_ip == src_ip)
    if dst_ip:
        query = query.filter(Packet.dst_ip == dst_ip)
    if exclude_ip:
        query = query.filter(
            and_(
                or_(Packet.src_ip.is_(None), Packet.src_ip != exclude_ip),
                or_(Packet.dst_ip.is_(None), Packet.dst_ip != exclude_ip)
            )
        )
    if peer_a and peer_b:
        query = query.filter(
            or_(
                and_(Packet.src_ip == peer_a, Packet.dst_ip == peer_b),
                and_(Packet.src_ip == peer_b, Packet.dst_ip == peer_a)
            )
        )
    if port is not None:
        query = query.filter(or_(Packet.src_port == port, Packet.dst_port == port))
    if src_port is not None:
        query = query.filter(Packet.src_port == src_port)
    if dst_port is not None:
        query = query.filter(Packet.dst_port == dst_port)
    if packet_number is not None:
        query = query.filter(Packet.packet_number == packet_number)
    if tcp_flag:
        query = query.filter(Packet.tcp_flags.ilike(f"%{tcp_flag}%"))
    if min_length is not None:
        query = query.filter(Packet.length >= min_length)
    if max_length is not None:
        query = query.filter(Packet.length <= max_length)
    if search:
        search_term = f"%{search}%"
        query = query.filter(
            or_(
                Packet.info.ilike(search_term),
                Packet.src_ip.ilike(search_term),
                Packet.dst_ip.ilike(search_term),
                Packet.protocol.ilike(search_term),
                Packet.details_json.ilike(search_term)
            )
        )
    return query, ast_node


@router.get("/packets", response_model=PacketListResponse)
def get_packets(
    capture_id: str,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    display_filter: Optional[str] = None,
    protocol: Optional[str] = None,
    ip: Optional[str] = None,
    src_ip: Optional[str] = None,
    dst_ip: Optional[str] = None,
    exclude_ip: Optional[str] = None,
    port: Optional[int] = None,
    src_port: Optional[int] = None,
    dst_port: Optional[int] = None,
    packet_number: Optional[int] = None,
    tcp_flag: Optional[str] = None,
    min_length: Optional[int] = None,
    max_length: Optional[int] = None,
    peer_a: Optional[str] = None,
    peer_b: Optional[str] = None,
    search: Optional[str] = None,
    sort_by: str = Query("packet_number"),
    sort_dir: str = Query("asc"),
    db: Session = Depends(get_db)
):
    base_query = db.query(Packet).filter(Packet.capture_id == capture_id)
    query, ast_node = _apply_packet_filters(
        base_query,
        display_filter=display_filter,
        protocol=protocol,
        ip=ip,
        src_ip=src_ip,
        dst_ip=dst_ip,
        exclude_ip=exclude_ip,
        port=port,
        src_port=src_port,
        dst_port=dst_port,
        packet_number=packet_number,
        tcp_flag=tcp_flag,
        min_length=min_length,
        max_length=max_length,
        peer_a=peer_a,
        peer_b=peer_b,
        search=search,
    )

    sort_col_map = {
        "packet_number": Packet.packet_number,
        "timestamp": Packet.timestamp,
        "rel_time": Packet.rel_time,
        "src_ip": Packet.src_ip,
        "dst_ip": Packet.dst_ip,
        "protocol": Packet.protocol,
        "length": Packet.length,
    }
    sort_col = sort_col_map.get(sort_by, Packet.packet_number)
    order_clause = sort_col.desc() if sort_dir.lower() == "desc" else sort_col.asc()
    ordered_query = query.order_by(order_clause, Packet.packet_number.asc())

    # If display_filter references deep JSON fields (like ip.ttl, tcp.seq, dns.qry.name),
    # verify exact match via evaluate_packet_dict so counts and rows are 100% accurate.
    needs_post_eval = bool(
        display_filter
        and any(k in display_filter.lower() for k in ("ip.ttl", "tcp.seq", "tcp.ack", "tcp.window", "dns.qry.name", "dns.rcode"))
    )

    if needs_post_eval and ast_node is not None:
        all_candidates = ordered_query.all()
        matched_records = [
            p for p in all_candidates
            if evaluate_packet_dict(ast_node, {
                "packet_number": p.packet_number,
                "timestamp": p.timestamp,
                "rel_time": p.rel_time,
                "src_ip": p.src_ip,
                "dst_ip": p.dst_ip,
                "src_port": p.src_port,
                "dst_port": p.dst_port,
                "protocol": p.protocol,
                "length": p.length,
                "tcp_flags": p.tcp_flags,
                "info": p.info,
                "details": p.details_json,
            })
        ]
        total = len(matched_records)
        offset = (page - 1) * page_size
        records = matched_records[offset : offset + page_size]
    else:
        total = ordered_query.count()
        offset = (page - 1) * page_size
        records = ordered_query.offset(offset).limit(page_size).all()

    total_pages = max(1, (total + page_size - 1) // page_size)

    items = [
        PacketSchema(
            id=p.id,
            packet_number=p.packet_number,
            timestamp=p.timestamp,
            rel_time=p.rel_time,
            src_ip=p.src_ip,
            dst_ip=p.dst_ip,
            src_port=p.src_port,
            dst_port=p.dst_port,
            protocol=p.protocol,
            length=p.length,
            original_length=p.original_length,
            tcp_flags=p.tcp_flags,
            info=p.info,
            details=json.loads(p.details_json or "{}")
        )
        for p in records
    ]

    return PacketListResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages
    )


@router.get("/packets-export")
def export_packets(
    capture_id: str,
    format: str = Query("csv", pattern="^(csv|json)$"),
    display_filter: Optional[str] = None,
    protocol: Optional[str] = None,
    ip: Optional[str] = None,
    src_ip: Optional[str] = None,
    dst_ip: Optional[str] = None,
    exclude_ip: Optional[str] = None,
    port: Optional[int] = None,
    src_port: Optional[int] = None,
    dst_port: Optional[int] = None,
    tcp_flag: Optional[str] = None,
    min_length: Optional[int] = None,
    max_length: Optional[int] = None,
    peer_a: Optional[str] = None,
    peer_b: Optional[str] = None,
    search: Optional[str] = None,
    packet_numbers: Optional[str] = None,
    db: Session = Depends(get_db)
):
    capture = db.query(Capture).filter(Capture.id == capture_id).first()
    if not capture:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Capture not found.")

    base_query = db.query(Packet).filter(Packet.capture_id == capture_id)
    query, ast_node = _apply_packet_filters(
        base_query,
        display_filter=display_filter,
        protocol=protocol,
        ip=ip,
        src_ip=src_ip,
        dst_ip=dst_ip,
        exclude_ip=exclude_ip,
        port=port,
        src_port=src_port,
        dst_port=dst_port,
        tcp_flag=tcp_flag,
        min_length=min_length,
        max_length=max_length,
        peer_a=peer_a,
        peer_b=peer_b,
        search=search,
    )

    if packet_numbers:
        try:
            nums = [int(x.strip()) for x in packet_numbers.split(",") if x.strip()]
            if nums:
                query = query.filter(Packet.packet_number.in_(nums))
        except ValueError:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid packet_numbers list.")

    records = query.order_by(Packet.packet_number.asc()).limit(5000).all()
    if ast_node is not None and display_filter:
        records = [
            p for p in records
            if evaluate_packet_dict(ast_node, {
                "packet_number": p.packet_number,
                "timestamp": p.timestamp,
                "rel_time": p.rel_time,
                "src_ip": p.src_ip,
                "dst_ip": p.dst_ip,
                "src_port": p.src_port,
                "dst_port": p.dst_port,
                "protocol": p.protocol,
                "length": p.length,
                "tcp_flags": p.tcp_flags,
                "info": p.info,
                "details": p.details_json,
            })
        ]

    if format == "json":
        payload = {
            "capture_id": capture.id,
            "original_filename": capture.original_filename,
            "display_filter": display_filter or "",
            "exported_packets": len(records),
            "packets": [
                {
                    "packet_number": p.packet_number,
                    "timestamp": p.timestamp,
                    "rel_time": p.rel_time,
                    "src_ip": p.src_ip,
                    "src_port": p.src_port,
                    "dst_ip": p.dst_ip,
                    "dst_port": p.dst_port,
                    "protocol": p.protocol,
                    "length": p.length,
                    "original_length": p.original_length,
                    "tcp_flags": p.tcp_flags,
                    "info": p.info,
                }
                for p in records
            ],
        }
        return Response(
            content=json.dumps(payload, indent=2),
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="packets_{capture.id[:8]}.json"'},
        )

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "packet_number",
        "timestamp",
        "rel_time",
        "src_ip",
        "src_port",
        "dst_ip",
        "dst_port",
        "protocol",
        "length",
        "original_length",
        "tcp_flags",
        "info",
    ])
    for p in records:
        writer.writerow([
            p.packet_number,
            p.timestamp,
            p.rel_time,
            p.src_ip or "",
            p.src_port if p.src_port is not None else "",
            p.dst_ip or "",
            p.dst_port if p.dst_port is not None else "",
            p.protocol or "",
            p.length,
            p.original_length,
            p.tcp_flags or "",
            p.info or "",
        ])

    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="packets_{capture.id[:8]}.csv"'},
    )

@router.get("/packets/{packet_number}", response_model=PacketSchema)
def get_packet_by_number(capture_id: str, packet_number: int, db: Session = Depends(get_db)):
    packet = db.query(Packet).filter(
        Packet.capture_id == capture_id,
        Packet.packet_number == packet_number
    ).first()
    if not packet:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Packet #{packet_number} not found.")

    return PacketSchema(
        id=packet.id,
        packet_number=packet.packet_number,
        timestamp=packet.timestamp,
        rel_time=packet.rel_time,
        src_ip=packet.src_ip,
        dst_ip=packet.dst_ip,
        src_port=packet.src_port,
        dst_port=packet.dst_port,
        protocol=packet.protocol,
        length=packet.length,
        original_length=packet.original_length,
        tcp_flags=packet.tcp_flags,
        info=packet.info,
        details=json.loads(packet.details_json or "{}")
    )

@router.get("/flows", response_model=FlowListResponse)
def get_flows(
    capture_id: str,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    protocol: Optional[str] = None,
    state: Optional[str] = None,
    ip: Optional[str] = None,
    db: Session = Depends(get_db)
):
    query = db.query(Flow).filter(Flow.capture_id == capture_id)

    if protocol:
        query = query.filter(Flow.protocol.ilike(f"%{protocol}%"))
    if state:
        query = query.filter(Flow.state == state)
    if ip:
        query = query.filter(or_(Flow.src_ip == ip, Flow.dst_ip == ip))

    total = query.count()
    offset = (page - 1) * page_size
    records = query.order_by(Flow.byte_count.desc()).offset(offset).limit(page_size).all()

    items = [
        FlowSchema(
            id=f.id,
            flow_id=f.flow_id,
            protocol=f.protocol,
            src_ip=f.src_ip,
            src_port=f.src_port,
            dst_ip=f.dst_ip,
            dst_port=f.dst_port,
            packet_count=f.packet_count,
            byte_count=f.byte_count,
            src_to_dst_packets=f.src_to_dst_packets,
            dst_to_src_packets=f.dst_to_src_packets,
            src_to_dst_bytes=f.src_to_dst_bytes,
            dst_to_src_bytes=f.dst_to_src_bytes,
            start_time=f.start_time,
            end_time=f.end_time,
            duration=f.duration,
            state=f.state,
            handshake_latency_ms=f.handshake_latency_ms,
            retransmissions_count=f.retransmissions_count,
            details=json.loads(f.details_json or "{}")
        )
        for f in records
    ]

    return FlowListResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size
    )

@router.get("/endpoints", response_model=List[EndpointSchema])
def get_endpoints(capture_id: str, db: Session = Depends(get_db)):
    records = db.query(Endpoint).filter(Endpoint.capture_id == capture_id).order_by(Endpoint.byte_count.desc()).all()
    return [
        EndpointSchema(
            id=ep.id,
            ip_address=ep.ip_address,
            packet_count=ep.packet_count,
            byte_count=ep.byte_count,
            sent_packets=ep.sent_packets,
            recv_packets=ep.recv_packets,
            sent_bytes=ep.sent_bytes,
            recv_bytes=ep.recv_bytes,
            first_seen=ep.first_seen,
            last_seen=ep.last_seen,
            protocols=json.loads(ep.protocols_json or "[]"),
            flows_count=ep.flows_count
        )
        for ep in records
    ]

@router.get("/dns", response_model=DNSListResponse)
def get_dns_records(
    capture_id: str,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    rcode: Optional[str] = None,
    is_answered: Optional[bool] = None,
    query_name: Optional[str] = None,
    db: Session = Depends(get_db)
):
    query = db.query(DNSRecord).filter(DNSRecord.capture_id == capture_id)

    if rcode:
        query = query.filter(DNSRecord.rcode == rcode)
    if is_answered is not None:
        query = query.filter(DNSRecord.is_answered == is_answered)
    if query_name:
        query = query.filter(DNSRecord.query_name.ilike(f"%{query_name}%"))

    total = query.count()
    offset = (page - 1) * page_size
    records = query.order_by(DNSRecord.query_time.asc()).offset(offset).limit(page_size).all()

    # Aggregate metrics
    all_dns = db.query(DNSRecord).filter(DNSRecord.capture_id == capture_id).all()
    total_q = len(all_dns)
    total_ans = len([d for d in all_dns if d.is_answered])
    total_unans = len([d for d in all_dns if not d.is_answered])
    rcodes = {}
    for d in all_dns:
        rcodes[d.rcode] = rcodes.get(d.rcode, 0) + 1

    items = [
        DNSItemSchema(
            id=d.id,
            transaction_id=d.transaction_id,
            query_name=d.query_name,
            query_type=d.query_type,
            client_ip=d.client_ip,
            server_ip=d.server_ip,
            query_time=d.query_time,
            response_time=d.response_time,
            rcode=d.rcode,
            is_answered=d.is_answered,
            latency_ms=d.latency_ms,
            query_packet_number=d.query_packet_number,
            response_packet_number=d.response_packet_number,
            answers=json.loads(d.answers_json or "[]")
        )
        for d in records
    ]

    return DNSListResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        total_queries=total_q,
        total_answered=total_ans,
        total_unanswered=total_unans,
        rcode_counts=rcodes
    )

@router.get("/topology", response_model=TopologyResponse)
def get_topology(
    capture_id: str,
    max_nodes: int = Query(150, ge=10, le=1000),
    protocol: Optional[str] = None,
    findings_only: bool = False,
    db: Session = Depends(get_db)
):
    capture = db.query(Capture).filter(Capture.id == capture_id).first()
    if not capture:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Capture not found.")
    if capture.status == "failed":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Cannot build topology for failed capture: {capture.error_message or 'Analysis failed.'}"
        )
    return get_capture_topology(
        db=db,
        capture=capture,
        max_nodes=max_nodes,
        protocol=protocol,
        findings_only=findings_only
    )

