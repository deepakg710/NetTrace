import os
import io
import json
import pytest
from pathlib import Path
from fastapi.testclient import TestClient

from app.main import app
from app.core.config import settings
from app.database.session import SessionLocal, init_db
from app.models.models import Capture, Packet, Flow, Finding, DNSRecord

client = TestClient(app)

@pytest.fixture(scope="module", autouse=True)
def setup_database():
    init_db()
    db = SessionLocal()
    from app.models.models import DetectorSetting
    db.query(DetectorSetting).delete()
    db.commit()
    db.close()
    yield
    # Cleanup after test module
    db = SessionLocal()
    db.query(DetectorSetting).delete()
    db.commit()
    db.close()

def test_health_endpoint():
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["database_ok"] is True
    assert data["app_name"] == "NetTrace"

def test_upload_rejections():
    # 1. Unsupported extension
    resp = client.post(
        "/api/v1/captures",
        files={"file": ("test.txt", b"hello world this is text", "text/plain")}
    )
    assert resp.status_code == 400
    assert "Unsupported file extension" in resp.json()["detail"]

    # 2. Empty file
    resp = client.post(
        "/api/v1/captures",
        files={"file": ("empty.pcap", b"", "application/vnd.tcpdump.pcap")}
    )
    assert resp.status_code == 400
    assert "empty or too small" in resp.json()["detail"]

    # 3. Invalid magic header
    resp = client.post(
        "/api/v1/captures",
        files={"file": ("fake.pcap", b"012345678901234567890123456789", "application/vnd.tcpdump.pcap")}
    )
    assert resp.status_code == 400
    assert "magic bytes" in resp.json()["detail"]

def test_upload_normal_capture():
    sample_path = Path(__file__).resolve().parent.parent.parent / "samples" / "normal_traffic.pcap"
    assert sample_path.exists(), "Sample normal_traffic.pcap must exist"

    with open(sample_path, "rb") as f:
        resp = client.post(
            "/api/v1/captures",
            files={"file": ("normal_traffic.pcap", f.read(), "application/vnd.tcpdump.pcap")}
        )

    assert resp.status_code == 201
    data = resp.json()
    assert data["status"] in ("completed", "partial")
    assert data["packet_count"] == 10
    assert data["original_filename"] == "normal_traffic.pcap"
    capture_id = data["id"]

    # Check summary
    sum_resp = client.get(f"/api/v1/captures/{capture_id}/summary")
    assert sum_resp.status_code == 200
    s_data = sum_resp.json()
    assert s_data["packet_count"] == 10
    assert "TCP" in s_data["protocol_distribution"]
    assert "DNS" in s_data["protocol_distribution"]
    assert s_data["tcp_stats"]["completed_handshakes"] >= 1
    assert s_data["tcp_stats"]["clean_closes"] >= 1
    # Clean capture should have 0 findings
    assert len(s_data["findings_by_severity"]) == 0

    # Check packets
    pkts_resp = client.get(f"/api/v1/captures/{capture_id}/packets?page=1&page_size=20")
    assert pkts_resp.status_code == 200
    p_data = pkts_resp.json()
    assert p_data["total"] == 10
    assert len(p_data["items"]) == 10

    # Check single packet
    p1 = client.get(f"/api/v1/captures/{capture_id}/packets/1")
    assert p1.status_code == 200
    assert p1.json()["packet_number"] == 1

    # Check flows
    flows_resp = client.get(f"/api/v1/captures/{capture_id}/flows")
    assert flows_resp.status_code == 200
    f_data = flows_resp.json()
    assert f_data["total"] >= 1

    # Check endpoints
    ep_resp = client.get(f"/api/v1/captures/{capture_id}/endpoints")
    assert ep_resp.status_code == 200
    eps = ep_resp.json()
    ep_ips = [e["ip_address"] for e in eps]
    assert "192.168.1.100" in ep_ips
    assert "10.0.0.80" in ep_ips

    # Cleanup test capture
    del_resp = client.delete(f"/api/v1/captures/{capture_id}")
    assert del_resp.status_code == 200

def test_upload_incident_capture_and_diagnostics():
    sample_path = Path(__file__).resolve().parent.parent.parent / "samples" / "incident_troubleshooting.pcap"
    assert sample_path.exists(), "Sample incident_troubleshooting.pcap must exist"

    with open(sample_path, "rb") as f:
        resp = client.post(
            "/api/v1/captures",
            files={"file": ("incident_troubleshooting.pcap", f.read(), "application/vnd.tcpdump.pcap")}
        )

    assert resp.status_code == 201
    data = resp.json()
    assert data["packet_count"] == 42
    capture_id = data["id"]

    # Check findings
    find_resp = client.get(f"/api/v1/captures/{capture_id}/findings")
    assert find_resp.status_code == 200
    findings = find_resp.json()
    assert len(findings) > 0

    rule_names = [f["rule_name"] for f in findings]
    # Check that key rules triggered
    assert "TCP_INCOMPLETE_HANDSHAKE" in rule_names
    assert "TCP_RESET_OBSERVED" in rule_names
    assert "DNS_NXDOMAIN_OBSERVED" in rule_names
    assert "DNS_SERVFAIL_OBSERVED" in rule_names
    assert "DNS_UNANSWERED_QUERY" in rule_names
    assert "PORT_SCAN_HEURISTIC" in rule_names

    # Verify that every finding has valid packet references and no fabricated IDs
    for f in findings:
        assert len(f["supporting_packet_numbers"]) > 0
        assert all(isinstance(p, int) and p > 0 for p in f["supporting_packet_numbers"])
        assert f["severity"] in ("Critical", "High", "Medium", "Low", "Informational")
        assert f["category"] in ("TCP", "DNS", "SCAN", "ANOMALY", "TRAFFIC", "INTEGRITY")
        assert f["limitations"] != ""
        assert f["recommendations"] != ""

    # Test Reports:
    # 1. HTML
    html_resp = client.get(f"/api/v1/captures/{capture_id}/reports/html")
    assert html_resp.status_code == 200
    assert "NETTRACE ANALYSIS REPORT" in html_resp.text
    assert "incident_troubleshooting.pcap" in html_resp.text

    # 2. PDF
    pdf_resp = client.get(f"/api/v1/captures/{capture_id}/reports/pdf")
    assert pdf_resp.status_code == 200
    assert pdf_resp.headers["content-type"] == "application/pdf"
    assert len(pdf_resp.content) > 1000

    # 3. JSON
    json_resp = client.get(f"/api/v1/captures/{capture_id}/reports/json")
    assert json_resp.status_code == 200
    j_data = json_resp.json()
    assert j_data["tool"] == "NetTrace"
    assert len(j_data["findings"]) > 0

    # Test Settings
    set_resp = client.get("/api/v1/settings")
    assert set_resp.status_code == 200
    curr_settings = set_resp.json()
    curr_settings["port_scan_threshold"] = 20
    update_resp = client.post("/api/v1/settings", json=curr_settings)
    assert update_resp.status_code == 200
    assert update_resp.json()["port_scan_threshold"] == 20

    # Re-verify persistence by listing captures
    list_resp = client.get("/api/v1/captures")
    assert list_resp.status_code == 200
    items = list_resp.json()
    assert any(c["id"] == capture_id for c in items)

    # Test Delete
    del_resp = client.delete(f"/api/v1/captures/{capture_id}")
    assert del_resp.status_code == 200

    # Confirm deleted
    get_del = client.get(f"/api/v1/captures/{capture_id}")
    assert get_del.status_code == 404


def _assert_inferred_items_have_basis(topo_data: dict) -> None:
    for node in topo_data["nodes"]:
        for role in node.get("roles", []):
            if role.get("inferred"):
                assert isinstance(role.get("basis"), str) and len(role["basis"].strip()) > 0
        hop = node.get("hop_estimate")
        if hop and hop.get("inferred"):
            assert isinstance(hop.get("basis"), str) and len(hop["basis"].strip()) > 0
    for edge in topo_data["edges"]:
        if edge.get("inferred") or edge.get("kind") == "inferred_l2":
            assert isinstance(edge.get("basis"), str) and len(edge["basis"].strip()) > 0


def test_topology_normal_sample():
    sample_path = Path(__file__).resolve().parent.parent.parent / "samples" / "normal_traffic.pcap"
    with open(sample_path, "rb") as f:
        resp = client.post(
            "/api/v1/captures",
            files={"file": ("normal_traffic.pcap", f.read(), "application/vnd.tcpdump.pcap")}
        )
    assert resp.status_code == 201
    capture_id = resp.json()["id"]

    ep_resp = client.get(f"/api/v1/captures/{capture_id}/endpoints")
    assert ep_resp.status_code == 200
    endpoints = ep_resp.json()

    topo_resp = client.get(f"/api/v1/captures/{capture_id}/topology")
    assert topo_resp.status_code == 200
    topo = topo_resp.json()

    assert topo["hints_available"] is True
    host_nodes = [n for n in topo["nodes"] if n["kind"] == "host"]
    assert len(host_nodes) == len(endpoints)

    node_ids = {n["id"] for n in topo["nodes"]}
    for edge in topo["edges"]:
        assert edge["source"] in node_ids
        assert edge["target"] in node_ids
        if edge["kind"] == "observed":
            assert edge["flow_count"] >= 1

    _assert_inferred_items_have_basis(topo)

    client.delete(f"/api/v1/captures/{capture_id}")


def test_topology_incident_sample():
    sample_path = Path(__file__).resolve().parent.parent.parent / "samples" / "incident_troubleshooting.pcap"
    with open(sample_path, "rb") as f:
        resp = client.post(
            "/api/v1/captures",
            files={"file": ("incident_troubleshooting.pcap", f.read(), "application/vnd.tcpdump.pcap")}
        )
    assert resp.status_code == 201
    capture_id = resp.json()["id"]

    topo_resp = client.get(f"/api/v1/captures/{capture_id}/topology")
    assert topo_resp.status_code == 200
    topo = topo_resp.json()

    # At least one edge has status == "reset"
    assert any(e["status"] == "reset" for e in topo["edges"])

    # At least one node has role dns_server matching a /dns server_ip
    dns_resp = client.get(f"/api/v1/captures/{capture_id}/dns")
    assert dns_resp.status_code == 200
    dns_server_ips = {item["server_ip"] for item in dns_resp.json()["items"]}
    dns_server_nodes = [
        n["id"] for n in topo["nodes"]
        if any(r["role"] == "dns_server" and not r["inferred"] for r in n["roles"])
    ]
    assert len(dns_server_nodes) >= 1
    assert any(ip in dns_server_ips for ip in dns_server_nodes)

    # Every finding_ids entry exists in /findings
    find_resp = client.get(f"/api/v1/captures/{capture_id}/findings")
    assert find_resp.status_code == 200
    valid_finding_ids = {f["id"] for f in find_resp.json()}
    for n in topo["nodes"]:
        for fid in n["finding_ids"]:
            assert fid in valid_finding_ids
    for e in topo["edges"]:
        for fid in e["finding_ids"]:
            assert fid in valid_finding_ids

    _assert_inferred_items_have_basis(topo)

    # Verify protocol_packets and protocol_bytes are populated from real analysis
    assert isinstance(topo.get("protocol_packets"), dict) and len(topo["protocol_packets"]) > 0
    assert isinstance(topo.get("protocol_bytes"), dict) and len(topo["protocol_bytes"]) > 0
    assert sum(topo["protocol_packets"].values()) > 0
    assert sum(topo["protocol_bytes"].values()) > 0

    # Verify protocol and findings_only query parameters filter accurately
    dns_topo_resp = client.get(f"/api/v1/captures/{capture_id}/topology?protocol=DNS&findings_only=true")
    assert dns_topo_resp.status_code == 200
    dns_topo = dns_topo_resp.json()
    for edge in dns_topo["edges"]:
        if edge["kind"] == "observed":
            assert "DNS" in edge["protocols"]

    client.delete(f"/api/v1/captures/{capture_id}")


def test_topology_truncation():
    from app.models.models import Endpoint, Finding
    from app.services.topology_service import build_topology_from_records

    sample_path = Path(__file__).resolve().parent.parent.parent / "samples" / "normal_traffic.pcap"
    with open(sample_path, "rb") as f:
        resp = client.post(
            "/api/v1/captures",
            files={"file": ("normal_traffic.pcap", f.read(), "application/vnd.tcpdump.pcap")}
        )
    assert resp.status_code == 201
    capture_id = resp.json()["id"]

    # max_nodes=10 on a capture with fewer than 10 nodes gives truncated == False
    topo_resp = client.get(f"/api/v1/captures/{capture_id}/topology?max_nodes=10")
    assert topo_resp.status_code == 200
    assert topo_resp.json()["truncated"] is False

    client.delete(f"/api/v1/captures/{capture_id}")

    # Unit-test build_topology_from_records with in-memory rows to verify truncation keeps finding nodes
    fake_endpoints = [
        Endpoint(
            capture_id="cap-unit",
            ip_address=f"10.0.0.{i}",
            packet_count=100 - i,
            byte_count=(100 - i) * 100,
            sent_packets=50,
            recv_packets=50,
            sent_bytes=500,
            recv_bytes=500,
            first_seen=1.0,
            last_seen=2.0,
            protocols_json='["TCP"]',
            flows_count=1,
        )
        for i in range(1, 21)
    ]
    # Give the lowest-byte node (10.0.0.20) a finding so truncation must preserve it
    fake_finding = Finding(
        id="find-low-byte-node",
        capture_id="cap-unit",
        category="SCAN",
        severity="High",
        confidence="Medium",
        title="Port scan candidate",
        observed_facts="Test",
        supporting_packet_numbers_json="[1]",
        timestamps_json="[1.0]",
        endpoints_json='["10.0.0.20"]',
        ports_json="[80]",
        rule_name="PORT_SCAN_HEURISTIC",
        threshold_val="15",
        explanations="Test",
        recommendations="Test",
        limitations="Test",
    )
    res = build_topology_from_records(
        capture_id="cap-unit",
        meta={"topology_hints": {"l2_available": False, "ip_macs": {}, "mac_ips": {}, "ip_ttls": {}}},
        endpoints=fake_endpoints,
        flows=[],
        dns_records=[],
        findings=[fake_finding],
        max_nodes=10,
    )
    assert res.truncated is True
    assert res.total_nodes == 20
    assert res.omitted_nodes == 10
    assert len(res.nodes) == 10
    kept_ids = {n.id for n in res.nodes}
    assert "10.0.0.20" in kept_ids


def test_topology_old_analysis():
    sample_path = Path(__file__).resolve().parent.parent.parent / "samples" / "normal_traffic.pcap"
    with open(sample_path, "rb") as f:
        resp = client.post(
            "/api/v1/captures",
            files={"file": ("normal_traffic.pcap", f.read(), "application/vnd.tcpdump.pcap")}
        )
    assert resp.status_code == 201
    capture_id = resp.json()["id"]

    # Delete topology_hints from capture metadata in DB
    db = SessionLocal()
    cap = db.query(Capture).filter(Capture.id == capture_id).first()
    meta = json.loads(cap.metadata_json or "{}")
    meta.pop("topology_hints", None)
    cap.metadata_json = json.dumps(meta)
    db.commit()
    db.close()

    topo_resp = client.get(f"/api/v1/captures/{capture_id}/topology")
    assert topo_resp.status_code == 200
    topo = topo_resp.json()
    assert topo["hints_available"] is False
    assert len(topo["notes"]) >= 1

    client.delete(f"/api/v1/captures/{capture_id}")


def test_topology_404():
    resp = client.get("/api/v1/captures/non-existent-capture-id/topology")
    assert resp.status_code == 404


def test_packets_facets_and_advanced_filters():
    sample_path = Path(__file__).resolve().parent.parent.parent / "samples" / "incident_troubleshooting.pcap"
    with open(sample_path, "rb") as f:
        resp = client.post(
            "/api/v1/captures",
            files={"file": ("incident_troubleshooting.pcap", f.read(), "application/vnd.tcpdump.pcap")}
        )
    assert resp.status_code == 201
    capture_id = resp.json()["id"]

    # 1. Facets endpoint returns observed protocols, IPs, ports, and TCP flags
    facets_resp = client.get(f"/api/v1/captures/{capture_id}/packets-facets")
    assert facets_resp.status_code == 200
    facets = facets_resp.json()
    assert facets["total_packets"] > 0
    assert len(facets["protocols"]) > 0
    assert len(facets["ips"]) > 0
    assert len(facets["ports"]) > 0
    assert facets["max_length"] >= facets["min_length"] > 0

    first_ip = facets["ips"][0]["value"]

    # 2. Directional src_ip / dst_ip / exclude_ip filters
    src_resp = client.get(f"/api/v1/captures/{capture_id}/packets?src_ip={first_ip}")
    assert src_resp.status_code == 200
    for pkt in src_resp.json()["items"]:
        assert pkt["src_ip"] == first_ip

    excl_resp = client.get(f"/api/v1/captures/{capture_id}/packets?exclude_ip={first_ip}")
    assert excl_resp.status_code == 200
    for pkt in excl_resp.json()["items"]:
        assert pkt["src_ip"] != first_ip and pkt["dst_ip"] != first_ip

    # 3. Conversation stream filter (peer_a & peer_b)
    if len(facets["ips"]) >= 2:
        peer_a = facets["ips"][0]["value"]
        peer_b = facets["ips"][1]["value"]
        stream_resp = client.get(
            f"/api/v1/captures/{capture_id}/packets?peer_a={peer_a}&peer_b={peer_b}"
        )
        assert stream_resp.status_code == 200
        for pkt in stream_resp.json()["items"]:
            assert {pkt["src_ip"], pkt["dst_ip"]} == {peer_a, peer_b}

    client.delete(f"/api/v1/captures/{capture_id}")


def test_display_filter_engine_parser_precedence_and_validation():
    from app.services.display_filter import (
        parse_display_filter,
        evaluate_packet_dict,
        DisplayFilterError,
    )

    # All Priority 1 required target expressions must parse cleanly
    required_expressions = [
        "ip.addr == 192.168.1.10",
        "ip.src == 192.168.1.10",
        "ip.dst == 10.0.0.5",
        "tcp.port == 443",
        "udp.port == 53",
        "dns",
        "tcp",
        "tcp.flags.syn == 1",
        "tcp.flags.reset == 1",
        "frame.number == 100",
        "frame.len > 1000",
        "ip.addr == 192.168.1.10 && tcp",
        "dns || tcp.port == 443",
        "!(arp)",
    ]
    for expr in required_expressions:
        ast = parse_display_filter(expr)
        assert ast is not None

    # Sample packet dictionaries for evaluation
    tcp_syn_pkt = {
        "packet_number": 100,
        "length": 1200,
        "protocol": "TCP",
        "src_ip": "192.168.1.10",
        "dst_ip": "10.0.0.5",
        "src_port": 51234,
        "dst_port": 443,
        "tcp_flags": "SYN",
        "info": "51234 -> 443 [SYN] Seq=0 Win=64240",
        "layers": [],
    }
    dns_udp_pkt = {
        "packet_number": 101,
        "length": 78,
        "protocol": "DNS",
        "src_ip": "192.168.1.10",
        "dst_ip": "8.8.8.8",
        "src_port": 53000,
        "dst_port": 53,
        "tcp_flags": None,
        "info": "DNS Query A api.internal.corp",
        "layers": [
            {
                "name": "DNS",
                "fields": {"qname": "api.internal.corp", "rcode": 0, "qr": 0},
            }
        ],
    }

    assert evaluate_packet_dict(parse_display_filter("ip.addr == 192.168.1.10 && tcp"), tcp_syn_pkt) is True
    assert evaluate_packet_dict(parse_display_filter("ip.addr == 192.168.1.10 && tcp"), dns_udp_pkt) is False
    assert evaluate_packet_dict(parse_display_filter("dns || tcp.port == 443"), tcp_syn_pkt) is True
    assert evaluate_packet_dict(parse_display_filter("dns || tcp.port == 443"), dns_udp_pkt) is True
    assert evaluate_packet_dict(parse_display_filter("tcp.flags.syn == 1"), tcp_syn_pkt) is True
    assert evaluate_packet_dict(parse_display_filter("tcp.flags.reset == 1"), tcp_syn_pkt) is False
    assert evaluate_packet_dict(parse_display_filter("frame.number == 100 && frame.len > 1000"), tcp_syn_pkt) is True
    assert evaluate_packet_dict(parse_display_filter("!(arp)"), tcp_syn_pkt) is True

    # Missing field semantics: tcp.port != 80 on a UDP/DNS packet must be False (since tcp.port does not exist on UDP)
    assert evaluate_packet_dict(parse_display_filter("tcp.port != 80"), dns_udp_pkt) is False

    # Operator precedence: && binds tighter than ||
    # dns || tcp && frame.number == 999 -> True for dns_udp_pkt because dns is True
    prec_ast = parse_display_filter("dns || tcp && frame.number == 999")
    assert evaluate_packet_dict(prec_ast, dns_udp_pkt) is True
    # With parentheses: (dns || tcp) && frame.number == 999 -> False for dns_udp_pkt
    paren_ast = parse_display_filter("(dns || tcp) && frame.number == 999")
    assert evaluate_packet_dict(paren_ast, dns_udp_pkt) is False

    # Invalid expressions must raise DisplayFilterError
    invalid_expressions = [
        "unknown.field == 1",
        "ip.addr == 999.999.1.1",
        "tcp.port == 70000",
        "ip.src = 10.0.0.1",
        "(tcp && dns",
        "tcp &&",
    ]
    for bad in invalid_expressions:
        try:
            parse_display_filter(bad)
            assert False, f"Expected DisplayFilterError for: {bad}"
        except DisplayFilterError:
            pass


def test_packets_display_filter_api_and_exports():
    sample_path = Path(__file__).resolve().parent.parent.parent / "samples" / "incident_troubleshooting.pcap"
    with open(sample_path, "rb") as f:
        resp = client.post(
            "/api/v1/captures",
            files={"file": ("incident_troubleshooting.pcap", f.read(), "application/vnd.tcpdump.pcap")}
        )
    assert resp.status_code == 201
    capture_id = resp.json()["id"]

    # 1. Validate endpoint
    v_ok = client.get(f"/api/v1/captures/{capture_id}/filter-validate", params={"expr": "dns || tcp.flags.reset == 1"})
    assert v_ok.status_code == 200
    assert v_ok.json()["valid"] is True

    v_bad = client.get(f"/api/v1/captures/{capture_id}/filter-validate", params={"expr": "ip.addr == 999.999.999.999"})
    assert v_bad.status_code == 200
    assert v_bad.json()["valid"] is False
    assert v_bad.json()["error"] is not None

    # 2. Invalid display_filter on /packets returns 400
    bad_pkt_resp = client.get(f"/api/v1/captures/{capture_id}/packets", params={"display_filter": "bad.field == 1"})
    assert bad_pkt_resp.status_code == 400

    # 3. Valid display_filter on /packets filters accurately
    rst_resp = client.get(f"/api/v1/captures/{capture_id}/packets", params={"display_filter": "tcp.flags.reset == 1"})
    assert rst_resp.status_code == 200
    rst_data = rst_resp.json()
    assert rst_data["total"] > 0
    for item in rst_data["items"]:
        assert item["protocol"] == "TCP"
        assert "RST" in (item["tcp_flags"] or "")

    # 4. Packet detail includes Frame layer, byte offsets, and raw_hex inside details
    first_pkt_no = rst_data["items"][0]["packet_number"]
    detail_resp = client.get(f"/api/v1/captures/{capture_id}/packets/{first_pkt_no}")
    assert detail_resp.status_code == 200
    detail = detail_resp.json()
    pkt_details = detail["details"]
    assert pkt_details.get("raw_hex") is not None and len(pkt_details["raw_hex"]) > 0
    assert len(pkt_details["layers_tree"]) >= 2
    assert pkt_details["layers_tree"][0]["name"].startswith("Frame ")
    assert "byte_start" in pkt_details["layers_tree"][0]
    assert "byte_end" in pkt_details["layers_tree"][0]

    # 5. CSV and JSON export endpoints
    csv_resp = client.get(
        f"/api/v1/captures/{capture_id}/packets-export",
        params={"format": "csv", "display_filter": "tcp.flags.reset == 1"},
    )
    assert csv_resp.status_code == 200
    assert "packet_number,timestamp,rel_time,src_ip" in csv_resp.text

    json_resp = client.get(
        f"/api/v1/captures/{capture_id}/packets-export",
        params={"format": "json", "packet_numbers": str(first_pkt_no)},
    )
    assert json_resp.status_code == 200
    exported_json = json_resp.json()
    assert exported_json["exported_packets"] == 1
    assert exported_json["packets"][0]["packet_number"] == first_pkt_no

    client.delete(f"/api/v1/captures/{capture_id}")



