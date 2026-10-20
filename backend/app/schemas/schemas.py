from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field

class HealthResponse(BaseModel):
    status: str
    version: str
    app_name: str
    database_ok: bool

class CaptureBase(BaseModel):
    id: str
    original_filename: str
    file_size_bytes: int
    upload_time: str
    status: str
    packet_count: int
    duration_seconds: float
    format: str

class CaptureListItem(CaptureBase):
    pass

class CaptureDetail(CaptureBase):
    filename: str
    error_message: Optional[str] = None
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    link_type: Optional[str] = None
    metadata: Dict[str, Any] = {}

class PacketSchema(BaseModel):
    id: int
    packet_number: int
    timestamp: float
    rel_time: float
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: str
    length: int
    original_length: int
    tcp_flags: Optional[str] = None
    info: str
    details: Dict[str, Any] = {}

class PacketListResponse(BaseModel):
    items: List[PacketSchema]
    total: int
    page: int
    page_size: int
    total_pages: int

class FlowSchema(BaseModel):
    id: int
    flow_id: str
    protocol: str
    src_ip: str
    src_port: Optional[int] = None
    dst_ip: str
    dst_port: Optional[int] = None
    packet_count: int
    byte_count: int
    src_to_dst_packets: int
    dst_to_src_packets: int
    src_to_dst_bytes: int
    dst_to_src_bytes: int
    start_time: float
    end_time: float
    duration: float
    state: str
    handshake_latency_ms: Optional[float] = None
    retransmissions_count: int = 0
    details: Dict[str, Any] = {}

class FlowListResponse(BaseModel):
    items: List[FlowSchema]
    total: int
    page: int
    page_size: int

class EndpointSchema(BaseModel):
    id: int
    ip_address: str
    packet_count: int
    byte_count: int
    sent_packets: int
    recv_packets: int
    sent_bytes: int
    recv_bytes: int
    first_seen: float
    last_seen: float
    protocols: List[str]
    flows_count: int

class DNSItemSchema(BaseModel):
    id: int
    transaction_id: str
    query_name: str
    query_type: str
    client_ip: str
    server_ip: str
    query_time: float
    response_time: Optional[float] = None
    rcode: str
    is_answered: bool
    latency_ms: Optional[float] = None
    query_packet_number: int
    response_packet_number: Optional[int] = None
    answers: List[str] = []

class DNSListResponse(BaseModel):
    items: List[DNSItemSchema]
    total: int
    page: int
    page_size: int
    total_queries: int
    total_answered: int
    total_unanswered: int
    rcode_counts: Dict[str, int] = {}

class FindingSchema(BaseModel):
    id: str
    capture_id: str
    category: str
    severity: str
    confidence: str
    title: str
    observed_facts: str
    supporting_packet_numbers: List[int] = []
    timestamps: List[float] = []
    endpoints: List[str] = []
    ports: List[int] = []
    rule_name: str
    threshold_val: str
    explanations: str
    recommendations: str
    limitations: str

class CaptureSummaryResponse(BaseModel):
    capture_id: str
    original_filename: str
    file_size_bytes: int
    status: str
    packet_count: int
    total_bytes: int
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    duration_seconds: float
    link_type: Optional[str] = None
    protocol_distribution: Dict[str, int]
    protocol_bytes: Dict[str, int]
    traffic_over_time: List[Dict[str, Any]]
    tcp_stats: Dict[str, Any]
    dns_stats: Dict[str, Any]
    findings_by_severity: Dict[str, int]
    findings_by_category: Dict[str, int]
    top_endpoints: List[Dict[str, Any]]
    top_flows: List[Dict[str, Any]]
    recent_findings: List[Dict[str, Any]] = []
    parser_warnings: List[str]

class DetectorSettingsSchema(BaseModel):
    port_scan_threshold: int = Field(15, ge=2, le=1000)
    host_scan_threshold: int = Field(10, ge=2, le=1000)
    connection_burst_threshold: int = Field(20, ge=2, le=1000)
    burst_window_seconds: float = Field(2.0, ge=0.1, le=60.0)
    repeated_dns_query_threshold: int = Field(5, ge=2, le=500)
    periodic_connection_min_count: int = Field(4, ge=3, le=100)
    periodic_cv_threshold: float = Field(0.2, ge=0.01, le=1.0)
    traffic_rate_spike_pps: float = Field(100.0, ge=1.0, le=100000.0)

class TopologyRoleSchema(BaseModel):
    role: str
    inferred: bool
    basis: str

class TopologyHopEstimateSchema(BaseModel):
    hops: int
    observed_ttl: int
    assumed_initial_ttl: int
    inferred: bool
    basis: str

class TopologyNodeSchema(BaseModel):
    id: str
    kind: str
    scope: str
    classification: str = "Host"
    packets: int
    bytes: int
    sent_packets: int = 0
    recv_packets: int = 0
    sent_bytes: int
    recv_bytes: int
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None
    flows_count: int = 0
    distinct_peers: int = 0
    protocols: List[str]
    macs: List[str]
    roles: List[TopologyRoleSchema]
    hop_estimate: Optional[TopologyHopEstimateSchema] = None
    finding_ids: List[str]
    max_severity: Optional[str] = None

class TopologyEdgeSchema(BaseModel):
    id: str
    source: str
    target: str
    initiator: Optional[str] = None
    responder: Optional[str] = None
    bidirectional: bool = False
    kind: str
    inferred: bool = False
    basis: Optional[str] = None
    protocols: List[str]
    ports: List[int]
    flow_count: int
    packets: int
    bytes: int
    src_to_dst_packets: int = 0
    dst_to_src_packets: int = 0
    src_to_dst_bytes: int = 0
    dst_to_src_bytes: int = 0
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None
    sample_packet_numbers: List[int] = []
    states: Dict[str, int]
    status: str
    finding_ids: List[str]

class TopologyResponse(BaseModel):
    capture_id: str
    hints_available: bool
    l2_available: bool
    truncated: bool
    total_nodes: int
    omitted_nodes: int
    total_flows: int = 0
    total_packets: int = 0
    total_bytes: int = 0
    protocol_packets: Dict[str, int] = {}
    protocol_bytes: Dict[str, int] = {}
    nodes: List[TopologyNodeSchema]
    edges: List[TopologyEdgeSchema]
    notes: List[str]

class PacketFacetItem(BaseModel):
    value: str
    count: int

class PortFacetItem(BaseModel):
    port: int
    service: str
    count: int

class PacketFacetsResponse(BaseModel):
    capture_id: str
    total_packets: int
    protocols: List[PacketFacetItem]
    ips: List[PacketFacetItem]
    ports: List[PortFacetItem]
    tcp_flags: List[PacketFacetItem]
    min_length: int
    max_length: int
    finding_packets: Dict[str, List[Dict[str, str]]] = {}
    guided_suggestions: List[Dict[str, str]] = []

class FilterValidationResponse(BaseModel):
    valid: bool
    expression: str
    error: Optional[str] = None
    position: Optional[int] = None




