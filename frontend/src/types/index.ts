export type SeverityLevel = 'Critical' | 'High' | 'Medium' | 'Low' | 'Informational';
export type FindingCategory = 'TCP' | 'DNS' | 'SCAN' | 'ANOMALY' | 'TRAFFIC' | 'INTEGRITY';

export interface CaptureItem {
  id: string;
  original_filename: string;
  file_size_bytes: number;
  upload_time: string;
  status: 'uploaded' | 'analyzing' | 'completed' | 'failed' | 'partial';
  packet_count: number;
  duration_seconds: number;
  format: 'pcap' | 'pcapng';
}

export interface CaptureDetail extends CaptureItem {
  filename: string;
  error_message?: string | null;
  start_time?: number | null;
  end_time?: number | null;
  link_type?: string | null;
  metadata: {
    total_bytes?: number;
    total_endpoints?: number;
    protocol_counts?: Record<string, number>;
    protocol_bytes?: Record<string, number>;
    traffic_over_time?: Array<{ time_offset: number; packets: number; bytes: number; sent?: number; received?: number }>;
    tcp_stats?: {
      total_tcp_flows: number;
      established_flows: number;
      completed_handshakes?: number;
      incomplete_handshakes: number;
      resets_observed: number;
      clean_closes: number;
    };
    dns_stats?: {
      total_dns_records: number;
      answered_queries: number;
      unanswered_queries: number;
      nxdomain_count: number;
      servfail_count: number;
    };
    findings_by_severity?: Record<string, number>;
    findings_by_category?: Record<string, number>;
    top_endpoints?: Array<{ ip: string; packets: number; bytes: number }>;
    top_flows?: Array<{ flow_id: string; protocol: string; src?: string; dst?: string; packets: number; bytes: number; state: string; duration?: number }>;
    recent_findings?: Array<{
      id: string;
      category: string;
      severity: string;
      title: string;
      rule_name: string;
      packet_numbers: number[];
      timestamp: number;
    }>;
    warnings?: string[];
  };
}

export interface PacketLayerItem {
  name: string;
  summary?: string;
  byte_start?: number;
  byte_end?: number;
  field_offsets?: Record<string, [number, number]>;
  fields: Record<string, any>;
}

export interface PacketItem {
  id: number;
  packet_number: number;
  timestamp: number;
  rel_time: number;
  src_ip?: string | null;
  dst_ip?: string | null;
  src_port?: number | null;
  dst_port?: number | null;
  protocol: string;
  length: number;
  original_length: number;
  tcp_flags?: string | null;
  info: string;
  details: {
    layers_tree?: PacketLayerItem[];
    hex_dump?: string;
    raw_hex?: string;
    [key: string]: any;
  };
}

export interface PacketListResponse {
  items: PacketItem[];
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
}

export interface FlowItem {
  id: number;
  flow_id: string;
  protocol: string;
  src_ip: string;
  src_port?: number | null;
  dst_ip: string;
  dst_port?: number | null;
  packet_count: number;
  byte_count: number;
  src_to_dst_packets: number;
  dst_to_src_packets: number;
  src_to_dst_bytes: number;
  dst_to_src_bytes: number;
  start_time: number;
  end_time: number;
  duration: number;
  state: string;
  handshake_latency_ms?: number | null;
  retransmissions_count: number;
  details: Record<string, any>;
}

export interface FlowListResponse {
  items: FlowItem[];
  total: number;
  page: number;
  page_size: number;
}

export interface EndpointItem {
  id: number;
  ip_address: string;
  packet_count: number;
  byte_count: number;
  sent_packets: number;
  recv_packets: number;
  sent_bytes: number;
  recv_bytes: number;
  first_seen: number;
  last_seen: number;
  protocols: string[];
  flows_count: number;
}

export interface DNSItem {
  id: number;
  transaction_id: string;
  query_name: string;
  query_type: string;
  client_ip: string;
  server_ip: string;
  query_time: number;
  response_time?: number | null;
  rcode: string;
  is_answered: boolean;
  latency_ms?: number | null;
  query_packet_number: number;
  response_packet_number?: number | null;
  answers: string[];
}

export interface DNSListResponse {
  items: DNSItem[];
  total: number;
  page: number;
  page_size: number;
  total_queries: number;
  total_answered: number;
  total_unanswered: number;
  rcode_counts: Record<string, number>;
}

export interface FindingItem {
  id: string;
  capture_id: string;
  category: FindingCategory;
  severity: SeverityLevel;
  confidence: string;
  title: string;
  observed_facts: string;
  supporting_packet_numbers: number[];
  timestamps: number[];
  endpoints: string[];
  ports: number[];
  rule_name: string;
  threshold_val: string;
  explanations: string;
  recommendations: string;
  limitations: string;
}

export interface DetectorSettings {
  port_scan_threshold: number;
  host_scan_threshold: number;
  connection_burst_threshold: number;
  burst_window_seconds: number;
  repeated_dns_query_threshold: number;
  periodic_connection_min_count: number;
  periodic_cv_threshold: number;
  traffic_rate_spike_pps: number;
}

export interface TopologyRole {
  role: string;
  inferred: boolean;
  basis: string;
}

export interface TopologyHopEstimate {
  hops: number;
  observed_ttl: number;
  assumed_initial_ttl: number;
  inferred: boolean;
  basis: string;
}

export type TopologyNodeKind = 'host' | 'inferred_gateway';
export type TopologyNodeScope = 'local' | 'remote' | 'multicast' | 'unknown';

export interface TopologyNode {
  id: string;
  kind: TopologyNodeKind;
  scope: TopologyNodeScope;
  classification?: string;
  packets: number;
  bytes: number;
  sent_packets?: number;
  recv_packets?: number;
  sent_bytes: number;
  recv_bytes: number;
  first_seen?: number | null;
  last_seen?: number | null;
  flows_count?: number;
  distinct_peers?: number;
  protocols: string[];
  macs: string[];
  roles: TopologyRole[];
  hop_estimate?: TopologyHopEstimate | null;
  finding_ids: string[];
  max_severity?: SeverityLevel | null;
}

export type TopologyEdgeKind = 'observed' | 'inferred_l2';
export type TopologyEdgeStatus = 'normal' | 'reset' | 'incomplete' | 'scan';

export interface TopologyEdge {
  id: string;
  source: string;
  target: string;
  initiator?: string | null;
  responder?: string | null;
  bidirectional?: boolean;
  kind: TopologyEdgeKind;
  inferred?: boolean;
  basis?: string | null;
  protocols: string[];
  ports: number[];
  flow_count: number;
  packets: number;
  bytes: number;
  src_to_dst_packets?: number;
  dst_to_src_packets?: number;
  src_to_dst_bytes?: number;
  dst_to_src_bytes?: number;
  first_seen?: number | null;
  last_seen?: number | null;
  sample_packet_numbers?: number[];
  states: Record<string, number>;
  status: TopologyEdgeStatus;
  finding_ids: string[];
}

export interface TopologyResponse {
  capture_id: string;
  hints_available: boolean;
  l2_available: boolean;
  truncated: boolean;
  total_nodes: number;
  omitted_nodes: number;
  total_flows?: number;
  total_packets?: number;
  total_bytes?: number;
  protocol_packets?: Record<string, number>;
  protocol_bytes?: Record<string, number>;
  nodes: TopologyNode[];
  edges: TopologyEdge[];
  notes: string[];
}

export interface PacketFacetItem {
  value: string;
  count: number;
}

export interface PortFacetItem {
  port: number;
  service: string;
  count: number;
}

export interface PacketFacetsResponse {
  capture_id: string;
  total_packets: number;
  protocols: PacketFacetItem[];
  ips: PacketFacetItem[];
  ports: PortFacetItem[];
  tcp_flags: PacketFacetItem[];
  min_length: number;
  max_length: number;
  finding_packets?: Record<string, Array<{ id: string; title: string; severity: string; category: string }>>;
  guided_suggestions?: Array<{ label: string; filter: string; reason: string }>;
}



