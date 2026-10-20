from typing import List, Dict, Any, Tuple
from collections import defaultdict
from app.services.packet_parser import ParsedPacketData

class FlowTracker:
    def __init__(self, key: str, proto: str, ep1: Tuple[str, int], ep2: Tuple[str, int]):
        self.key = key
        self.proto = proto
        self.initiator_ip, self.initiator_port = ep1
        self.responder_ip, self.responder_port = ep2
        self.packets: List[ParsedPacketData] = []
        self.start_time = 0.0
        self.end_time = 0.0
        self.init_to_resp_pkts = 0
        self.resp_to_init_pkts = 0
        self.init_to_resp_bytes = 0
        self.resp_to_init_bytes = 0
        self.syn_pkt: ParsedPacketData = None
        self.syn_ack_pkt: ParsedPacketData = None
        self.final_ack_pkt: ParsedPacketData = None
        self.rst_seen = False
        self.fin_seen = False
        self.handshake_latency_ms = None
        self.state = "UNKNOWN"
        self.retransmissions = 0

def analyze_flows(packets: List[ParsedPacketData]) -> List[Dict[str, Any]]:
    """
    Groups packets into bidirectional flows and analyzes TCP/UDP state.
    """
    flows_map: Dict[str, FlowTracker] = {}

    for pkt in packets:
        if not pkt.src_ip or not pkt.dst_ip or pkt.protocol in ("ARP", "OTHER", "CORRUPTED"):
            continue

        p1 = f"{pkt.src_ip}:{pkt.src_port or 0}"
        p2 = f"{pkt.dst_ip}:{pkt.dst_port or 0}"
        proto = "TCP" if "TCP" in pkt.protocol or pkt.tcp_flags else ("UDP" if pkt.protocol == "UDP" or "dns" in pkt.details else pkt.protocol)
        
        # Canonical flow key
        canon_key = f"{min(p1, p2)}_{max(p1, p2)}_{proto}"

        if canon_key not in flows_map:
            flows_map[canon_key] = FlowTracker(
                key=canon_key,
                proto=proto,
                ep1=(pkt.src_ip, pkt.src_port or 0),
                ep2=(pkt.dst_ip, pkt.dst_port or 0)
            )

        flow = flows_map[canon_key]
        if not flow.packets:
            flow.start_time = pkt.timestamp
        flow.end_time = pkt.timestamp
        flow.packets.append(pkt)

        # Direction tracking
        is_from_initiator = (pkt.src_ip == flow.initiator_ip and (pkt.src_port or 0) == flow.initiator_port)
        if is_from_initiator:
            flow.init_to_resp_pkts += 1
            flow.init_to_resp_bytes += pkt.length
        else:
            flow.resp_to_init_pkts += 1
            flow.resp_to_init_bytes += pkt.length

        # TCP state tracking
        if proto == "TCP" and "tcp" in pkt.details:
            flags = pkt.details["tcp"]["flags"]
            if "SYN" in flags and "ACK" not in flags and not flow.syn_pkt:
                flow.syn_pkt = pkt
                # If SYN was sent from the other side, adjust initiator
                if not is_from_initiator:
                    flow.initiator_ip, flow.responder_ip = flow.responder_ip, flow.initiator_ip
                    flow.initiator_port, flow.responder_port = flow.responder_port, flow.initiator_port
                    flow.init_to_resp_pkts, flow.resp_to_init_pkts = flow.resp_to_init_pkts, flow.init_to_resp_pkts
                    flow.init_to_resp_bytes, flow.resp_to_init_bytes = flow.resp_to_init_bytes, flow.init_to_resp_bytes

            elif "SYN" in flags and "ACK" in flags and not flow.syn_ack_pkt:
                flow.syn_ack_pkt = pkt
                if flow.syn_pkt and pkt.timestamp >= flow.syn_pkt.timestamp:
                    flow.handshake_latency_ms = round((pkt.timestamp - flow.syn_pkt.timestamp) * 1000, 2)

            elif "ACK" in flags and "SYN" not in flags and flow.syn_ack_pkt and not flow.final_ack_pkt:
                if is_from_initiator:
                    flow.final_ack_pkt = pkt

            if "RST" in flags:
                flow.rst_seen = True
                if not getattr(flow, "rst_pkt", None):
                    flow.rst_pkt = pkt
            if "FIN" in flags:
                flow.fin_seen = True

    # Finalize state for each flow
    flow_results: List[Dict[str, Any]] = []
    for flow in flows_map.values():
        duration = max(0.0, round(flow.end_time - flow.start_time, 4))
        
        if flow.proto == "TCP":
            if flow.rst_seen:
                flow.state = "RESET"
            elif flow.syn_pkt and flow.syn_ack_pkt and flow.final_ack_pkt:
                flow.state = "CLOSED_CLEAN" if flow.fin_seen else "ESTABLISHED"
            elif flow.syn_pkt and not flow.syn_ack_pkt:
                flow.state = "INCOMPLETE_HANDSHAKE"
            elif flow.syn_pkt and flow.syn_ack_pkt and not flow.final_ack_pkt:
                flow.state = "INCOMPLETE_HANDSHAKE"
            elif flow.fin_seen:
                flow.state = "CLOSED_CLEAN"
            else:
                flow.state = "ONGOING_OR_MIDSTREAM"
        else:
            flow.state = "UDP_BIDIRECTIONAL" if (flow.init_to_resp_pkts > 0 and flow.resp_to_init_pkts > 0) else "UDP_UNIDIRECTIONAL"

        packet_nums = [p.packet_number for p in flow.packets]
        timeline = [
            {
                "offset": round(p.timestamp - flow.start_time, 4),
                "packet_number": p.packet_number,
                "sent": 1 if (p.src_ip == flow.initiator_ip and (p.src_port or 0) == flow.initiator_port) else 0,
                "recv": 0 if (p.src_ip == flow.initiator_ip and (p.src_port or 0) == flow.initiator_port) else 1,
                "bytes": p.length,
            }
            for p in flow.packets[:100]
        ]
        rst_pkt = getattr(flow, "rst_pkt", None)

        flow_results.append({
            "flow_id": flow.key,
            "protocol": flow.proto,
            "src_ip": flow.initiator_ip,
            "src_port": flow.initiator_port if flow.initiator_port > 0 else None,
            "dst_ip": flow.responder_ip,
            "dst_port": flow.responder_port if flow.responder_port > 0 else None,
            "packet_count": len(flow.packets),
            "byte_count": flow.init_to_resp_bytes + flow.resp_to_init_bytes,
            "src_to_dst_packets": flow.init_to_resp_pkts,
            "dst_to_src_packets": flow.resp_to_init_pkts,
            "src_to_dst_bytes": flow.init_to_resp_bytes,
            "dst_to_src_bytes": flow.resp_to_init_bytes,
            "start_time": flow.start_time,
            "end_time": flow.end_time,
            "duration": duration,
            "state": flow.state,
            "handshake_latency_ms": flow.handshake_latency_ms,
            "retransmissions_count": flow.retransmissions,
            "packet_numbers": packet_nums[:100],  # sample packet numbers
            "details": {
                "syn_packet": flow.syn_pkt.packet_number if flow.syn_pkt else None,
                "syn_ack_packet": flow.syn_ack_pkt.packet_number if flow.syn_ack_pkt else None,
                "final_ack_packet": flow.final_ack_pkt.packet_number if flow.final_ack_pkt else None,
                "rst_packet": rst_pkt.packet_number if rst_pkt else None,
                "rst_seen": flow.rst_seen,
                "fin_seen": flow.fin_seen,
                "timeline": timeline,
            }
        })

    return flow_results
