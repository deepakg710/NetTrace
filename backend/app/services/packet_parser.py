import time
from pathlib import Path
from typing import Generator, Dict, Any, List, Tuple
from scapy.all import PcapReader, Ether, IP, IPv6, TCP, UDP, ICMP, ARP, DNS, DNSRR, DNSQR
from scapy.error import Scapy_Exception
from app.core.logging import logger

def format_hex_dump(raw_bytes: bytes, max_bytes: int = 128) -> str:
    if not raw_bytes:
        return ""
    slice_bytes = raw_bytes[:max_bytes]
    lines = []
    for i in range(0, len(slice_bytes), 16):
        chunk = slice_bytes[i:i+16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        if len(chunk) < 16:
            hex_part = hex_part.ljust(16 * 3 - 1)
        ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        lines.append(f"{i:04x}  {hex_part}  |{ascii_part}|")
    if len(raw_bytes) > max_bytes:
        lines.append(f"... [{len(raw_bytes) - max_bytes} bytes omitted]")
    return "\n".join(lines)

DNS_TYPES = {
    1: "A", 28: "AAAA", 5: "CNAME", 15: "MX", 12: "PTR",
    16: "TXT", 2: "NS", 6: "SOA", 33: "SRV"
}

DNS_RCODES = {
    0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN",
    4: "NOTIMP", 5: "REFUSED", 9: "NOTAUTH"
}

ICMP_TYPES = {
    0: "Echo Reply",
    3: {
        0: "Net Unreachable",
        1: "Host Unreachable",
        2: "Protocol Unreachable",
        3: "Port Unreachable",
        4: "Fragmentation Needed",
        "default": "Destination Unreachable"
    },
    8: "Echo Request",
    11: "Time Exceeded"
}

def parse_tcp_flags(flags_val) -> Tuple[str, List[str]]:
    flag_names = []
    # Scapy flags representation
    f_str = str(flags_val)
    if "S" in f_str:
        flag_names.append("SYN")
    if "A" in f_str:
        flag_names.append("ACK")
    if "F" in f_str:
        flag_names.append("FIN")
    if "R" in f_str:
        flag_names.append("RST")
    if "P" in f_str:
        flag_names.append("PSH")
    if "U" in f_str:
        flag_names.append("URG")
    if "E" in f_str:
        flag_names.append("ECE")
    if "C" in f_str:
        flag_names.append("CWR")
    return ", ".join(flag_names), flag_names

class ParsedPacketData:
    def __init__(self, packet_number: int, timestamp: float, length: int, original_length: int,
                 protocol: str, src_ip: str, dst_ip: str, src_port: int, dst_port: int,
                 tcp_flags: str, info: str, details: Dict[str, Any], warnings: List[str]):
        self.packet_number = packet_number
        self.timestamp = timestamp
        self.length = length
        self.original_length = original_length
        self.protocol = protocol
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.tcp_flags = tcp_flags
        self.info = info
        self.details = details
        self.warnings = warnings

def stream_parse_pcap(filepath: Path) -> Generator[ParsedPacketData, None, None]:
    """
    Streams packets from a pcap or pcapng file.
    Does not crash on malformed packets; records warnings instead.
    """
    packet_number = 0
    try:
        reader = PcapReader(str(filepath))
    except Exception as e:
        logger.error(f"Failed to open capture reader for {filepath}: {e}")
        raise ValueError(f"Could not open capture file: {e}")

    with reader:
        while True:
            try:
                pkt = reader.read_packet()
                if pkt is None:
                    break
            except EOFError:
                break
            except Exception as e:
                packet_number += 1
                yield ParsedPacketData(
                    packet_number=packet_number,
                    timestamp=time.time(),
                    length=0,
                    original_length=0,
                    protocol="CORRUPTED",
                    src_ip="",
                    dst_ip="",
                    src_port=None,
                    dst_port=None,
                    tcp_flags="",
                    info="[Malformed or truncated packet]",
                    details={"error": str(e)},
                    warnings=[f"Parser error on packet {packet_number}: {str(e)}"]
                )
                continue

            packet_number += 1
            warnings: List[str] = []
            
            # Timestamp
            ts = float(pkt.time) if hasattr(pkt, "time") and pkt.time is not None else 0.0
            
            # Lengths
            cap_len = len(pkt)
            wire_len = getattr(pkt, "wirelen", cap_len)
            if wire_len is None or wire_len < cap_len:
                wire_len = cap_len

            src_ip = None
            dst_ip = None
            src_port = None
            dst_port = None
            proto = "OTHER"
            tcp_flags_str = ""
            details: Dict[str, Any] = {}
            info_parts = []

            # Network Layer
            if IP in pkt:
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                proto = "IPv4"
                details["ip_ttl"] = pkt[IP].ttl
                details["ip_id"] = pkt[IP].id
            elif IPv6 in pkt:
                src_ip = pkt[IPv6].src
                dst_ip = pkt[IPv6].dst
                proto = "IPv6"
                details["hop_limit"] = pkt[IPv6].hlim
            elif ARP in pkt:
                proto = "ARP"
                src_ip = pkt[ARP].psrc
                dst_ip = pkt[ARP].pdst
                details["arp_op"] = "request" if pkt[ARP].op == 1 else "reply"
                info_parts.append(f"ARP {details['arp_op']} who-has {dst_ip} tell {src_ip}")

            # Transport / Application Layers
            if TCP in pkt:
                proto = "TCP"
                src_port = pkt[TCP].sport
                dst_port = pkt[TCP].dport
                flags_str, flag_list = parse_tcp_flags(pkt[TCP].flags)
                tcp_flags_str = flags_str
                
                payload_len = len(pkt[TCP].payload) if pkt[TCP].payload else 0
                details["tcp"] = {
                    "seq": pkt[TCP].seq,
                    "ack": pkt[TCP].ack,
                    "window": pkt[TCP].window,
                    "flags": flag_list,
                    "payload_len": payload_len
                }
                info_parts.append(f"{src_port} \u2192 {dst_port} [{flags_str}] Seq={pkt[TCP].seq} Ack={pkt[TCP].ack} Win={pkt[TCP].window} Len={payload_len}")

            elif UDP in pkt:
                proto = "UDP"
                src_port = pkt[UDP].sport
                dst_port = pkt[UDP].dport
                payload_len = len(pkt[UDP].payload) if pkt[UDP].payload else 0
                details["udp"] = {
                    "len": pkt[UDP].len,
                    "payload_len": payload_len
                }
                info_parts.append(f"{src_port} \u2192 {dst_port} Len={payload_len}")

            elif ICMP in pkt:
                proto = "ICMP"
                icmp_type = pkt[ICMP].type
                icmp_code = pkt[ICMP].code
                type_desc = ICMP_TYPES.get(icmp_type, f"Type {icmp_type}")
                if isinstance(type_desc, dict):
                    code_desc = type_desc.get(icmp_code, type_desc.get("default", f"Code {icmp_code}"))
                else:
                    code_desc = type_desc
                details["icmp"] = {
                    "type": icmp_type,
                    "code": icmp_code,
                    "description": code_desc
                }
                info_parts.append(f"ICMP {code_desc} (type {icmp_type}, code {icmp_code})")

            # Check for DNS inside UDP/TCP
            if DNS in pkt:
                proto = "DNS"
                dns_layer = pkt[DNS]
                is_response = (dns_layer.qr == 1)
                tx_id = f"0x{dns_layer.id:04x}"
                rcode_val = dns_layer.rcode
                rcode_name = DNS_RCODES.get(rcode_val, f"RCODE_{rcode_val}")

                queries = []
                if dns_layer.qdcount > 0 and dns_layer.qd:
                    curr_qd = dns_layer.qd
                    while curr_qd and isinstance(curr_qd, DNSQR):
                        qname = curr_qd.qname.decode("utf-8", errors="replace").rstrip(".") if hasattr(curr_qd.qname, "decode") else str(curr_qd.qname).rstrip(".")
                        qtype_num = curr_qd.qtype
                        qtype_str = DNS_TYPES.get(qtype_num, f"TYPE_{qtype_num}")
                        queries.append({"name": qname, "type": qtype_str})
                        curr_qd = curr_qd.payload if hasattr(curr_qd, "payload") and isinstance(curr_qd.payload, DNSQR) else None

                answers = []
                if dns_layer.ancount > 0 and dns_layer.an:
                    curr_an = dns_layer.an
                    while curr_an and isinstance(curr_an, DNSRR):
                        rrname = curr_an.rrname.decode("utf-8", errors="replace").rstrip(".") if hasattr(curr_an.rrname, "decode") else str(curr_an.rrname).rstrip(".")
                        rrtype = DNS_TYPES.get(curr_an.type, f"TYPE_{curr_an.type}")
                        rdata = str(curr_an.rdata) if hasattr(curr_an, "rdata") else ""
                        answers.append(f"{rrname} {rrtype} {rdata}")
                        curr_an = curr_an.payload if hasattr(curr_an, "payload") and isinstance(curr_an.payload, DNSRR) else None

                details["dns"] = {
                    "id": tx_id,
                    "is_response": is_response,
                    "rcode": rcode_name,
                    "rcode_val": rcode_val,
                    "queries": queries,
                    "answers": answers
                }

                first_q = queries[0] if queries else {"name": "unknown", "type": ""}
                if is_response:
                    ans_summary = f" {len(answers)} ans" if answers else ""
                    info_parts = [f"DNS Standard response {tx_id} {rcode_name}{ans_summary} {first_q['type']} {first_q['name']}"]
                else:
                    info_parts = [f"DNS Standard query {tx_id} {first_q['type']} {first_q['name']}"]

            # Common application layer detection (HTTP, TLS, etc.)
            http_headers_dict: Dict[str, str] = {}
            if TCP in pkt and (src_port in (80, 8080) or dst_port in (80, 8080)):
                if pkt[TCP].payload:
                    try:
                        raw_bytes = bytes(pkt[TCP].payload)
                        if any(raw_bytes.startswith(m) for m in [b"GET ", b"POST ", b"HTTP/1.", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS "]):
                            proto = "HTTP"
                            lines_raw = raw_bytes.split(b"\r\n")
                            first_line = lines_raw[0].decode("utf-8", errors="replace")
                            info_parts = [f"HTTP {first_line[:80]}"]
                            http_headers_dict["Request/Status Line"] = first_line[:120]
                            for hdr_line in lines_raw[1:10]:
                                if not hdr_line:
                                    break
                                decoded_hdr = hdr_line.decode("utf-8", errors="replace")
                                if ":" in decoded_hdr:
                                    hk, hv = decoded_hdr.split(":", 1)
                                    if hk.strip().lower() in ("host", "user-agent", "content-type", "content-length", "server", "accept"):
                                        http_headers_dict[hk.strip()] = hv.strip()[:120]
                            details["http"] = http_headers_dict
                    except Exception:
                        pass
            elif TCP in pkt and (src_port in (443, 8443) or dst_port in (443, 8443)):
                proto = "TLS"

            # Build structured layer tree with real byte offsets for frontend inspection
            layers_tree = [
                {
                    "name": f"Frame {packet_number}",
                    "summary": f"{wire_len} bytes on wire ({wire_len * 8} bits), {cap_len} bytes captured",
                    "byte_start": 0,
                    "byte_end": min(cap_len, 256),
                    "fields": {
                        "Frame Number": packet_number,
                        "Wire Length": f"{wire_len} bytes ({wire_len * 8} bits)",
                        "Captured Length": f"{cap_len} bytes ({cap_len * 8} bits)",
                        "Epoch Time": f"{ts:.6f} seconds",
                        "Protocols in Frame": proto,
                    },
                }
            ]

            cursor = 0
            if pkt.haslayer(Ether):
                eth_end = min(cap_len, 14)
                layers_tree.append({
                    "name": "Ethernet II",
                    "summary": f"Src: {getattr(pkt[Ether], 'src', '')}, Dst: {getattr(pkt[Ether], 'dst', '')}",
                    "byte_start": 0,
                    "byte_end": eth_end,
                    "field_offsets": {
                        "Destination MAC": [0, 6],
                        "Source MAC": [6, 12],
                        "Type": [12, 14],
                    },
                    "fields": {
                        "Destination MAC": getattr(pkt[Ether], "dst", ""),
                        "Source MAC": getattr(pkt[Ether], "src", ""),
                        "Type": f"0x{getattr(pkt[Ether], 'type', 0):04x}",
                    },
                })
                cursor = 14

            l3_start = cursor
            l4_start = cursor
            if IP in pkt:
                ihl_bytes = (getattr(pkt[IP], "ihl", 5) or 5) * 4
                l4_start = min(cap_len, l3_start + ihl_bytes)
                layers_tree.append({
                    "name": "Internet Protocol Version 4 (IPv4)",
                    "summary": f"Src: {pkt[IP].src}, Dst: {pkt[IP].dst}",
                    "byte_start": l3_start,
                    "byte_end": l4_start,
                    "field_offsets": {
                        "Version": [l3_start, l3_start + 1],
                        "Header Length": [l3_start, l3_start + 1],
                        "Total Length": [l3_start + 2, l3_start + 4],
                        "Identification": [l3_start + 4, l3_start + 6],
                        "Time to Live (TTL)": [l3_start + 8, l3_start + 9],
                        "Protocol": [l3_start + 9, l3_start + 10],
                        "Source IP": [l3_start + 12, l3_start + 16],
                        "Destination IP": [l3_start + 16, l3_start + 20],
                    },
                    "fields": {
                        "Version": 4,
                        "Header Length": f"{ihl_bytes} bytes",
                        "Total Length": f"{pkt[IP].len} bytes",
                        "Identification": f"0x{pkt[IP].id:04x} ({pkt[IP].id})",
                        "Time to Live (TTL)": pkt[IP].ttl,
                        "Protocol": pkt[IP].proto,
                        "Source IP": pkt[IP].src,
                        "Destination IP": pkt[IP].dst,
                    },
                })
            elif IPv6 in pkt:
                l4_start = min(cap_len, l3_start + 40)
                layers_tree.append({
                    "name": "Internet Protocol Version 6 (IPv6)",
                    "summary": f"Src: {pkt[IPv6].src}, Dst: {pkt[IPv6].dst}",
                    "byte_start": l3_start,
                    "byte_end": l4_start,
                    "field_offsets": {
                        "Hop Limit": [l3_start + 7, l3_start + 8],
                        "Source IP": [l3_start + 8, l3_start + 24],
                        "Destination IP": [l3_start + 24, l3_start + 40],
                    },
                    "fields": {
                        "Hop Limit": pkt[IPv6].hlim,
                        "Source IP": pkt[IPv6].src,
                        "Destination IP": pkt[IPv6].dst,
                    },
                })
            elif ARP in pkt:
                l4_start = min(cap_len, l3_start + 28)
                layers_tree.append({
                    "name": "Address Resolution Protocol (ARP)",
                    "summary": f"{details.get('arp_op', 'ARP')} {src_ip} -> {dst_ip}",
                    "byte_start": l3_start,
                    "byte_end": l4_start,
                    "fields": {
                        "Hardware Type": pkt[ARP].hwtype,
                        "Protocol Type": f"0x{pkt[ARP].ptype:04x}",
                        "Opcode": "request (1)" if pkt[ARP].op == 1 else f"reply ({pkt[ARP].op})",
                        "Sender MAC": pkt[ARP].hwsrc,
                        "Sender IP": pkt[ARP].psrc,
                        "Target MAC": pkt[ARP].hwdst,
                        "Target IP": pkt[ARP].pdst,
                    },
                })

            l4_end = l4_start
            if TCP in pkt:
                tcp_hdr_len = ((getattr(pkt[TCP], "dataofs", 5) or 5) * 4)
                l4_end = min(cap_len, l4_start + tcp_hdr_len)
                layers_tree.append({
                    "name": "Transmission Control Protocol (TCP)",
                    "summary": f"Src Port: {pkt[TCP].sport}, Dst Port: {pkt[TCP].dport}, Seq: {pkt[TCP].seq}, Ack: {pkt[TCP].ack}, Len: {payload_len}",
                    "byte_start": l4_start,
                    "byte_end": l4_end,
                    "field_offsets": {
                        "Source Port": [l4_start, l4_start + 2],
                        "Destination Port": [l4_start + 2, l4_start + 4],
                        "Sequence Number": [l4_start + 4, l4_start + 8],
                        "Acknowledgment Number": [l4_start + 8, l4_start + 12],
                        "Flags": [l4_start + 13, l4_start + 14],
                        "Window Size": [l4_start + 14, l4_start + 16],
                    },
                    "fields": {
                        "Source Port": pkt[TCP].sport,
                        "Destination Port": pkt[TCP].dport,
                        "Sequence Number": pkt[TCP].seq,
                        "Acknowledgment Number": pkt[TCP].ack,
                        "Header Length": f"{tcp_hdr_len} bytes",
                        "Flags": flag_list,
                        "Window Size": pkt[TCP].window,
                        "Payload Length": payload_len,
                    },
                })
            elif UDP in pkt:
                l4_end = min(cap_len, l4_start + 8)
                layers_tree.append({
                    "name": "User Datagram Protocol (UDP)",
                    "summary": f"Src Port: {pkt[UDP].sport}, Dst Port: {pkt[UDP].dport}, Len: {payload_len}",
                    "byte_start": l4_start,
                    "byte_end": l4_end,
                    "field_offsets": {
                        "Source Port": [l4_start, l4_start + 2],
                        "Destination Port": [l4_start + 2, l4_start + 4],
                        "Length": [l4_start + 4, l4_start + 6],
                    },
                    "fields": {
                        "Source Port": pkt[UDP].sport,
                        "Destination Port": pkt[UDP].dport,
                        "Length": pkt[UDP].len,
                        "Payload Length": payload_len,
                    },
                })
            elif ICMP in pkt:
                l4_end = min(cap_len, l4_start + 8)
                layers_tree.append({
                    "name": "Internet Control Message Protocol (ICMP)",
                    "summary": f"{code_desc} (type {pkt[ICMP].type}, code {pkt[ICMP].code})",
                    "byte_start": l4_start,
                    "byte_end": l4_end,
                    "field_offsets": {
                        "Type": [l4_start, l4_start + 1],
                        "Code": [l4_start + 1, l4_start + 2],
                    },
                    "fields": {
                        "Type": pkt[ICMP].type,
                        "Code": pkt[ICMP].code,
                        "Description": code_desc,
                    },
                })

            if DNS in pkt:
                layers_tree.append({
                    "name": "Domain Name System (DNS)",
                    "summary": "response" if is_response else "query",
                    "byte_start": l4_end,
                    "byte_end": min(cap_len, 256),
                    "fields": {
                        "Transaction ID": tx_id,
                        "Is Response": is_response,
                        "Response Code": rcode_name,
                        "Queries": [f"{q['name']} ({q['type']})" for q in queries],
                        "Answers": answers,
                    },
                })
            elif http_headers_dict:
                layers_tree.append({
                    "name": "Hypertext Transfer Protocol (HTTP)",
                    "summary": http_headers_dict.get("Request/Status Line", ""),
                    "byte_start": l4_end,
                    "byte_end": min(cap_len, 256),
                    "fields": http_headers_dict,
                })
            elif proto == "TLS" and cap_len > l4_end:
                layers_tree.append({
                    "name": "Transport Layer Security (TLS Metadata)",
                    "summary": "Encrypted TLS Record / Session Traffic",
                    "byte_start": l4_end,
                    "byte_end": min(cap_len, 256),
                    "fields": {
                        "Port": dst_port if dst_port in (443, 8443) else src_port,
                        "Encrypted Payload Length": f"{max(0, cap_len - l4_end)} bytes",
                        "Privacy Note": "Encrypted payload bytes are not decrypted.",
                    },
                })

            details["layers_tree"] = layers_tree
            try:
                raw_pkt_bytes = bytes(pkt)
                details["hex_dump"] = format_hex_dump(raw_pkt_bytes, max_bytes=256)
                details["raw_hex"] = raw_pkt_bytes[:256].hex()
            except Exception:
                details["hex_dump"] = ""
                details["raw_hex"] = ""

            info = " | ".join(info_parts) if info_parts else f"{proto} Packet length {cap_len} bytes"

            yield ParsedPacketData(
                packet_number=packet_number,
                timestamp=ts,
                length=cap_len,
                original_length=wire_len,
                protocol=proto,
                src_ip=src_ip or "unknown",
                dst_ip=dst_ip or "unknown",
                src_port=src_port,
                dst_port=dst_port,
                tcp_flags=tcp_flags_str,
                info=info,
                details=details,
                warnings=warnings
            )
