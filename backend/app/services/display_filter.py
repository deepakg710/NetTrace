"""
NetTrace Display-Filter Engine
==============================
A safe, deterministic tokenizer, recursive-descent AST parser, validator,
SQLAlchemy expression compiler, and in-memory packet evaluator for
Wireshark-like display filters. Never uses eval() or exec().
"""

import ipaddress
import json
from dataclasses import dataclass
from typing import List, Optional, Union, Dict, Any
from sqlalchemy import or_, and_, not_
from app.models.models import Packet


class DisplayFilterError(ValueError):
    """Raised when a display filter has a syntax or validation error."""

    def __init__(self, message: str, position: int = 0):
        super().__init__(message)
        self.message = message
        self.position = position


# Documented Field Registry
FIELD_REGISTRY: Dict[str, Dict[str, Any]] = {
    # Protocol existence tests
    "tcp": {"type": "protocol", "description": "Match packets containing TCP header or payload"},
    "udp": {"type": "protocol", "description": "Match packets containing UDP header or payload"},
    "dns": {"type": "protocol", "description": "Match Domain Name System queries and responses"},
    "icmp": {"type": "protocol", "description": "Match ICMP diagnostic/control packets"},
    "arp": {"type": "protocol", "description": "Match Address Resolution Protocol frames"},
    "http": {"type": "protocol", "description": "Match HTTP web traffic"},
    "tls": {"type": "protocol", "description": "Match TLS / HTTPS encrypted traffic"},
    "https": {"type": "protocol", "description": "Alias for tls (HTTPS traffic)"},
    "ipv4": {"type": "protocol", "description": "Match IPv4 packets"},
    "ip": {"type": "protocol", "description": "Match IP packets"},
    "ipv6": {"type": "protocol", "description": "Match IPv6 packets"},
    # IP layer fields
    "ip.addr": {"type": "ip", "description": "Source or Destination IP address (e.g. ip.addr == 192.168.1.10)"},
    "ip.src": {"type": "ip", "description": "Source IP address (e.g. ip.src == 192.168.1.10)"},
    "ip.dst": {"type": "ip", "description": "Destination IP address (e.g. ip.dst == 10.0.0.5)"},
    "ip.ttl": {"type": "int", "min": 0, "max": 255, "description": "IPv4 Time to Live (TTL)"},
    # TCP / UDP Port & Header fields
    "port": {"type": "port", "description": "TCP or UDP source or destination port"},
    "tcp.port": {"type": "port", "description": "TCP source or destination port (e.g. tcp.port == 443)"},
    "tcp.srcport": {"type": "port", "description": "TCP source port"},
    "tcp.dstport": {"type": "port", "description": "TCP destination port"},
    "udp.port": {"type": "port", "description": "UDP source or destination port (e.g. udp.port == 53)"},
    "udp.srcport": {"type": "port", "description": "UDP source port"},
    "udp.dstport": {"type": "port", "description": "UDP destination port"},
    "tcp.seq": {"type": "int", "min": 0, "description": "TCP sequence number"},
    "tcp.ack": {"type": "int", "min": 0, "description": "TCP acknowledgment number"},
    "tcp.window": {"type": "int", "min": 0, "description": "TCP window size"},
    # TCP Flags
    "tcp.flags": {"type": "string", "description": "TCP flags string (e.g. tcp.flags contains \"SYN\")"},
    "tcp.flags.syn": {"type": "flag", "flag": "SYN", "description": "TCP SYN flag set (1 or 0)"},
    "tcp.flags.ack": {"type": "flag", "flag": "ACK", "description": "TCP ACK flag set (1 or 0)"},
    "tcp.flags.reset": {"type": "flag", "flag": "RST", "description": "TCP RST flag set (1 or 0)"},
    "tcp.flags.rst": {"type": "flag", "flag": "RST", "description": "Alias for tcp.flags.reset"},
    "tcp.flags.fin": {"type": "flag", "flag": "FIN", "description": "TCP FIN flag set (1 or 0)"},
    "tcp.flags.push": {"type": "flag", "flag": "PSH", "description": "TCP PSH flag set (1 or 0)"},
    "tcp.flags.psh": {"type": "flag", "flag": "PSH", "description": "Alias for tcp.flags.push"},
    "tcp.flags.urg": {"type": "flag", "flag": "URG", "description": "TCP URG flag set (1 or 0)"},
    # Frame fields
    "frame.number": {"type": "int", "min": 1, "description": "1-indexed packet number in capture"},
    "frame.len": {"type": "int", "min": 0, "description": "Captured packet frame length in bytes"},
    "frame.time_relative": {"type": "float", "min": 0.0, "description": "Relative timestamp in seconds from capture start"},
    "frame.info": {"type": "string", "description": "Packet summary info text"},
    "frame": {"type": "string", "description": "Full frame summary or decoded details substring search"},
    # DNS fields
    "dns.qry.name": {"type": "string", "description": "Queried DNS domain name"},
    "dns.rcode": {"type": "string", "description": "DNS response code name (NOERROR, NXDOMAIN, SERVFAIL)"},
}

ALLOWED_OPERATORS_BY_TYPE: Dict[str, set] = {
    "protocol": set(),
    "ip": {"==", "!=", "contains"},
    "port": {"==", "!=", ">", ">=", "<", "<="},
    "int": {"==", "!=", ">", ">=", "<", "<="},
    "float": {"==", "!=", ">", ">=", "<", "<="},
    "flag": {"==", "!="},
    "string": {"==", "!=", "contains"},
}


@dataclass
class Token:
    kind: str  # LPAREN, RPAREN, AND, OR, NOT, OP, IDENT, STRING, VALUE
    value: str
    pos: int


# AST Node Definitions
@dataclass
class BinaryLogicNode:
    op: str  # 'AND' or 'OR'
    left: "ASTNode"
    right: "ASTNode"


@dataclass
class NotNode:
    operand: "ASTNode"


@dataclass
class ProtocolNode:
    protocol: str


@dataclass
class ComparisonNode:
    field: str
    field_type: str
    op: str
    value: Union[str, int, float, bool]


ASTNode = Union[BinaryLogicNode, NotNode, ProtocolNode, ComparisonNode]


def tokenize_display_filter(expr: str) -> List[Token]:
    tokens: List[Token] = []
    i = 0
    n = len(expr)

    while i < n:
        ch = expr[i]
        if ch.isspace():
            i += 1
            continue

        if ch == "(":
            tokens.append(Token("LPAREN", "(", i))
            i += 1
            continue
        if ch == ")":
            tokens.append(Token("RPAREN", ")", i))
            i += 1
            continue

        # Multi-character logical / comparison operators
        two = expr[i : i + 2]
        if two == "&&":
            tokens.append(Token("AND", "&&", i))
            i += 2
            continue
        if two == "||":
            tokens.append(Token("OR", "||", i))
            i += 2
            continue
        if two in ("==", "!=", ">=", "<="):
            tokens.append(Token("OP", two, i))
            i += 2
            continue

        if ch == "!":
            tokens.append(Token("NOT", "!", i))
            i += 1
            continue
        if ch in (">", "<"):
            tokens.append(Token("OP", ch, i))
            i += 1
            continue

        if ch == "=":
            raise DisplayFilterError(
                "Single '=' is not a valid operator. Use '==' for equality comparison.",
                i,
            )

        # Quoted string literal
        if ch in ('"', "'"):
            quote_char = ch
            start = i
            i += 1
            buf = []
            while i < n and expr[i] != quote_char:
                if expr[i] == "\\" and i + 1 < n:
                    i += 1
                buf.append(expr[i])
                i += 1
            if i >= n:
                raise DisplayFilterError("Unterminated string literal in filter expression.", start)
            i += 1  # consume closing quote
            tokens.append(Token("STRING", "".join(buf), start))
            continue

        # Word / identifier / IP / number token
        start = i
        while i < n and (not expr[i].isspace()) and expr[i] not in "()!&|=><\"'":
            i += 1
        word = expr[start:i]
        if not word:
            raise DisplayFilterError(f"Unexpected character '{expr[i]}' at position {i}.", i)

        lower_w = word.lower()
        if lower_w == "and":
            tokens.append(Token("AND", "and", start))
        elif lower_w == "or":
            tokens.append(Token("OR", "or", start))
        elif lower_w == "not":
            tokens.append(Token("NOT", "not", start))
        elif lower_w == "contains":
            tokens.append(Token("OP", "contains", start))
        elif lower_w in ("eq", "ne", "gt", "ge", "lt", "le"):
            op_map = {"eq": "==", "ne": "!=", "gt": ">", "ge": ">=", "lt": "<", "le": "<="}
            tokens.append(Token("OP", op_map[lower_w], start))
        else:
            tokens.append(Token("IDENT", word, start))

    return tokens


def _validate_and_convert_value(
    field_name: str, field_meta: Dict[str, Any], op: str, val_token: Token
) -> Union[str, int, float, bool]:
    ftype = field_meta["type"]
    raw_val = val_token.value

    if ftype == "ip":
        if op == "contains":
            if not raw_val:
                raise DisplayFilterError(f"Empty value for '{field_name} contains'.", val_token.pos)
            return raw_val
        try:
            ip_obj = ipaddress.ip_address(raw_val)
            return str(ip_obj)
        except ValueError:
            raise DisplayFilterError(
                f"Invalid IP address '{raw_val}' for field '{field_name}'. Expected IPv4 or IPv6 address (e.g. 192.168.1.10).",
                val_token.pos,
            )

    if ftype == "port":
        try:
            port_num = int(raw_val)
        except ValueError:
            raise DisplayFilterError(
                f"Invalid port number '{raw_val}' for field '{field_name}'. Must be an integer between 0 and 65535.",
                val_token.pos,
            )
        if not (0 <= port_num <= 65535):
            raise DisplayFilterError(
                f"Port number {port_num} out of valid range (0–65535) for field '{field_name}'.",
                val_token.pos,
            )
        return port_num

    if ftype == "int":
        try:
            int_val = int(raw_val)
        except ValueError:
            raise DisplayFilterError(
                f"Invalid integer value '{raw_val}' for field '{field_name}'.",
                val_token.pos,
            )
        min_v = field_meta.get("min")
        max_v = field_meta.get("max")
        if min_v is not None and int_val < min_v:
            raise DisplayFilterError(
                f"Value {int_val} for '{field_name}' must be >= {min_v}.",
                val_token.pos,
            )
        if max_v is not None and int_val > max_v:
            raise DisplayFilterError(
                f"Value {int_val} for '{field_name}' must be <= {max_v}.",
                val_token.pos,
            )
        return int_val

    if ftype == "float":
        try:
            float_val = float(raw_val)
        except ValueError:
            raise DisplayFilterError(
                f"Invalid numeric value '{raw_val}' for field '{field_name}'.",
                val_token.pos,
            )
        return float_val

    if ftype == "flag":
        low = raw_val.lower()
        if low in ("1", "true", "yes", "set"):
            return True
        if low in ("0", "false", "no", "unset"):
            return False
        raise DisplayFilterError(
            f"Invalid flag value '{raw_val}' for '{field_name}'. Use 1 (set) or 0 (unset).",
            val_token.pos,
        )

    return str(raw_val)


class _Parser:
    def __init__(self, tokens: List[Token]):
        self.tokens = tokens
        self.pos = 0

    def current(self) -> Optional[Token]:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def consume(self) -> Token:
        tok = self.tokens[self.pos]
        self.pos += 1
        return tok

    def parse(self) -> ASTNode:
        if not self.tokens:
            raise DisplayFilterError("Empty filter expression.", 0)
        node = self.parse_or()
        rem = self.current()
        if rem is not None:
            raise DisplayFilterError(
                f"Unexpected token '{rem.value}' at position {rem.pos}. Combine clauses with '&&' or '||'.",
                rem.pos,
            )
        return node

    def parse_or(self) -> ASTNode:
        left = self.parse_and()
        while self.current() is not None and self.current().kind == "OR":
            op_tok = self.consume()
            if self.current() is None:
                raise DisplayFilterError(
                    f"Missing right-hand expression after '{op_tok.value}'.",
                    op_tok.pos,
                )
            right = self.parse_and()
            left = BinaryLogicNode("OR", left, right)
        return left

    def parse_and(self) -> ASTNode:
        left = self.parse_not()
        while self.current() is not None and self.current().kind == "AND":
            op_tok = self.consume()
            if self.current() is None:
                raise DisplayFilterError(
                    f"Missing right-hand expression after '{op_tok.value}'.",
                    op_tok.pos,
                )
            right = self.parse_not()
            left = BinaryLogicNode("AND", left, right)
        return left

    def parse_not(self) -> ASTNode:
        tok = self.current()
        if tok is not None and tok.kind == "NOT":
            self.consume()
            if self.current() is None:
                raise DisplayFilterError(
                    f"Missing expression after '{tok.value}' operator.",
                    tok.pos,
                )
            return NotNode(self.parse_not())
        return self.parse_primary()

    def parse_primary(self) -> ASTNode:
        tok = self.current()
        if tok is None:
            raise DisplayFilterError("Unexpected end of filter expression.", 0)

        if tok.kind == "LPAREN":
            open_tok = self.consume()
            if self.current() is not None and self.current().kind == "RPAREN":
                raise DisplayFilterError("Empty parentheses '()' in filter expression.", open_tok.pos)
            inner = self.parse_or()
            close_tok = self.current()
            if close_tok is None or close_tok.kind != "RPAREN":
                raise DisplayFilterError(
                    f"Unclosed parenthesis '(' starting at position {open_tok.pos}.",
                    open_tok.pos,
                )
            self.consume()
            return inner

        if tok.kind != "IDENT":
            raise DisplayFilterError(
                f"Expected field or protocol name, but found '{tok.value}' at position {tok.pos}.",
                tok.pos,
            )

        ident_tok = self.consume()
        field_name = ident_tok.value.lower()
        if field_name not in FIELD_REGISTRY:
            raise DisplayFilterError(
                f"Unknown filter field or protocol '{ident_tok.value}'. "
                f"Try fields like ip.addr, ip.src, ip.dst, tcp.port, udp.port, dns, tcp, tcp.flags.syn, frame.number, frame.len.",
                ident_tok.pos,
            )

        field_meta = FIELD_REGISTRY[field_name]
        ftype = field_meta["type"]

        next_tok = self.current()
        if next_tok is not None and next_tok.kind == "OP":
            op_tok = self.consume()
            if ftype == "protocol":
                raise DisplayFilterError(
                    f"Protocol filter '{field_name}' does not take comparison operator '{op_tok.value}'. "
                    f"Use '{field_name}' alone or compare a specific field like '{field_name}.port == 80'.",
                    op_tok.pos,
                )
            allowed_ops = ALLOWED_OPERATORS_BY_TYPE.get(ftype, set())
            if op_tok.value not in allowed_ops:
                raise DisplayFilterError(
                    f"Operator '{op_tok.value}' is not supported for field '{field_name}' (type {ftype}).",
                    op_tok.pos,
                )
            val_tok = self.current()
            if val_tok is None or val_tok.kind not in ("IDENT", "STRING", "VALUE"):
                raise DisplayFilterError(
                    f"Missing value after '{field_name} {op_tok.value}'.",
                    op_tok.pos,
                )
            self.consume()
            typed_val = _validate_and_convert_value(field_name, field_meta, op_tok.value, val_tok)
            return ComparisonNode(field=field_name, field_type=ftype, op=op_tok.value, value=typed_val)

        # Bare identifier without operator
        if ftype == "protocol":
            return ProtocolNode(protocol=field_name)
        if ftype == "flag":
            return ComparisonNode(field=field_name, field_type="flag", op="==", value=True)

        raise DisplayFilterError(
            f"Field '{field_name}' requires a comparison operator and value (e.g. {field_name} == ...).",
            ident_tok.pos,
        )


def parse_display_filter(expr: str) -> ASTNode:
    """Tokenizes, parses, and validates a display-filter string into an AST."""
    tokens = tokenize_display_filter(expr)
    parser = _Parser(tokens)
    return parser.parse()


def compile_to_sqlalchemy(node: ASTNode):
    """Compiles a validated Display-Filter AST into a SQLAlchemy filter expression on Packet."""
    if isinstance(node, BinaryLogicNode):
        if node.op == "AND":
            return and_(compile_to_sqlalchemy(node.left), compile_to_sqlalchemy(node.right))
        return or_(compile_to_sqlalchemy(node.left), compile_to_sqlalchemy(node.right))

    if isinstance(node, NotNode):
        return not_(compile_to_sqlalchemy(node.operand))

    if isinstance(node, ProtocolNode):
        p = node.protocol.upper()
        if p in ("IPV4", "IP"):
            return or_(
                Packet.protocol.in_(["IPv4", "TCP", "UDP", "DNS", "HTTP", "TLS", "TLS/HTTPS", "ICMP"]),
                Packet.details_json.ilike('%"ip_ttl"%'),
            )
        if p == "IPV6":
            return or_(Packet.protocol == "IPv6", Packet.details_json.ilike('%"hop_limit"%'))
        if p == "TCP":
            return or_(
                Packet.protocol.in_(["TCP", "HTTP", "TLS", "TLS/HTTPS"]),
                Packet.tcp_flags.isnot(None) & (Packet.tcp_flags != ""),
            )
        if p == "UDP":
            return or_(
                Packet.protocol.in_(["UDP", "DNS"]),
                Packet.details_json.ilike('%"udp"%'),
            )
        if p in ("TLS", "HTTPS"):
            return or_(
                Packet.protocol.in_(["TLS", "TLS/HTTPS"]),
                Packet.src_port == 443,
                Packet.dst_port == 443,
            )
        return Packet.protocol.ilike(f"%{p}%")

    if isinstance(node, ComparisonNode):
        f = node.field
        op = node.op
        v = node.value

        if f == "ip.addr":
            if op == "==":
                return or_(Packet.src_ip == str(v), Packet.dst_ip == str(v))
            if op == "!=":
                return and_(Packet.src_ip != str(v), Packet.dst_ip != str(v))
            if op == "contains":
                return or_(Packet.src_ip.ilike(f"%{v}%"), Packet.dst_ip.ilike(f"%{v}%"))

        if f == "ip.src":
            return _compare_col(Packet.src_ip, op, str(v))
        if f == "ip.dst":
            return _compare_col(Packet.dst_ip, op, str(v))

        if f in ("port", "tcp.port", "udp.port"):
            proto_guard = None
            if f == "tcp.port":
                proto_guard = or_(
                    Packet.protocol.in_(["TCP", "HTTP", "TLS", "TLS/HTTPS"]),
                    Packet.tcp_flags != "",
                )
            elif f == "udp.port":
                proto_guard = or_(Packet.protocol.in_(["UDP", "DNS"]), Packet.details_json.ilike('%"udp"%'))

            if op == "==":
                port_expr = or_(Packet.src_port == int(v), Packet.dst_port == int(v))
            elif op == "!=":
                port_expr = and_(
                    Packet.src_port.isnot(None),
                    Packet.dst_port.isnot(None),
                    Packet.src_port != int(v),
                    Packet.dst_port != int(v),
                )
            else:
                port_expr = or_(
                    _compare_col(Packet.src_port, op, int(v)),
                    _compare_col(Packet.dst_port, op, int(v)),
                )
            return and_(proto_guard, port_expr) if proto_guard is not None else port_expr

        if f in ("tcp.srcport", "udp.srcport"):
            return _compare_col(Packet.src_port, op, int(v))
        if f in ("tcp.dstport", "udp.dstport"):
            return _compare_col(Packet.dst_port, op, int(v))

        if f.startswith("tcp.flags."):
            flag_code = FIELD_REGISTRY[f]["flag"]
            want_set = (v is True and op == "==") or (v is False and op == "!=")
            has_flag = Packet.tcp_flags.ilike(f"%{flag_code}%")
            if want_set:
                return has_flag
            return or_(Packet.tcp_flags.is_(None), not_(has_flag))

        if f == "tcp.flags":
            return _compare_col(Packet.tcp_flags, op, str(v))

        if f == "frame.number":
            return _compare_col(Packet.packet_number, op, int(v))
        if f == "frame.len":
            return _compare_col(Packet.length, op, int(v))
        if f == "frame.time_relative":
            return _compare_col(Packet.rel_time, op, float(v))
        if f == "frame.info":
            return _compare_col(Packet.info, op, str(v))
        if f == "frame":
            return or_(
                Packet.info.ilike(f"%{v}%"),
                Packet.details_json.ilike(f"%{v}%"),
                Packet.src_ip.ilike(f"%{v}%"),
                Packet.dst_ip.ilike(f"%{v}%"),
            )
        if f in ("dns.qry.name", "dns.rcode"):
            return and_(
                Packet.protocol == "DNS",
                or_(Packet.info.ilike(f"%{v}%"), Packet.details_json.ilike(f"%{v}%")),
            )

        # Fallback for deep JSON fields (ip.ttl, tcp.seq, tcp.ack, tcp.window)
        return Packet.details_json.ilike(f"%{v}%")

    raise DisplayFilterError("Unsupported AST node.")


def _compare_col(col, op: str, val):
    if op == "==":
        return col == val
    if op == "!=":
        return col != val
    if op == ">":
        return col > val
    if op == ">=":
        return col >= val
    if op == "<":
        return col < val
    if op == "<=":
        return col <= val
    if op == "contains":
        return col.ilike(f"%{val}%")
    return col == val


def evaluate_packet_dict(node: ASTNode, pkt: Dict[str, Any]) -> bool:
    """
    Evaluates a parsed Display-Filter AST against an in-memory packet dictionary
    (or PacketSchema dict). Ensures exact post-filtering for deep JSON fields
    and deterministic unit testing.
    """
    if isinstance(node, BinaryLogicNode):
        if node.op == "AND":
            return evaluate_packet_dict(node.left, pkt) and evaluate_packet_dict(node.right, pkt)
        return evaluate_packet_dict(node.left, pkt) or evaluate_packet_dict(node.right, pkt)

    if isinstance(node, NotNode):
        return not evaluate_packet_dict(node.operand, pkt)

    proto = str(pkt.get("protocol") or "").upper()
    src_ip = str(pkt.get("src_ip") or "")
    dst_ip = str(pkt.get("dst_ip") or "")
    src_port = pkt.get("src_port")
    dst_port = pkt.get("dst_port")
    tcp_flags_raw = str(pkt.get("tcp_flags") or "")
    flags_set = {fl.strip().upper() for fl in tcp_flags_raw.split(",") if fl.strip()}
    details = pkt.get("details") or {}
    if isinstance(details, str):
        try:
            details = json.loads(details)
        except Exception:
            details = {}

    if isinstance(node, ProtocolNode):
        p = node.protocol.upper()
        if p in ("IPV4", "IP"):
            return proto in ("IPV4", "TCP", "UDP", "DNS", "HTTP", "TLS", "TLS/HTTPS", "ICMP") or "ip_ttl" in details
        if p == "IPV6":
            return proto == "IPV6" or "hop_limit" in details
        if p == "TCP":
            return proto in ("TCP", "HTTP", "TLS", "TLS/HTTPS") or bool(flags_set) or "tcp" in details
        if p == "UDP":
            return proto in ("UDP", "DNS") or "udp" in details
        if p in ("TLS", "HTTPS"):
            return proto in ("TLS", "TLS/HTTPS") or src_port == 443 or dst_port == 443
        return p in proto

    if isinstance(node, ComparisonNode):
        f = node.field
        op = node.op
        v = node.value

        if f == "ip.addr":
            if op == "==":
                return src_ip == str(v) or dst_ip == str(v)
            if op == "!=":
                return src_ip != str(v) and dst_ip != str(v)
            if op == "contains":
                return str(v).lower() in src_ip.lower() or str(v).lower() in dst_ip.lower()

        if f == "ip.src":
            return _eval_cmp(src_ip, op, str(v))
        if f == "ip.dst":
            return _eval_cmp(dst_ip, op, str(v))
        if f == "ip.ttl":
            ttl = details.get("ip_ttl")
            return ttl is not None and _eval_cmp(int(ttl), op, int(v))

        if f in ("port", "tcp.port", "udp.port"):
            if f == "tcp.port" and not (proto in ("TCP", "HTTP", "TLS", "TLS/HTTPS") or bool(flags_set)):
                return False
            if f == "udp.port" and not (proto in ("UDP", "DNS") or "udp" in details):
                return False
            ports = [p for p in (src_port, dst_port) if p is not None]
            if not ports:
                return False
            if op == "!=":
                return all(int(p) != int(v) for p in ports)
            return any(_eval_cmp(int(p), op, int(v)) for p in ports)

        if f in ("tcp.srcport", "udp.srcport"):
            return src_port is not None and _eval_cmp(int(src_port), op, int(v))
        if f in ("tcp.dstport", "udp.dstport"):
            return dst_port is not None and _eval_cmp(int(dst_port), op, int(v))

        if f.startswith("tcp.flags."):
            flag_code = FIELD_REGISTRY[f]["flag"]
            is_present = flag_code in flags_set
            return (is_present == bool(v)) if op == "==" else (is_present != bool(v))

        if f == "tcp.flags":
            return _eval_cmp(tcp_flags_raw, op, str(v))

        if f in ("tcp.seq", "tcp.ack", "tcp.window"):
            tcp_meta = details.get("tcp") or {}
            key_name = f.split(".")[1]
            actual = tcp_meta.get(key_name)
            return actual is not None and _eval_cmp(int(actual), op, int(v))

        if f == "frame.number":
            return _eval_cmp(int(pkt.get("packet_number", 0)), op, int(v))
        if f == "frame.len":
            return _eval_cmp(int(pkt.get("length", 0)), op, int(v))
        if f == "frame.time_relative":
            return _eval_cmp(float(pkt.get("rel_time", 0.0)), op, float(v))
        if f == "frame.info":
            return _eval_cmp(str(pkt.get("info", "")), op, str(v))
        if f == "frame":
            haystack = f"{pkt.get('info', '')} {src_ip} {dst_ip} {json.dumps(details)}"
            return _eval_cmp(haystack, op, str(v))

        if f == "dns.qry.name":
            dns_meta = details.get("dns") or {}
            queries = dns_meta.get("queries") or []
            qnames = [str(q.get("name", "")) for q in queries]
            return any(_eval_cmp(qn, op, str(v)) for qn in qnames)

        if f == "dns.rcode":
            dns_meta = details.get("dns") or {}
            rcode = str(dns_meta.get("rcode", ""))
            return bool(rcode) and _eval_cmp(rcode, op, str(v))

    return False


def _eval_cmp(actual, op: str, expected) -> bool:
    if isinstance(actual, str) and isinstance(expected, str):
        if op == "==":
            return actual.lower() == expected.lower()
        if op == "!=":
            return actual.lower() != expected.lower()
        if op == "contains":
            return expected.lower() in actual.lower()
    if op == "==":
        return actual == expected
    if op == "!=":
        return actual != expected
    if op == ">":
        return actual > expected
    if op == ">=":
        return actual >= expected
    if op == "<":
        return actual < expected
    if op == "<=":
        return actual <= expected
    return False
