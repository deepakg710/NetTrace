import datetime
from sqlalchemy import Column, String, Integer, Float, Boolean, Text, DateTime, ForeignKey, Index
from sqlalchemy.orm import relationship
from app.database.session import Base

class Capture(Base):
    __tablename__ = "captures"

    id = Column(String(36), primary_key=True, index=True)
    filename = Column(String(255), nullable=False)
    original_filename = Column(String(255), nullable=False)
    file_size_bytes = Column(Integer, nullable=False, default=0)
    upload_time = Column(DateTime, default=datetime.datetime.utcnow)
    status = Column(String(32), default="uploaded", index=True)  # uploaded, analyzing, completed, failed, partial
    error_message = Column(Text, nullable=True)
    packet_count = Column(Integer, default=0)
    start_time = Column(Float, nullable=True)
    end_time = Column(Float, nullable=True)
    duration_seconds = Column(Float, default=0.0)
    link_type = Column(String(64), nullable=True)
    format = Column(String(16), default="pcap")
    metadata_json = Column(Text, default="{}")

    packets = relationship("Packet", back_populates="capture", cascade="all, delete-orphan")
    flows = relationship("Flow", back_populates="capture", cascade="all, delete-orphan")
    endpoints = relationship("Endpoint", back_populates="capture", cascade="all, delete-orphan")
    dns_records = relationship("DNSRecord", back_populates="capture", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="capture", cascade="all, delete-orphan")


class Packet(Base):
    __tablename__ = "packets"

    id = Column(Integer, primary_key=True, autoincrement=True)
    capture_id = Column(String(36), ForeignKey("captures.id", ondelete="CASCADE"), index=True, nullable=False)
    packet_number = Column(Integer, index=True, nullable=False)
    timestamp = Column(Float, index=True, nullable=False)
    rel_time = Column(Float, default=0.0)
    src_ip = Column(String(64), index=True, nullable=True)
    dst_ip = Column(String(64), index=True, nullable=True)
    src_port = Column(Integer, index=True, nullable=True)
    dst_port = Column(Integer, index=True, nullable=True)
    protocol = Column(String(32), index=True, nullable=False)
    length = Column(Integer, nullable=False)
    original_length = Column(Integer, nullable=False)
    tcp_flags = Column(String(64), nullable=True)
    info = Column(String(512), nullable=False, default="")
    details_json = Column(Text, default="{}")

    capture = relationship("Capture", back_populates="packets")

    __table_args__ = (
        Index("ix_packets_capture_number", "capture_id", "packet_number"),
    )


class Flow(Base):
    __tablename__ = "flows"

    id = Column(Integer, primary_key=True, autoincrement=True)
    capture_id = Column(String(36), ForeignKey("captures.id", ondelete="CASCADE"), index=True, nullable=False)
    flow_id = Column(String(128), index=True, nullable=False)
    protocol = Column(String(16), nullable=False)
    src_ip = Column(String(64), nullable=False)
    src_port = Column(Integer, nullable=True)
    dst_ip = Column(String(64), nullable=False)
    dst_port = Column(Integer, nullable=True)
    packet_count = Column(Integer, default=0)
    byte_count = Column(Integer, default=0)
    src_to_dst_packets = Column(Integer, default=0)
    dst_to_src_packets = Column(Integer, default=0)
    src_to_dst_bytes = Column(Integer, default=0)
    dst_to_src_bytes = Column(Integer, default=0)
    start_time = Column(Float, nullable=False)
    end_time = Column(Float, nullable=False)
    duration = Column(Float, default=0.0)
    state = Column(String(64), default="UNKNOWN")
    handshake_latency_ms = Column(Float, nullable=True)
    retransmissions_count = Column(Integer, default=0)
    details_json = Column(Text, default="{}")

    capture = relationship("Capture", back_populates="flows")


class Endpoint(Base):
    __tablename__ = "endpoints"

    id = Column(Integer, primary_key=True, autoincrement=True)
    capture_id = Column(String(36), ForeignKey("captures.id", ondelete="CASCADE"), index=True, nullable=False)
    ip_address = Column(String(64), index=True, nullable=False)
    packet_count = Column(Integer, default=0)
    byte_count = Column(Integer, default=0)
    sent_packets = Column(Integer, default=0)
    recv_packets = Column(Integer, default=0)
    sent_bytes = Column(Integer, default=0)
    recv_bytes = Column(Integer, default=0)
    first_seen = Column(Float, nullable=False)
    last_seen = Column(Float, nullable=False)
    protocols_json = Column(Text, default="[]")
    flows_count = Column(Integer, default=0)

    capture = relationship("Capture", back_populates="endpoints")


class DNSRecord(Base):
    __tablename__ = "dns_records"

    id = Column(Integer, primary_key=True, autoincrement=True)
    capture_id = Column(String(36), ForeignKey("captures.id", ondelete="CASCADE"), index=True, nullable=False)
    transaction_id = Column(String(32), nullable=False)
    query_name = Column(String(255), index=True, nullable=False)
    query_type = Column(String(16), default="A")
    client_ip = Column(String(64), nullable=False)
    server_ip = Column(String(64), nullable=False)
    query_time = Column(Float, nullable=False)
    response_time = Column(Float, nullable=True)
    rcode = Column(String(32), default="UNANSWERED", index=True)
    is_answered = Column(Boolean, default=False)
    latency_ms = Column(Float, nullable=True)
    query_packet_number = Column(Integer, nullable=False)
    response_packet_number = Column(Integer, nullable=True)
    answers_json = Column(Text, default="[]")

    capture = relationship("Capture", back_populates="dns_records")


class Finding(Base):
    __tablename__ = "findings"

    id = Column(String(36), primary_key=True, index=True)
    capture_id = Column(String(36), ForeignKey("captures.id", ondelete="CASCADE"), index=True, nullable=False)
    category = Column(String(32), index=True, nullable=False)  # TCP, DNS, SCAN, ANOMALY, TRAFFIC, INTEGRITY
    severity = Column(String(32), index=True, nullable=False)  # Informational, Low, Medium, High, Critical
    confidence = Column(String(32), nullable=False, default="High")  # High, Medium, Low
    title = Column(String(255), nullable=False)
    observed_facts = Column(Text, nullable=False)
    supporting_packet_numbers_json = Column(Text, default="[]")
    timestamps_json = Column(Text, default="[]")
    endpoints_json = Column(Text, default="[]")
    ports_json = Column(Text, default="[]")
    rule_name = Column(String(128), nullable=False)
    threshold_val = Column(String(128), nullable=False)
    explanations = Column(Text, nullable=False)
    recommendations = Column(Text, nullable=False)
    limitations = Column(Text, nullable=False)

    capture = relationship("Capture", back_populates="findings")


class DetectorSetting(Base):
    __tablename__ = "detector_settings"

    key = Column(String(64), primary_key=True)
    value_json = Column(Text, nullable=False)
