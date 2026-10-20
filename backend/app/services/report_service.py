import json
import html
from io import BytesIO
from pathlib import Path
from typing import Dict, Any, List
from sqlalchemy.orm import Session

from app.models.models import Capture, Packet, Flow, Endpoint, DNSRecord, Finding
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, HRFlowable
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.pdfgen import canvas

class NumberedCanvas(canvas.Canvas):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_number(num_pages)
            super().showPage()
        super().save()

    def draw_page_number(self, page_count):
        self.saveState()
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#64748b"))
        self.drawString(54, 30, "NetTrace — Network Troubleshooting & Packet Analysis Toolkit")
        self.drawRightString(letter[0] - 54, 30, f"Page {self._pageNumber} of {page_count}")
        self.restoreState()

def generate_json_report(capture: Capture, db: Session) -> Dict[str, Any]:
    meta = json.loads(capture.metadata_json or "{}")
    findings = db.query(Finding).filter(Finding.capture_id == capture.id).all()
    flows = db.query(Flow).filter(Flow.capture_id == capture.id).limit(100).all()
    endpoints = db.query(Endpoint).filter(Endpoint.capture_id == capture.id).limit(100).all()
    dns_recs = db.query(DNSRecord).filter(DNSRecord.capture_id == capture.id).limit(100).all()

    return {
        "report_version": "1.0",
        "generated_at": time_now_iso(),
        "tool": "NetTrace",
        "capture": {
            "id": capture.id,
            "original_filename": capture.original_filename,
            "file_size_bytes": capture.file_size_bytes,
            "upload_time": capture.upload_time.isoformat() if capture.upload_time else None,
            "status": capture.status,
            "packet_count": capture.packet_count,
            "duration_seconds": capture.duration_seconds,
            "start_time": capture.start_time,
            "end_time": capture.end_time,
            "link_type": capture.link_type,
            "format": capture.format
        },
        "summary": meta,
        "findings": [
            {
                "id": f.id,
                "category": f.category,
                "severity": f.severity,
                "confidence": f.confidence,
                "title": f.title,
                "observed_facts": f.observed_facts,
                "supporting_packet_numbers": json.loads(f.supporting_packet_numbers_json or "[]"),
                "timestamps": json.loads(f.timestamps_json or "[]"),
                "endpoints": json.loads(f.endpoints_json or "[]"),
                "ports": json.loads(f.ports_json or "[]"),
                "rule_name": f.rule_name,
                "threshold_val": f.threshold_val,
                "explanations": f.explanations,
                "recommendations": f.recommendations,
                "limitations": f.limitations
            }
            for f in findings
        ],
        "top_flows_sample": [
            {
                "flow_id": fl.flow_id,
                "protocol": fl.protocol,
                "src": f"{fl.src_ip}:{fl.src_port}",
                "dst": f"{fl.dst_ip}:{fl.dst_port}",
                "packets": fl.packet_count,
                "bytes": fl.byte_count,
                "state": fl.state,
                "duration": fl.duration
            }
            for fl in flows[:20]
        ],
        "endpoints_sample": [
            {
                "ip": ep.ip_address,
                "packets": ep.packet_count,
                "bytes": ep.byte_count,
                "protocols": json.loads(ep.protocols_json or "[]")
            }
            for ep in endpoints[:20]
        ],
        "dns_activity_sample": [
            {
                "query_name": d.query_name,
                "rcode": d.rcode,
                "is_answered": d.is_answered,
                "latency_ms": d.latency_ms,
                "query_packet": d.query_packet_number,
                "response_packet": d.response_packet_number
            }
            for d in dns_recs[:20]
        ],
        "methodology": {
            "disclaimer": "Diagnostic heuristics are evidence-based observations. Absence of return packets may be caused by capture boundaries or filters.",
            "tcp_analysis": "Handshakes, resets, and retransmission candidates are tracked via sequence numbers and flags.",
            "dns_analysis": "Transactions correlated via ID, query name, client and server IPs.",
            "scan_detection": "Threshold-based sliding window heuristic tracking distinct ports and target hosts."
        }
    }

def time_now_iso() -> str:
    import datetime
    return datetime.datetime.utcnow().isoformat() + "Z"

def generate_html_report(capture: Capture, db: Session) -> str:
    """
    Generates a responsive, standalone, dark-themed HTML report.
    All user and packet-derived data is safely HTML-escaped.
    """
    meta = json.loads(capture.metadata_json or "{}")
    findings = db.query(Finding).filter(Finding.capture_id == capture.id).all()
    flows = db.query(Flow).filter(Flow.capture_id == capture.id).order_by(Flow.byte_count.desc()).limit(15).all()
    endpoints = db.query(Endpoint).filter(Endpoint.capture_id == capture.id).order_by(Endpoint.byte_count.desc()).limit(15).all()
    dns_recs = db.query(DNSRecord).filter(DNSRecord.capture_id == capture.id).limit(15).all()

    fname = html.escape(capture.original_filename)
    cid = html.escape(capture.id)
    dur = f"{capture.duration_seconds:.2f}s"
    pkts = f"{capture.packet_count:,}"
    bytes_total = f"{meta.get('total_bytes', 0):,} bytes"

    # Severity styling
    def badge(sev: str) -> str:
        colors_map = {
            "Critical": "bg-red-900/60 text-red-300 border-red-700",
            "High": "bg-rose-900/60 text-rose-300 border-rose-700",
            "Medium": "bg-amber-900/60 text-amber-300 border-amber-700",
            "Low": "bg-cyan-900/60 text-cyan-300 border-cyan-700",
            "Informational": "bg-slate-800 text-slate-300 border-slate-700"
        }
        cls = colors_map.get(sev, colors_map["Informational"])
        return f'<span class="inline-block px-2.5 py-0.5 text-xs font-semibold rounded border {cls}">{html.escape(sev)}</span>'

    findings_html = ""
    if findings:
        for f in findings:
            p_nums = json.loads(f.supporting_packet_numbers_json or "[]")
            p_tags = " ".join([f'<span class="bg-slate-800 text-cyan-400 font-mono px-2 py-0.5 rounded text-xs">#{p}</span>' for p in p_nums[:10]])
            findings_html += f"""
            <div class="bg-slate-900/80 border border-slate-800 rounded-lg p-5 mb-4 shadow-sm">
                <div class="flex items-center justify-between mb-2">
                    <div class="flex items-center gap-3">
                        {badge(f.severity)}
                        <span class="text-xs font-mono text-slate-400 bg-slate-950 px-2 py-0.5 rounded">{html.escape(f.category)}</span>
                        <h4 class="text-base font-semibold text-slate-100">{html.escape(f.title)}</h4>
                    </div>
                    <span class="text-xs text-slate-400 font-mono">Confidence: {html.escape(f.confidence)}</span>
                </div>
                <div class="mt-3 text-sm text-slate-300">
                    <p class="font-medium text-slate-400 text-xs uppercase tracking-wide mb-1">Observed Facts</p>
                    <p class="mb-3">{html.escape(f.observed_facts)}</p>
                    <div class="flex items-center gap-2 mb-3">
                        <span class="text-xs text-slate-400 font-medium">Evidence Packets:</span>
                        {p_tags}
                    </div>
                    <div class="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs bg-slate-950/60 p-3 rounded border border-slate-800/80">
                        <div>
                            <span class="font-semibold text-amber-400/90 block mb-1">Possible Explanations:</span>
                            <span class="text-slate-400">{html.escape(f.explanations)}</span>
                        </div>
                        <div>
                            <span class="font-semibold text-cyan-400/90 block mb-1">Recommended Actions:</span>
                            <span class="text-slate-400">{html.escape(f.recommendations)}</span>
                        </div>
                    </div>
                    <div class="mt-2 text-xs text-slate-500 italic">
                        <strong>Limitations:</strong> {html.escape(f.limitations)}
                    </div>
                </div>
            </div>
            """
    else:
        findings_html = """
        <div class="bg-slate-900/50 border border-slate-800 rounded-lg p-8 text-center text-slate-400">
            No diagnostic anomalies or protocol warnings were triggered for this capture under current threshold heuristics.
        </div>
        """

    # Protocol distribution rows
    proto_counts = meta.get("protocol_counts", {})
    proto_rows = "".join([
        f'<tr><td class="py-2 px-3 font-mono text-cyan-300">{html.escape(p)}</td><td class="py-2 px-3 text-right font-mono">{c:,}</td><td class="py-2 px-3 text-right font-mono text-slate-400">{meta.get("protocol_bytes", {}).get(p, 0):,} B</td></tr>'
        for p, c in sorted(proto_counts.items(), key=lambda x: x[1], reverse=True)
    ])

    # Endpoints rows
    ep_rows = "".join([
        f'<tr><td class="py-2 px-3 font-mono text-cyan-300">{html.escape(ep.ip_address)}</td><td class="py-2 px-3 text-right font-mono">{ep.packet_count:,}</td><td class="py-2 px-3 text-right font-mono">{ep.byte_count:,} B</td><td class="py-2 px-3 text-slate-400 font-mono text-xs">{", ".join(json.loads(ep.protocols_json or "[]"))}</td></tr>'
        for ep in endpoints
    ])

    # Flows rows
    flow_rows = "".join([
        f'<tr><td class="py-2 px-3 font-mono text-xs text-slate-300">{html.escape(fl.flow_id)}</td><td class="py-2 px-3 text-cyan-400 font-mono text-xs">{html.escape(fl.protocol)}</td><td class="py-2 px-3 text-xs"><span class="px-2 py-0.5 rounded bg-slate-800 text-slate-300">{html.escape(fl.state)}</span></td><td class="py-2 px-3 text-right font-mono text-xs">{fl.packet_count}</td><td class="py-2 px-3 text-right font-mono text-xs">{fl.byte_count:,} B</td></tr>'
        for fl in flows
    ])

    return f"""<!doctype html>
<html lang="en" class="dark">
<head>
    <meta charset="utf-8"/>
    <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
    <title>NetTrace Analysis Report - {fname}</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        body {{ background-color: #0b0f19; color: #f1f5f9; font-family: ui-sans-serif, system-ui, sans-serif; }}
    </style>
</head>
<body class="p-6 md:p-12 max-w-6xl mx-auto selection:bg-cyan-500/20">
    <header class="border-b border-slate-800 pb-6 mb-8 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
            <div class="flex items-center gap-3">
                <span class="bg-cyan-500/20 text-cyan-400 px-3 py-1 rounded text-xs font-mono font-bold tracking-wider">NETTRACE ANALYSIS REPORT</span>
                <span class="text-xs text-slate-400 font-mono">Format: {html.escape(capture.format.upper())}</span>
            </div>
            <h1 class="text-2xl md:text-3xl font-bold text-slate-100 mt-2">{fname}</h1>
            <p class="text-xs text-slate-400 font-mono mt-1">Capture ID: {cid} | Generated: {time_now_iso()}</p>
        </div>
        <div class="flex gap-4">
            <div class="bg-slate-900 border border-slate-800 px-4 py-2.5 rounded-lg text-right">
                <div class="text-xs text-slate-400 font-mono">PACKETS</div>
                <div class="text-xl font-bold font-mono text-cyan-400">{pkts}</div>
            </div>
            <div class="bg-slate-900 border border-slate-800 px-4 py-2.5 rounded-lg text-right">
                <div class="text-xs text-slate-400 font-mono">DURATION</div>
                <div class="text-xl font-bold font-mono text-slate-200">{dur}</div>
            </div>
            <div class="bg-slate-900 border border-slate-800 px-4 py-2.5 rounded-lg text-right">
                <div class="text-xs text-slate-400 font-mono">TOTAL BYTES</div>
                <div class="text-xl font-bold font-mono text-slate-200">{bytes_total}</div>
            </div>
        </div>
    </header>

    <!-- Scope & Limitations Callout -->
    <section class="bg-slate-900/60 border-l-4 border-cyan-500 rounded-r-lg p-4 mb-8 text-xs text-slate-300">
        <h3 class="font-semibold text-cyan-400 text-sm mb-1">Analysis Scope & Limitations</h3>
        <p>This report documents offline protocol findings derived strictly from uploaded packet headers. Findings represent observed behaviors and heuristic correlations within the captured observation window. Absence of response packets (e.g. in TCP handshakes or DNS queries) may result from asymmetric capture routing, interface drop filters, or truncated recording sessions.</p>
    </section>

    <!-- Findings Section -->
    <section class="mb-10">
        <h2 class="text-lg font-bold text-slate-200 mb-4 flex items-center gap-2">
            <span>Diagnostic Findings & Evidence</span>
            <span class="bg-slate-800 text-slate-400 px-2.5 py-0.5 rounded-full text-xs font-mono">{len(findings)}</span>
        </h2>
        {findings_html}
    </section>

    <!-- Protocol Distribution & Top Endpoints Grid -->
    <div class="grid grid-cols-1 md:grid-cols-2 gap-8 mb-10">
        <section class="bg-slate-900/80 border border-slate-800 rounded-lg p-5">
            <h3 class="text-sm font-semibold text-slate-200 mb-3 uppercase tracking-wide text-xs">Protocol Breakdown</h3>
            <div class="overflow-x-auto">
                <table class="w-full text-left text-xs">
                    <thead>
                        <tr class="border-b border-slate-800 text-slate-400 font-mono">
                            <th class="py-2 px-3">Protocol</th>
                            <th class="py-2 px-3 text-right">Packets</th>
                            <th class="py-2 px-3 text-right">Bytes</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-slate-800/60">
                        {proto_rows}
                    </tbody>
                </table>
            </div>
        </section>

        <section class="bg-slate-900/80 border border-slate-800 rounded-lg p-5">
            <h3 class="text-sm font-semibold text-slate-200 mb-3 uppercase tracking-wide text-xs">Top Communicating Endpoints</h3>
            <div class="overflow-x-auto">
                <table class="w-full text-left text-xs">
                    <thead>
                        <tr class="border-b border-slate-800 text-slate-400 font-mono">
                            <th class="py-2 px-3">IP Address</th>
                            <th class="py-2 px-3 text-right">Packets</th>
                            <th class="py-2 px-3 text-right">Bytes</th>
                            <th class="py-2 px-3">Protocols</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-slate-800/60">
                        {ep_rows}
                    </tbody>
                </table>
            </div>
        </section>
    </div>

    <!-- Top Flows Section -->
    <section class="bg-slate-900/80 border border-slate-800 rounded-lg p-5 mb-10">
        <h3 class="text-sm font-semibold text-slate-200 mb-3 uppercase tracking-wide text-xs">Top Active Conversations (Flows)</h3>
        <div class="overflow-x-auto">
            <table class="w-full text-left text-xs">
                <thead>
                    <tr class="border-b border-slate-800 text-slate-400 font-mono">
                        <th class="py-2 px-3">Conversation</th>
                        <th class="py-2 px-3">Proto</th>
                        <th class="py-2 px-3">State</th>
                        <th class="py-2 px-3 text-right">Packets</th>
                        <th class="py-2 px-3 text-right">Bytes</th>
                    </tr>
                </thead>
                <tbody class="divide-y divide-slate-800/60">
                    {flow_rows}
                </tbody>
            </table>
        </div>
    </section>

    <footer class="border-t border-slate-800 pt-6 text-center text-xs text-slate-500 font-mono">
        Generated by NetTrace • Network Troubleshooting & Packet Analysis Toolkit • Local Offline Engine
    </footer>
</body>
</html>"""

def generate_pdf_report(capture: Capture, db: Session) -> bytes:
    """
    Generates a structured, multi-page PDF analysis report using ReportLab.
    """
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=40,
        rightMargin=40,
        topMargin=40,
        bottomMargin=45
    )

    meta = json.loads(capture.metadata_json or "{}")
    findings = db.query(Finding).filter(Finding.capture_id == capture.id).all()
    flows = db.query(Flow).filter(Flow.capture_id == capture.id).order_by(Flow.byte_count.desc()).limit(10).all()
    endpoints = db.query(Endpoint).filter(Endpoint.capture_id == capture.id).order_by(Endpoint.byte_count.desc()).limit(10).all()

    styles = getSampleStyleSheet()
    
    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=20,
        leading=24,
        textColor=colors.HexColor("#0f172a")
    )

    h2_style = ParagraphStyle(
        "SectionHeading",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=13,
        leading=16,
        textColor=colors.HexColor("#1e293b"),
        spaceBefore=14,
        spaceAfter=6
    )

    body_style = ParagraphStyle(
        "BodyDark",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=12,
        textColor=colors.HexColor("#334155")
    )

    mono_style = ParagraphStyle(
        "MonoText",
        parent=styles["Normal"],
        fontName="Courier",
        fontSize=8,
        leading=10,
        textColor=colors.HexColor("#0f172a")
    )

    callout_style = ParagraphStyle(
        "Callout",
        parent=styles["Normal"],
        fontName="Helvetica-Oblique",
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#475569")
    )

    story = []

    # Title block
    story.append(Paragraph("NETTRACE — Network Analysis Report", title_style))
    story.append(Paragraph(f"<b>File:</b> {html.escape(capture.original_filename)} | <b>Capture ID:</b> {capture.id[:12]} | <b>Format:</b> {capture.format.upper()}", body_style))
    story.append(Spacer(1, 10))

    # Metrics Overview Table
    metrics_data = [
        [
            Paragraph("<b>Total Packets</b>", body_style),
            Paragraph(f"{capture.packet_count:,}", mono_style),
            Paragraph("<b>Duration</b>", body_style),
            Paragraph(f"{capture.duration_seconds:.2f}s", mono_style)
        ],
        [
            Paragraph("<b>Total Bytes</b>", body_style),
            Paragraph(f"{meta.get('total_bytes', 0):,} B", mono_style),
            Paragraph("<b>Status</b>", body_style),
            Paragraph(capture.status.upper(), mono_style)
        ]
    ]
    t_metrics = Table(metrics_data, colWidths=[100, 150, 100, 150])
    t_metrics.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#e2e8f0")),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
    ]))
    story.append(t_metrics)
    story.append(Spacer(1, 10))

    # Scope & Limitations Callout
    story.append(Paragraph(
        "<b>Scope & Limitations:</b> Analysis results are derived offline from parsed PCAP frames. "
        "Missing packets may reflect capture filter restrictions or interface drop counters rather than service failure.",
        callout_style
    ))
    story.append(Spacer(1, 12))

    # Diagnostic Findings
    story.append(Paragraph(f"Diagnostic Findings ({len(findings)})", h2_style))
    if findings:
        for f in findings:
            p_nums = json.loads(f.supporting_packet_numbers_json or "[]")
            p_str = ", ".join([f"#{p}" for p in p_nums[:8]])
            
            sev_color = "#dc2626" if f.severity in ("Critical", "High") else ("#d97706" if f.severity == "Medium" else "#0284c7")
            
            f_content = [
                Paragraph(f"<font color='{sev_color}'><b>[{f.severity.upper()}]</b></font> <b>{html.escape(f.title)}</b> (Rule: {html.escape(f.rule_name)})", body_style),
                Paragraph(f"<b>Observed Facts:</b> {html.escape(f.observed_facts)}", body_style),
                Paragraph(f"<b>Evidence Packets:</b> {p_str}", mono_style),
                Paragraph(f"<b>Possible Explanations:</b> {html.escape(f.explanations)}", callout_style),
                Paragraph(f"<b>Recommendations:</b> {html.escape(f.recommendations)}", body_style),
                Spacer(1, 6)
            ]
            story.append(KeepTogether(f_content))
    else:
        story.append(Paragraph("No diagnostic anomalies were triggered for this capture under active thresholds.", body_style))

    story.append(Spacer(1, 10))

    # Protocol Distribution Table
    story.append(Paragraph("Protocol Breakdown", h2_style))
    proto_counts = meta.get("protocol_counts", {})
    proto_data = [["Protocol", "Packets", "Captured Bytes"]]
    for p, c in sorted(proto_counts.items(), key=lambda x: x[1], reverse=True)[:8]:
        b = meta.get("protocol_bytes", {}).get(p, 0)
        proto_data.append([p, f"{c:,}", f"{b:,} B"])
    
    t_proto = Table(proto_data, colWidths=[150, 150, 200])
    t_proto.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#0f172a")),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 4),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor("#f8fafc"), colors.white]),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ('FONTSIZE', (0, 0), (-1, -1), 8),
    ]))
    story.append(t_proto)

    story.append(Spacer(1, 10))

    # Top Endpoints Table
    story.append(Paragraph("Top Communicating Endpoints", h2_style))
    ep_data = [["IP Address", "Packets", "Bytes", "Protocols"]]
    for ep in endpoints[:8]:
        ep_data.append([
            ep.ip_address,
            f"{ep.packet_count:,}",
            f"{ep.byte_count:,} B",
            ", ".join(json.loads(ep.protocols_json or "[]"))[:30]
        ])
    t_ep = Table(ep_data, colWidths=[140, 90, 110, 160])
    t_ep.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#0f172a")),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor("#f8fafc"), colors.white]),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ('FONTSIZE', (0, 0), (-1, -1), 8),
    ]))
    story.append(t_ep)

    doc.build(story, canvasmaker=NumberedCanvas)
    return buffer.getvalue()
