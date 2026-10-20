import os
import uuid
import json
from pathlib import Path
from typing import List
from fastapi import APIRouter, Depends, UploadFile, File, HTTPException, status
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models.models import Capture, Packet, Flow, Endpoint, DNSRecord, Finding
from app.schemas.schemas import CaptureBase, CaptureListItem, CaptureDetail, CaptureSummaryResponse
from app.core.security import validate_capture_file, generate_safe_storage_name
from app.core.config import settings
from app.services.capture_service import process_and_analyze_capture
from app.core.logging import logger

router = APIRouter(prefix="/captures", tags=["Captures"])

@router.post("", response_model=CaptureDetail, status_code=status.HTTP_201_CREATED)
async def upload_capture(file: UploadFile = File(...), db: Session = Depends(get_db)):
    """
    Uploads and validates a PCAP/PCAPNG file, then automatically begins analysis.
    """
    if not file.filename:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No filename provided.")

    # Read header bytes to validate
    header_bytes = await file.read(64)
    if len(header_bytes) < 24:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="File is empty or too small to be a valid PCAP/PCAPNG capture."
        )

    # Read remaining content in memory or chunk to disk
    # We will stream write to disk to stay bounded
    safe_storage_name = generate_safe_storage_name(file.filename)
    dest_path = settings.UPLOADS_DIR / safe_storage_name

    total_bytes = len(header_bytes)
    try:
        with open(dest_path, "wb") as f_out:
            f_out.write(header_bytes)
            while chunk := await file.read(1024 * 1024):  # 1MB chunks
                total_bytes += len(chunk)
                if total_bytes > settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024:
                    f_out.close()
                    if dest_path.exists():
                        dest_path.unlink()
                    raise HTTPException(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        detail=f"Uploaded file exceeds maximum limit of {settings.MAX_UPLOAD_SIZE_MB} MB."
                    )
                f_out.write(chunk)
    except HTTPException:
        raise
    except Exception as e:
        if dest_path.exists():
            dest_path.unlink()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to save upload: {e}")

    # Validate header and format
    try:
        fmt = validate_capture_file(file.filename, header_bytes, total_bytes)
    except HTTPException:
        if dest_path.exists():
            dest_path.unlink()
        raise

    capture_id = str(uuid.uuid4())
    capture = Capture(
        id=capture_id,
        filename=str(dest_path),
        original_filename=Path(file.filename).name,
        file_size_bytes=total_bytes,
        status="uploaded",
        format=fmt,
        metadata_json="{}"
    )
    db.add(capture)
    db.commit()
    db.refresh(capture)

    # Run core analysis
    try:
        capture = process_and_analyze_capture(capture_id, db)
    except Exception as e:
        logger.error(f"Analysis failed for {capture_id}: {e}")

    meta = json.loads(capture.metadata_json or "{}")
    return CaptureDetail(
        id=capture.id,
        filename=capture.filename,
        original_filename=capture.original_filename,
        file_size_bytes=capture.file_size_bytes,
        upload_time=capture.upload_time.isoformat() if capture.upload_time else "",
        status=capture.status,
        packet_count=capture.packet_count,
        duration_seconds=capture.duration_seconds,
        format=capture.format,
        error_message=capture.error_message,
        start_time=capture.start_time,
        end_time=capture.end_time,
        link_type=capture.link_type,
        metadata=meta
    )

@router.get("", response_model=List[CaptureListItem])
def list_captures(db: Session = Depends(get_db)):
    captures = db.query(Capture).order_by(Capture.upload_time.desc()).all()
    return [
        CaptureListItem(
            id=c.id,
            original_filename=c.original_filename,
            file_size_bytes=c.file_size_bytes,
            upload_time=c.upload_time.isoformat() if c.upload_time else "",
            status=c.status,
            packet_count=c.packet_count,
            duration_seconds=c.duration_seconds,
            format=c.format
        )
        for c in captures
    ]

@router.get("/{capture_id}", response_model=CaptureDetail)
def get_capture(capture_id: str, db: Session = Depends(get_db)):
    capture = db.query(Capture).filter(Capture.id == capture_id).first()
    if not capture:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Capture not found.")
    
    meta = json.loads(capture.metadata_json or "{}")
    return CaptureDetail(
        id=capture.id,
        filename=capture.filename,
        original_filename=capture.original_filename,
        file_size_bytes=capture.file_size_bytes,
        upload_time=capture.upload_time.isoformat() if capture.upload_time else "",
        status=capture.status,
        packet_count=capture.packet_count,
        duration_seconds=capture.duration_seconds,
        format=capture.format,
        error_message=capture.error_message,
        start_time=capture.start_time,
        end_time=capture.end_time,
        link_type=capture.link_type,
        metadata=meta
    )

@router.delete("/{capture_id}", status_code=status.HTTP_200_OK)
def delete_capture(capture_id: str, db: Session = Depends(get_db)):
    capture = db.query(Capture).filter(Capture.id == capture_id).first()
    if not capture:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Capture not found.")

    # Remove stored pcap file
    file_path = Path(capture.filename)
    if file_path.exists():
        try:
            file_path.unlink()
        except Exception as e:
            logger.warning(f"Failed to delete capture file {file_path}: {e}")

    db.delete(capture)
    db.commit()
    return {"message": f"Capture {capture_id} and all associated records deleted."}

@router.post("/{capture_id}/analyze", response_model=CaptureDetail)
def reanalyze_capture(capture_id: str, db: Session = Depends(get_db)):
    capture = db.query(Capture).filter(Capture.id == capture_id).first()
    if not capture:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Capture not found.")

    # Clear previous analyses records for this capture
    db.query(Packet).filter(Packet.capture_id == capture_id).delete()
    db.query(Flow).filter(Flow.capture_id == capture_id).delete()
    db.query(Endpoint).filter(Endpoint.capture_id == capture_id).delete()
    db.query(DNSRecord).filter(DNSRecord.capture_id == capture_id).delete()
    db.query(Finding).filter(Finding.capture_id == capture_id).delete()
    db.commit()

    capture = process_and_analyze_capture(capture_id, db)
    meta = json.loads(capture.metadata_json or "{}")
    return CaptureDetail(
        id=capture.id,
        filename=capture.filename,
        original_filename=capture.original_filename,
        file_size_bytes=capture.file_size_bytes,
        upload_time=capture.upload_time.isoformat() if capture.upload_time else "",
        status=capture.status,
        packet_count=capture.packet_count,
        duration_seconds=capture.duration_seconds,
        format=capture.format,
        error_message=capture.error_message,
        start_time=capture.start_time,
        end_time=capture.end_time,
        link_type=capture.link_type,
        metadata=meta
    )

@router.get("/{capture_id}/summary", response_model=CaptureSummaryResponse)
def get_capture_summary(capture_id: str, db: Session = Depends(get_db)):
    capture = db.query(Capture).filter(Capture.id == capture_id).first()
    if not capture:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Capture not found.")

    meta = json.loads(capture.metadata_json or "{}")
    return CaptureSummaryResponse(
        capture_id=capture.id,
        original_filename=capture.original_filename,
        file_size_bytes=capture.file_size_bytes,
        status=capture.status,
        packet_count=capture.packet_count,
        total_bytes=meta.get("total_bytes", 0),
        start_time=capture.start_time,
        end_time=capture.end_time,
        duration_seconds=capture.duration_seconds,
        link_type=capture.link_type,
        protocol_distribution=meta.get("protocol_counts", {}),
        protocol_bytes=meta.get("protocol_bytes", {}),
        traffic_over_time=meta.get("traffic_over_time", []),
        tcp_stats=meta.get("tcp_stats", {}),
        dns_stats=meta.get("dns_stats", {}),
        findings_by_severity=meta.get("findings_by_severity", {}),
        findings_by_category=meta.get("findings_by_category", {}),
        top_endpoints=meta.get("top_endpoints", []),
        top_flows=meta.get("top_flows", []),
        recent_findings=meta.get("recent_findings", []),
        parser_warnings=meta.get("warnings", [])
    )
