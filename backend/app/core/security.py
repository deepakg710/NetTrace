import re
import uuid
from pathlib import Path
from fastapi import HTTPException, status
from app.core.config import settings

PCAP_MAGIC_BYTES = [
    b"\xa1\xb2\xc3\xd4",  # Microsecond PCAP (big-endian)
    b"\xd4\xc3\xb2\xa1",  # Microsecond PCAP (little-endian)
    b"\xa1\xb2\x3c\x4d",  # Nanosecond PCAP (big-endian)
    b"\x4d\x3c\xb2\xa1",  # Nanosecond PCAP (little-endian)
]

PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"  # PCAPNG Section Header Block

ALLOWED_EXTENSIONS = {".pcap", ".pcapng"}

def sanitize_filename(filename: str) -> str:
    # Strip any directory components
    clean_name = Path(filename).name
    # Keep only alphanumeric, hyphens, underscores, dots
    clean_name = re.sub(r"[^a-zA-Z0-9_\-\.]", "_", clean_name)
    if not clean_name:
        clean_name = "capture"
    return clean_name

def validate_capture_file(filename: str, header_bytes: bytes, file_size: int) -> str:
    """
    Validates file extension, magic header bytes, and size.
    Returns detected capture format: 'pcap' or 'pcapng'.
    """
    ext = Path(filename).suffix.lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported file extension '{ext}'. Only .pcap and .pcapng files are supported."
        )

    max_bytes = settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024
    if file_size > max_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File exceeds maximum upload size of {settings.MAX_UPLOAD_SIZE_MB} MB."
        )

    if file_size < 24:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="File is empty or too small to be a valid PCAP/PCAPNG capture."
        )

    # Check magic bytes
    if header_bytes.startswith(PCAPNG_MAGIC):
        return "pcapng"
    
    for magic in PCAP_MAGIC_BYTES:
        if header_bytes.startswith(magic):
            return "pcap"

    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="Invalid file content: Missing valid PCAP or PCAPNG header magic bytes."
    )

def generate_safe_storage_name(original_filename: str) -> str:
    clean_name = sanitize_filename(original_filename)
    unique_id = uuid.uuid4().hex[:12]
    ext = Path(clean_name).suffix.lower()
    stem = Path(clean_name).stem[:32]
    return f"{stem}_{unique_id}{ext}"
