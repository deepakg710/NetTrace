import json
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models.models import DetectorSetting
from app.schemas.schemas import DetectorSettingsSchema
from app.core.config import settings

router = APIRouter(prefix="/settings", tags=["Settings"])

@router.get("", response_model=DetectorSettingsSchema)
def get_settings(db: Session = Depends(get_db)):
    current = {
        "port_scan_threshold": settings.PORT_SCAN_THRESHOLD,
        "host_scan_threshold": settings.HOST_SCAN_THRESHOLD,
        "connection_burst_threshold": settings.CONNECTION_BURST_THRESHOLD,
        "burst_window_seconds": settings.BURST_WINDOW_SECONDS,
        "repeated_dns_query_threshold": settings.REPEATED_DNS_QUERY_THRESHOLD,
        "periodic_connection_min_count": settings.PERIODIC_CONNECTION_MIN_COUNT,
        "periodic_cv_threshold": settings.PERIODIC_CV_THRESHOLD,
        "traffic_rate_spike_pps": settings.TRAFFIC_RATE_SPIKE_PPS,
    }

    records = db.query(DetectorSetting).all()
    for r in records:
        try:
            if r.key in current:
                current[r.key] = json.loads(r.value_json)
        except Exception:
            pass

    return DetectorSettingsSchema(**current)

@router.post("", response_model=DetectorSettingsSchema)
def update_settings(payload: DetectorSettingsSchema, db: Session = Depends(get_db)):
    data = payload.model_dump()
    for k, v in data.items():
        rec = db.query(DetectorSetting).filter(DetectorSetting.key == k).first()
        if not rec:
            rec = DetectorSetting(key=k, value_json=json.dumps(v))
            db.add(rec)
        else:
            rec.value_json = json.dumps(v)
    db.commit()
    return payload
