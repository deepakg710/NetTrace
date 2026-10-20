import json
from typing import Optional, List
from fastapi import APIRouter, Depends, Query, HTTPException, status
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models.models import Finding
from app.schemas.schemas import FindingSchema

router = APIRouter(prefix="/captures/{capture_id}/findings", tags=["Findings"])

@router.get("", response_model=List[FindingSchema])
def get_findings(
    capture_id: str,
    category: Optional[str] = None,
    severity: Optional[str] = None,
    db: Session = Depends(get_db)
):
    query = db.query(Finding).filter(Finding.capture_id == capture_id)

    if category:
        query = query.filter(Finding.category == category)
    if severity:
        query = query.filter(Finding.severity == severity)

    findings = query.all()

    # Sort by severity weight
    sev_weights = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Informational": 1}
    sorted_findings = sorted(findings, key=lambda f: sev_weights.get(f.severity, 0), reverse=True)

    return [
        FindingSchema(
            id=f.id,
            capture_id=f.capture_id,
            category=f.category,
            severity=f.severity,
            confidence=f.confidence,
            title=f.title,
            observed_facts=f.observed_facts,
            supporting_packet_numbers=json.loads(f.supporting_packet_numbers_json or "[]"),
            timestamps=json.loads(f.timestamps_json or "[]"),
            endpoints=json.loads(f.endpoints_json or "[]"),
            ports=json.loads(f.ports_json or "[]"),
            rule_name=f.rule_name,
            threshold_val=f.threshold_val,
            explanations=f.explanations,
            recommendations=f.recommendations,
            limitations=f.limitations
        )
        for f in sorted_findings
    ]

@router.get("/{finding_id}", response_model=FindingSchema)
def get_finding_by_id(capture_id: str, finding_id: str, db: Session = Depends(get_db)):
    f = db.query(Finding).filter(Finding.capture_id == capture_id, Finding.id == finding_id).first()
    if not f:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Finding {finding_id} not found.")

    return FindingSchema(
        id=f.id,
        capture_id=f.capture_id,
        category=f.category,
        severity=f.severity,
        confidence=f.confidence,
        title=f.title,
        observed_facts=f.observed_facts,
        supporting_packet_numbers=json.loads(f.supporting_packet_numbers_json or "[]"),
        timestamps=json.loads(f.timestamps_json or "[]"),
        endpoints=json.loads(f.endpoints_json or "[]"),
        ports=json.loads(f.ports_json or "[]"),
        rule_name=f.rule_name,
        threshold_val=f.threshold_val,
        explanations=f.explanations,
        recommendations=f.recommendations,
        limitations=f.limitations
    )
