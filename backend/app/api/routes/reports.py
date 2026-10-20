from fastapi import APIRouter, Depends, HTTPException, status, Response
from fastapi.responses import HTMLResponse, JSONResponse
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models.models import Capture
from app.services.report_service import generate_html_report, generate_pdf_report, generate_json_report

router = APIRouter(prefix="/captures/{capture_id}/reports", tags=["Reports"])

@router.get("/html", response_class=HTMLResponse)
def get_html_report(capture_id: str, db: Session = Depends(get_db)):
    capture = db.query(Capture).filter(Capture.id == capture_id).first()
    if not capture:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Capture not found.")
    
    html_content = generate_html_report(capture, db)
    return HTMLResponse(
        content=html_content,
        headers={"Content-Disposition": f'inline; filename="nettrace_report_{capture_id[:8]}.html"'}
    )

@router.get("/pdf")
def get_pdf_report(capture_id: str, db: Session = Depends(get_db)):
    capture = db.query(Capture).filter(Capture.id == capture_id).first()
    if not capture:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Capture not found.")
    
    pdf_bytes = generate_pdf_report(capture, db)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="nettrace_report_{capture_id[:8]}.pdf"'}
    )

@router.get("/json", response_class=JSONResponse)
def get_json_report_export(capture_id: str, db: Session = Depends(get_db)):
    capture = db.query(Capture).filter(Capture.id == capture_id).first()
    if not capture:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Capture not found.")
    
    data = generate_json_report(capture, db)
    return JSONResponse(
        content=data,
        headers={"Content-Disposition": f'attachment; filename="nettrace_export_{capture_id[:8]}.json"'}
    )
