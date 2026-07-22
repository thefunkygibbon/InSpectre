from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy import text
from sqlalchemy.orm import Session
from database import get_db
from auth_utils import get_current_user
from models import FingerprintEntry

router = APIRouter()


@router.get("/fingerprints")
def get_fingerprints(db: Session = Depends(get_db)):
    fps = db.query(FingerprintEntry).order_by(FingerprintEntry.updated_at.desc()).all()
    return [
        {"id": fp.id, "oui_prefix": fp.oui_prefix, "hostname_pattern": fp.hostname_pattern,
         "open_ports": fp.open_ports, "device_type": fp.device_type, "vendor_name": fp.vendor_name,
         "confidence_score": fp.confidence_score, "hit_count": fp.hit_count, "source": fp.source,
         "created_at": fp.created_at.isoformat() if fp.created_at else None,
         "updated_at": fp.updated_at.isoformat() if fp.updated_at else None}
        for fp in fps
    ]


@router.get("/fingerprints/stats")
def fingerprint_stats(db: Session = Depends(get_db)):
    total     = db.query(FingerprintEntry).count()
    manual    = db.query(FingerprintEntry).filter(FingerprintEntry.source == 'manual').count()
    community = db.query(FingerprintEntry).filter(FingerprintEntry.source == 'community').count()
    auto      = db.query(FingerprintEntry).filter(FingerprintEntry.source == 'auto').count()
    return {"total": total, "manual": manual, "community": community, "auto": auto}


@router.delete("/fingerprints/{fid}")
def delete_fingerprint(fid: int, db: Session = Depends(get_db)):
    fp = db.get(FingerprintEntry, fid)
    if not fp:
        raise HTTPException(404, "Fingerprint not found")
    db.delete(fp); db.commit()
    return {"deleted": fid}
