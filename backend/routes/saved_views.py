from fastapi import APIRouter, HTTPException, Depends, status
from sqlalchemy import text
from sqlalchemy.orm import Session
import json, uuid
from database import get_db
from auth_utils import get_current_user
from schemas import SavedViewCreate

router = APIRouter()


@router.get("/saved-views")
def list_saved_views(db: Session = Depends(get_db)):
    try:
        rows = db.execute(text(
            "SELECT id, name, description, filters, created_at, updated_at FROM saved_views ORDER BY name"
        )).fetchall()
        return [
            {
                "id": r[0], "name": r[1], "description": r[2],
                "filters": r[3] or {},
                "created_at": r[4].isoformat() if r[4] else None,
                "updated_at": r[5].isoformat() if r[5] else None,
            }
            for r in rows
        ]
    except Exception as e:
        raise HTTPException(500, str(e))


@router.get("/saved-views/{view_id}")
def get_saved_view(view_id: int, db: Session = Depends(get_db)):
    row = db.execute(
        text("SELECT id, name, description, filters, created_at, updated_at FROM saved_views WHERE id = :id"),
        {"id": view_id}
    ).fetchone()
    if not row:
        raise HTTPException(404, "View not found")
    return {
        "id": row[0], "name": row[1], "description": row[2],
        "filters": row[3] or {},
        "created_at": row[4].isoformat() if row[4] else None,
        "updated_at": row[5].isoformat() if row[5] else None,
    }


@router.post("/saved-views", status_code=201)
def create_saved_view(body: SavedViewCreate, db: Session = Depends(get_db)):
    try:
        row = db.execute(
            text("""
                INSERT INTO saved_views (name, description, filters)
                VALUES (:name, :description, cast(:filters AS jsonb))
                RETURNING id, name, description, filters, created_at, updated_at
            """),
            {"name": body.name, "description": body.description, "filters": json.dumps(body.filters)}
        ).fetchone()
        db.commit()
        return {
            "id": row[0], "name": row[1], "description": row[2],
            "filters": row[3] or {},
            "created_at": row[4].isoformat() if row[4] else None,
            "updated_at": row[5].isoformat() if row[5] else None,
        }
    except Exception as e:
        db.rollback()
        raise HTTPException(500, str(e))


@router.put("/saved-views/{view_id}")
def update_saved_view(view_id: int, body: SavedViewCreate, db: Session = Depends(get_db)):
    try:
        row = db.execute(
            text("""
                UPDATE saved_views
                SET name = :name, description = :description,
                    filters = cast(:filters AS jsonb), updated_at = NOW()
                WHERE id = :id
                RETURNING id, name, description, filters, created_at, updated_at
            """),
            {"id": view_id, "name": body.name, "description": body.description, "filters": json.dumps(body.filters)}
        ).fetchone()
        if not row:
            raise HTTPException(404, "View not found")
        db.commit()
        return {
            "id": row[0], "name": row[1], "description": row[2],
            "filters": row[3] or {},
            "created_at": row[4].isoformat() if row[4] else None,
            "updated_at": row[5].isoformat() if row[5] else None,
        }
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(500, str(e))


@router.delete("/saved-views/{view_id}", status_code=204)
def delete_saved_view(view_id: int, db: Session = Depends(get_db)):
    db.execute(text("DELETE FROM saved_views WHERE id = :id"), {"id": view_id})
    db.commit()
