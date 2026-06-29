"""
SuRaksha DocShield — FastAPI Backend
All processing is offline. No external API calls.
"""
from __future__ import annotations
import io
import base64
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import numpy as np
from PIL import Image
import cv2

# Internal layers
from database import init_db, compute_sha256, register_hash, log_audit
from utils.preprocessor import load_document, enhance_for_ocr, resize_for_analysis
from layers.visual_forensics import analyse_visual
from layers.semantic_nlp import verify_semantic
from layers.crypto_hash import verify_hash
from layers.scoring_engine import compute_score
from layers.doc_validator import validate_document

init_db()

app = FastAPI(
    title="SuRaksha DocShield API",
    description="Offline AI-powered document forensics for banking",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


def _image_to_b64(arr: np.ndarray) -> str:
    """Convert numpy array to base64 PNG string for JSON transport."""
    success, buf = cv2.imencode(".png", arr)
    if not success:
        return ""
    return base64.b64encode(buf.tobytes()).decode("utf-8")


def _draw_annotations(image: Image.Image, regions: list[dict]) -> str:
    """Draw bounding boxes on image and return as base64."""
    img_arr = cv2.cvtColor(np.array(image), cv2.COLOR_RGB2BGR)
    colours = {
        "ela_anomaly":  (0, 0, 255),    # red
        "copy_move":    (0, 165, 255),  # orange
    }
    for reg in regions:
        colour = colours.get(reg["type"], (255, 0, 0))
        x, y, w, h = reg["x"], reg["y"], reg["w"], reg["h"]
        cv2.rectangle(img_arr, (x, y), (x + w, y + h), colour, 2)
        label = f"{reg['type']} ({reg['confidence']:.0f}%)"
        cv2.putText(img_arr, label, (x, max(y - 6, 12)),
                    cv2.FONT_HERSHEY_SIMPLEX, 0.45, colour, 1)
    return _image_to_b64(img_arr)


@app.post("/analyse")
async def analyse_document(file: UploadFile = File(...)):
    raw_bytes = await file.read()
    filename  = file.filename or "document"

    if len(raw_bytes) > 20 * 1024 * 1024:   # 20 MB guard
        raise HTTPException(status_code=413, detail="File too large (max 20 MB)")

    try:
        # ── Preprocessing ─────────────────────────────────────────────────
        pages = load_document(raw_bytes, filename)
        # Analyse first page only (representative for hackathon)
        page   = pages[0]
        page   = resize_for_analysis(page, max_dim=1800)
        page_ocr = enhance_for_ocr(page)

        # ── Three layers (parallel in production; sequential here) ─────────
        visual_result   = analyse_visual(page, raw_bytes, filename)
        semantic_result = verify_semantic(page_ocr)
        hash_result     = verify_hash(raw_bytes, filename)
        doc_validation  = validate_document(semantic_result.ocr_result.text if semantic_result.ocr_result else "", page)

        report = compute_score(visual_result, semantic_result, hash_result, doc_validation)

        # ── Register in DB ─────────────────────────────────────────────────
        register_hash(
            sha256   = report.sha256,
            filename = filename,
            status   = "FLAGGED" if report.verdict == "FRAUD" else "GENUINE",
            score    = report.final_score,
            metadata = {"verdict": report.verdict, "risk": report.risk_level}
        )
        log_audit(report.sha256, "ANALYSE", f"verdict={report.verdict} score={report.final_score:.1f}")

        # ── Build visual artefacts ─────────────────────────────────────────
        annotated_b64 = _draw_annotations(page, report.suspicious_regions)
        ela_b64 = ""
        if visual_result.ela_image is not None:
            ela_coloured = cv2.applyColorMap(
                cv2.cvtColor(visual_result.ela_image, cv2.COLOR_RGB2GRAY),
                cv2.COLORMAP_JET
            )
            ela_b64 = _image_to_b64(ela_coloured)

        # ── Response ───────────────────────────────────────────────────────
        return JSONResponse({
            "filename": filename,
            "page_count": len(pages),

            # Final verdict
            "final_score":   round(report.final_score, 2),
            "verdict":       report.verdict,
            "risk_level":    report.risk_level,
            "recommendation": report.recommendation,

            # Sub-scores
            "scores": {
                "visual":   round(report.visual_score, 2),
                "semantic": round(report.semantic_score, 2),
                "hash":     round(report.hash_score, 2),
            },

            # XAI
            "explanation":    report.explanation,
            "flags":          report.all_flags,
            "suspicious_regions": report.suspicious_regions,

            # Extracted data
            "entities":   report.entities,
            "ocr_preview": report.ocr_text[:500] if report.ocr_text else "",
            "ocr_engine":  report.ocr_engine,

            # Hash / blockchain
            "sha256":             report.sha256,
            "is_duplicate":       report.is_duplicate,
            "previous_record":    report.previous_record,
            "blockchain_block":   report.blockchain_block,

            # Visuals (base64 PNGs)
            "annotated_image_b64": annotated_b64,
            "ela_image_b64":       ela_b64,
        })

    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis error: {e}")


@app.get("/health")
def health():
    return {"status": "ok", "service": "SuRaksha DocShield", "mode": "offline"}


@app.get("/history")
def get_history(limit: int = 20):
    from database import DB_PATH
    import sqlite3
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        SELECT sha256, filename, status, score, created_at
        FROM document_hashes
        ORDER BY id DESC LIMIT ?
    """, (limit,))
    rows = c.fetchall()
    conn.close()
    return [
        {"sha256": r[0][:16]+"...", "filename": r[1],
         "status": r[2], "score": r[3], "created_at": r[4]}
        for r in rows
    ]