"""
SuRaksha DocShield — Layer 1: Visual Forensics
Techniques: ELA, Copy-Move Detection, EXIF Metadata, Font Variance
All offline — no network calls.
"""
from __future__ import annotations
import io
import math
import tempfile
from pathlib import Path
from dataclasses import dataclass, field

import cv2
import numpy as np
from PIL import Image, ImageChops, ImageEnhance
import PyPDF2

try:
    import exifread
    EXIFREAD_OK = True
except ImportError:
    EXIFREAD_OK = False


# ─────────────────────────────────────────────
# Result container
# ─────────────────────────────────────────────
@dataclass
class VisualResult:
    tamper_score: float = 0.0          # 0–100, higher = more suspicious
    ela_score: float = 0.0
    copy_move_score: float = 0.0
    metadata_score: float = 0.0
    suspicious_regions: list[dict] = field(default_factory=list)
    flags: list[str] = field(default_factory=list)
    ela_image: np.ndarray | None = None   # visualisation


# ─────────────────────────────────────────────
# Error Level Analysis
# ─────────────────────────────────────────────
def _ela(image: Image.Image, quality: int = 90, amplify: int = 15) -> tuple[float, np.ndarray, list[dict]]:
    """
    Re-save at reduced quality and compute pixel-level error.
    Returns (score 0-100, ela_array, suspicious_boxes).
    """
    buf = io.BytesIO()
    image.convert("RGB").save(buf, format="JPEG", quality=quality)
    buf.seek(0)
    recompressed = Image.open(buf)

    diff = ImageChops.difference(image.convert("RGB"), recompressed)
    ela_arr = np.array(diff) * amplify
    ela_arr = np.clip(ela_arr, 0, 255).astype(np.uint8)

    # Score = mean brightness of diff (normalised 0-100)
    score = float(np.mean(ela_arr)) / 255 * 100

    # Find suspicious high-error regions
    gray_ela = cv2.cvtColor(ela_arr, cv2.COLOR_RGB2GRAY)
    _, thresh = cv2.threshold(gray_ela, 50, 255, cv2.THRESH_BINARY)
    contours, _ = cv2.findContours(thresh, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)

    boxes = []
    h, w = ela_arr.shape[:2]
    for cnt in contours:
        area = cv2.contourArea(cnt)
        if area > (h * w * 0.002):   # only regions > 0.2% of image
            x, y, bw, bh = cv2.boundingRect(cnt)
            boxes.append({
                "type": "ela_anomaly",
                "x": int(x), "y": int(y),
                "w": int(bw), "h": int(bh),
                "confidence": min(100, float(area / (h * w) * 500))
            })

    return min(score * 2, 100), ela_arr, boxes[:10]   # cap at 100


# ─────────────────────────────────────────────
# Copy-Move Detection (ORB keypoint matching)
# ─────────────────────────────────────────────
def _copy_move(image: Image.Image) -> tuple[float, list[dict]]:
    """
    Detect duplicated regions using ORB feature matching.
    Returns (score 0-100, suspicious_boxes).
    """
    gray = cv2.cvtColor(np.array(image.convert("RGB")), cv2.COLOR_RGB2GRAY)
    orb = cv2.ORB_create(nfeatures=500)
    kp, des = orb.detectAndCompute(gray, None)

    if des is None or len(kp) < 10:
        return 0.0, []

    bf = cv2.BFMatcher(cv2.NORM_HAMMING, crossCheck=True)
    matches = bf.match(des, des)

    # Self-matches at distance > 0 indicate duplicated regions
    suspicious_matches = [
        m for m in matches
        if 0 < m.distance < 30 and m.queryIdx != m.trainIdx
    ]

    score = min(len(suspicious_matches) / max(len(matches), 1) * 300, 100)

    boxes = []
    for m in suspicious_matches[:5]:
        pt = kp[m.queryIdx].pt
        boxes.append({
            "type": "copy_move",
            "x": int(pt[0] - 20), "y": int(pt[1] - 20),
            "w": 40, "h": 40,
            "confidence": float(score)
        })

    return score, boxes


# ─────────────────────────────────────────────
# EXIF / PDF Metadata Analysis
# ─────────────────────────────────────────────
SUSPICIOUS_SOFTWARE = {
    "photoshop", "gimp", "paint", "inkscape",
    "canva", "midjourney", "dall-e", "stable diffusion",
    "firefly", "snapseed", "pixlr"
}

def _metadata_analysis(raw_bytes: bytes, filename: str) -> tuple[float, list[str]]:
    flags = []
    score = 0.0

    ext = Path(filename).suffix.lower()

    # PDF metadata
    if ext == ".pdf":
        try:
            reader = PyPDF2.PdfReader(io.BytesIO(raw_bytes))
            info = reader.metadata or {}
            producer = str(info.get("/Producer", "")).lower()
            creator = str(info.get("/Creator", "")).lower()
            for field_val in [producer, creator]:
                for sw in SUSPICIOUS_SOFTWARE:
                    if sw in field_val:
                        flags.append(f"PDF produced by suspicious software: {field_val}")
                        score += 40
            # Page count sanity
            if reader.pages and len(reader.pages) == 0:
                flags.append("PDF has zero pages")
                score += 30
        except Exception as e:
            flags.append(f"PDF parse error: {e}")
            score += 10

    # Image EXIF
    if ext in {".jpg", ".jpeg", ".png", ".tiff"} and EXIFREAD_OK:
        try:
            tags = exifread.process_file(io.BytesIO(raw_bytes), details=False)
            software = str(tags.get("Image Software", "")).lower()
            for sw in SUSPICIOUS_SOFTWARE:
                if sw in software:
                    flags.append(f"Image edited with: {software}")
                    score += 40
            mod_time = tags.get("Image DateTime")
            doc_date = tags.get("EXIF DateTimeOriginal")
            if mod_time and doc_date and str(mod_time) != str(doc_date):
                flags.append("Modification timestamp differs from original capture time")
                score += 20
        except Exception:
            pass

    return min(score, 100), flags


# ─────────────────────────────────────────────
# Main entry point
# ─────────────────────────────────────────────
def analyse_visual(image: Image.Image, raw_bytes: bytes, filename: str) -> VisualResult:
    result = VisualResult()

    # 1. ELA
    ela_score, ela_arr, ela_boxes = _ela(image)
    result.ela_score = ela_score
    result.ela_image = ela_arr
    result.suspicious_regions.extend(ela_boxes)
    if ela_score > 40:
        result.flags.append(f"ELA detected high compression anomalies (score {ela_score:.1f})")

    # 2. Copy-move
    cm_score, cm_boxes = _copy_move(image)
    result.copy_move_score = cm_score
    result.suspicious_regions.extend(cm_boxes)
    if cm_score > 30:
        result.flags.append(f"Possible duplicated regions detected (copy-move score {cm_score:.1f})")

    # 3. Metadata
    meta_score, meta_flags = _metadata_analysis(raw_bytes, filename)
    result.metadata_score = meta_score
    result.flags.extend(meta_flags)

    # Composite score (weighted)
    result.tamper_score = (
        0.50 * ela_score +
        0.25 * cm_score +
        0.25 * meta_score
    )

    return result
