"""
SuRaksha DocShield — Layer 2: OCR + Semantic Verification
Offline-only: pytesseract OR basic OpenCV text region detection.
No LLM, no API calls.
"""
from __future__ import annotations
import re
from dataclasses import dataclass, field
from PIL import Image
import numpy as np
import cv2


# ─────────────────────────────────────────────
# Attempt to import OCR engines (graceful fallback)
# ─────────────────────────────────────────────
try:
    import pytesseract
    TESSERACT_OK = True
except ImportError:
    TESSERACT_OK = False

try:
    import easyocr
    _easyocr_reader = None   # lazy init
    EASYOCR_OK = True
except ImportError:
    EASYOCR_OK = False


def _get_easyocr():
    global _easyocr_reader
    if _easyocr_reader is None:
        _easyocr_reader = easyocr.Reader(["en"], gpu=False, verbose=False)
    return _easyocr_reader


# ─────────────────────────────────────────────
# OCR
# ─────────────────────────────────────────────
@dataclass
class OcrResult:
    text: str = ""
    word_boxes: list[dict] = field(default_factory=list)   # {text, x, y, w, h, conf}
    engine: str = "none"


def run_ocr(image: Image.Image) -> OcrResult:
    """Run best available offline OCR engine."""

    # ── Tesseract (preferred, fast) ──────────────────────────────────────
    if TESSERACT_OK:
        try:
            data = pytesseract.image_to_data(
                image, output_type=pytesseract.Output.DICT, lang="eng"
            )
            words = []
            full_words = []
            for i, word in enumerate(data["text"]):
                if word.strip():
                    conf = int(data["conf"][i])
                    words.append({
                        "text": word,
                        "x": data["left"][i], "y": data["top"][i],
                        "w": data["width"][i], "h": data["height"][i],
                        "conf": conf
                    })
                    full_words.append(word)
            return OcrResult(
                text=" ".join(full_words),
                word_boxes=words,
                engine="tesseract"
            )
        except Exception as e:
            pass   # fall through

    # ── EasyOCR fallback ─────────────────────────────────────────────────
    if EASYOCR_OK:
        try:
            reader = _get_easyocr()
            results = reader.readtext(np.array(image))
            words = []
            full_words = []
            for (bbox, text, conf) in results:
                xs = [p[0] for p in bbox]
                ys = [p[1] for p in bbox]
                words.append({
                    "text": text,
                    "x": int(min(xs)), "y": int(min(ys)),
                    "w": int(max(xs) - min(xs)), "h": int(max(ys) - min(ys)),
                    "conf": int(conf * 100)
                })
                full_words.append(text)
            return OcrResult(text=" ".join(full_words), word_boxes=words, engine="easyocr")
        except Exception:
            pass

    # ── Minimal OpenCV fallback (no OCR, just text regions) ──────────────
    gray = cv2.cvtColor(np.array(image.convert("RGB")), cv2.COLOR_RGB2GRAY)
    _, thresh = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY_INV + cv2.THRESH_OTSU)
    kernel = cv2.getStructuringElement(cv2.MORPH_RECT, (30, 5))
    dilated = cv2.dilate(thresh, kernel, iterations=1)
    contours, _ = cv2.findContours(dilated, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
    boxes = []
    for cnt in contours:
        x, y, w, h = cv2.boundingRect(cnt)
        if w > 50 and h > 8:
            boxes.append({"text": "[text region]", "x": x, "y": y, "w": w, "h": h, "conf": 0})
    return OcrResult(text="[OCR not available – install pytesseract]", word_boxes=boxes, engine="cv2_fallback")


# ─────────────────────────────────────────────
# Named Entity Extraction (regex-based, offline)
# ─────────────────────────────────────────────
PATTERNS = {
    "pan":          r"\b[A-Z]{5}[0-9]{4}[A-Z]\b",
    "aadhaar":      r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}\b",
    "date":         r"\b(?:\d{1,2}[\/\-\.]\d{1,2}[\/\-\.]\d{2,4}|\d{4}[\/\-\.]\d{1,2}[\/\-\.]\d{1,2})\b",
    "amount_inr":   r"(?:Rs\.?|INR|₹)\s?[\d,]+(?:\.\d{2})?",
    "email":        r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z]{2,}",
    "phone":        r"\b(?:\+91[\-\s]?)?[6-9]\d{9}\b",
    "pincode":      r"\b[1-9]\d{5}\b",
    "gst":          r"\b\d{2}[A-Z]{5}\d{4}[A-Z][1-9A-Z]Z[0-9A-Z]\b",
    "loan_ac":      r"\b(?:Loan|Account|A\/C)\s*(?:No\.?|Number|#)?\s*[A-Z0-9]{6,20}\b",
}


def extract_entities(text: str) -> dict[str, list[str]]:
    entities: dict[str, list[str]] = {}
    for label, pattern in PATTERNS.items():
        matches = re.findall(pattern, text, re.IGNORECASE)
        if matches:
            entities[label] = list(set(matches))
    return entities


# ─────────────────────────────────────────────
# Rule-based semantic checks
# ─────────────────────────────────────────────
@dataclass
class SemanticResult:
    semantic_score: float = 100.0   # 0-100, 100 = clean
    entities: dict = field(default_factory=dict)
    inconsistencies: list[str] = field(default_factory=list)
    ocr_result: OcrResult | None = None


def _check_name_consistency(text: str) -> list[str]:
    """Detect if the same person's name is spelled differently across the doc."""
    issues = []
    # Simple heuristic: find capitalised sequences and group similar ones
    words = re.findall(r"\b[A-Z][a-z]+\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?\b", text)
    # Build a frequency map
    freq: dict[str, int] = {}
    for w in words:
        freq[w] = freq.get(w, 0) + 1
    # Look for pairs that differ only by 1-2 characters (possible typos in forgeries)
    names = list(freq.keys())
    for i in range(len(names)):
        for j in range(i + 1, len(names)):
            a, b = names[i], names[j]
            # Rough edit-distance check using length difference
            if abs(len(a) - len(b)) <= 3 and a[:4].lower() == b[:4].lower() and a != b:
                issues.append(f"Possible name inconsistency: '{a}' vs '{b}'")
    return issues


def _check_date_consistency(dates: list[str]) -> list[str]:
    """Flags if multiple dates exist that might be logically inconsistent."""
    issues = []
    if len(dates) > 1:
        # Just report all dates for human review; advanced parsing would need dateutil
        issues.append(f"Multiple dates detected — verify logical order: {', '.join(dates[:5])}")
    return issues


def _check_amount_plausibility(amounts: list[str]) -> list[str]:
    issues = []
    for amt in amounts:
        num_str = re.sub(r"[^\d]", "", amt)
        if num_str and int(num_str) == 0:
            issues.append(f"Zero amount detected: {amt}")
    return issues


def verify_semantic(image: Image.Image) -> SemanticResult:
    result = SemanticResult()

    # 1. OCR
    ocr = run_ocr(image)
    result.ocr_result = ocr
    text = ocr.text

    # 2. Entity extraction
    entities = extract_entities(text)
    result.entities = entities

    penalty = 0.0

    # 3. Rule checks
    name_issues = _check_name_consistency(text)
    result.inconsistencies.extend(name_issues)
    penalty += len(name_issues) * 15

    date_issues = _check_date_consistency(entities.get("date", []))
    result.inconsistencies.extend(date_issues)
    penalty += len(date_issues) * 5

    amount_issues = _check_amount_plausibility(entities.get("amount_inr", []))
    result.inconsistencies.extend(amount_issues)
    penalty += len(amount_issues) * 10

    # 4. Font consistency heuristic via word box height variance
    if ocr.word_boxes:
        heights = [b["h"] for b in ocr.word_boxes if b["h"] > 5]
        if heights:
            variance = float(np.std(heights))
            # High variance → mixed fonts → suspicious
            if variance > 8:
                result.inconsistencies.append(
                    f"High font size variance detected ({variance:.1f}px std) — possible text insertion"
                )
                penalty += min(variance * 2, 25)

    # 5. Low OCR confidence
    if ocr.word_boxes:
        confidences = [b["conf"] for b in ocr.word_boxes if b["conf"] >= 0]
        if confidences:
            avg_conf = float(np.mean(confidences))
            if avg_conf < 50:
                result.inconsistencies.append(
                    f"Low OCR confidence ({avg_conf:.0f}%) — possible image overlay or degraded scan"
                )
                penalty += 15

    result.semantic_score = max(0.0, 100.0 - penalty)
    return result
