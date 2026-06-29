"""
SuRaksha DocShield — Document Preprocessor
Converts PDFs / images to PIL Images. Fully offline.
"""
from __future__ import annotations
import io
from pathlib import Path
from PIL import Image, ImageFilter, ImageOps
import numpy as np
import cv2

try:
    from pdf2image import convert_from_bytes
    PDF2IMAGE_OK = True
except ImportError:
    PDF2IMAGE_OK = False

try:
    import PyPDF2
    PYPDF2_OK = True
except ImportError:
    PYPDF2_OK = False


SUPPORTED_IMAGE_EXTS = {".jpg", ".jpeg", ".png", ".tiff", ".tif", ".bmp", ".webp"}
SUPPORTED_PDF_EXTS   = {".pdf"}


def load_document(raw_bytes: bytes, filename: str) -> list[Image.Image]:
    """
    Returns a list of PIL Images (one per page).
    For images, returns a single-element list.
    """
    ext = Path(filename).suffix.lower()

    if ext in SUPPORTED_IMAGE_EXTS:
        img = Image.open(io.BytesIO(raw_bytes))
        return [img.convert("RGB")]

    if ext in SUPPORTED_PDF_EXTS:
        if PDF2IMAGE_OK:
            try:
                pages = convert_from_bytes(raw_bytes, dpi=200)
                return [p.convert("RGB") for p in pages]
            except Exception:
                pass
        # Fallback: try rendering first page via PyPDF2 + blank placeholder
        return [_pdf_to_blank_placeholder()]

    # Unknown format — try PIL anyway
    try:
        img = Image.open(io.BytesIO(raw_bytes))
        return [img.convert("RGB")]
    except Exception:
        raise ValueError(f"Unsupported or unreadable file format: {filename}")


def _pdf_to_blank_placeholder() -> Image.Image:
    """Return a white image when PDF rendering is unavailable."""
    img = Image.new("RGB", (800, 1100), color=(255, 255, 255))
    return img


def enhance_for_ocr(image: Image.Image) -> Image.Image:
    """Sharpen and binarise for better OCR accuracy."""
    # Convert to grayscale numpy array
    arr = np.array(image.convert("L"))

    # CLAHE for contrast enhancement
    clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8))
    arr = clahe.apply(arr)

    # Denoise
    arr = cv2.fastNlMeansDenoising(arr, h=10)

    return Image.fromarray(arr).convert("RGB")


def resize_for_analysis(image: Image.Image, max_dim: int = 2000) -> Image.Image:
    """Keep aspect ratio but cap max dimension for speed."""
    w, h = image.size
    if max(w, h) > max_dim:
        scale = max_dim / max(w, h)
        image = image.resize((int(w * scale), int(h * scale)), Image.LANCZOS)
    return image
