"""
SuRaksha DocShield
Layer : Template Validation Engine

Purpose
-------
Detect fabricated documents by comparing the uploaded document against
official layout templates.

Unlike ELA, this detects documents created from scratch using
Photoshop / Canva / Gemini / ChatGPT / Stable Diffusion.

Supported documents

- PAN
- Aadhaar
- Passport
- Driving Licence
- Voter ID
- Bank Statement
- Salary Slip
- Property Documents

Everything works completely offline.
"""

from __future__ import annotations

import json
import math
from pathlib import Path
from dataclasses import dataclass, field

import cv2
import numpy as np
from PIL import Image

# ----------------------------------------------------
# Result
# ----------------------------------------------------

@dataclass
class TemplateResult:

    score: float = 100.0

    issues: list[str] = field(default_factory=list)

    detected_boxes: dict = field(default_factory=dict)

    expected_boxes: dict = field(default_factory=dict)

    matched: bool = False

    fabrication_probability: float = 0.0


# ----------------------------------------------------
# Paths
# ----------------------------------------------------

BASE = Path(__file__).resolve().parent

TEMPLATE_FOLDER = BASE / "templates"

SUPPORTED = {

    "PAN":"pan.json",

    "AADHAAR":"aadhaar.json",

    "PASSPORT":"passport.json",

    "DRIVING_LICENCE":"dl.json",

    "VOTER_ID":"voter.json",

    "BANK_STATEMENT":"bank.json",

    "SALARY_SLIP":"salary.json",

    "PROPERTY_DOC":"property.json"

}


# ----------------------------------------------------
# Utilities
# ----------------------------------------------------

def load_template(doc_type:str):

    file=TEMPLATE_FOLDER/SUPPORTED.get(doc_type,"")

    if not file.exists():

        return None

    with open(file,"r") as f:

        return json.load(f)


# ----------------------------------------------------
# Resize
# ----------------------------------------------------

def normalize(image:Image.Image):

    img=np.array(image.convert("RGB"))

    img=cv2.resize(img,(1000,700))

    return img


# ----------------------------------------------------
# Perspective Correction
# ----------------------------------------------------

def correct_perspective(img):

    gray=cv2.cvtColor(img,cv2.COLOR_RGB2GRAY)

    blur=cv2.GaussianBlur(gray,(5,5),0)

    edges=cv2.Canny(blur,60,180)

    contours,_=cv2.findContours(
        edges,
        cv2.RETR_EXTERNAL,
        cv2.CHAIN_APPROX_SIMPLE
    )

    if not contours:

        return img

    cnt=max(contours,key=cv2.contourArea)

    peri=cv2.arcLength(cnt,True)

    approx=cv2.approxPolyDP(cnt,0.02*peri,True)

    if len(approx)!=4:

        return img

    pts=approx.reshape(4,2).astype("float32")

    s=pts.sum(axis=1)

    diff=np.diff(pts,axis=1)

    rect=np.zeros((4,2),dtype="float32")

    rect[0]=pts[np.argmin(s)]

    rect[2]=pts[np.argmax(s)]

    rect[1]=pts[np.argmin(diff)]

    rect[3]=pts[np.argmax(diff)]

    dst=np.array([

        [0,0],

        [999,0],

        [999,699],

        [0,699]

    ],dtype="float32")

    M=cv2.getPerspectiveTransform(rect,dst)

    warped=cv2.warpPerspective(img,M,(1000,700))

    return warped


# ----------------------------------------------------
# Bounding Box Finder
# ----------------------------------------------------

def find_large_rectangles(img):

    gray=cv2.cvtColor(img,cv2.COLOR_RGB2GRAY)

    thr=cv2.adaptiveThreshold(

        gray,

        255,

        cv2.ADAPTIVE_THRESH_GAUSSIAN_C,

        cv2.THRESH_BINARY_INV,

        31,

        12

    )

    cnts,_=cv2.findContours(

        thr,

        cv2.RETR_EXTERNAL,

        cv2.CHAIN_APPROX_SIMPLE

    )

    rects=[]

    H,W=gray.shape

    for c in cnts:

        area=cv2.contourArea(c)

        if area<1000:

            continue

        x,y,w,h=cv2.boundingRect(c)

        rects.append({

            "x":x,

            "y":y,

            "w":w,

            "h":h,

            "area":area

        })

    return rects

# ----------------------------------------------------
# Logo Detector
# ----------------------------------------------------

def detect_logo(img):

    """
    Detect probable government logo region.

    PAN:
        top-left

    Aadhaar:
        top-left

    Passport:
        top-center

    Returns:
        dict | None
    """

    H,W=img.shape[:2]

    roi=img[0:int(H*0.25),0:int(W*0.40)]

    gray=cv2.cvtColor(roi,cv2.COLOR_RGB2GRAY)

    edges=cv2.Canny(gray,70,170)

    cnts,_=cv2.findContours(
        edges,
        cv2.RETR_EXTERNAL,
        cv2.CHAIN_APPROX_SIMPLE
    )

    best=None
    best_area=0

    for c in cnts:

        x,y,w,h=cv2.boundingRect(c)

        area=w*h

        if area<200:
            continue

        ratio=w/float(h)

        if ratio<0.5 or ratio>2.5:
            continue

        if area>best_area:

            best_area=area

            best={
                "x":x,
                "y":y,
                "w":w,
                "h":h
            }

    return best


# ----------------------------------------------------
# Photo Detector
# ----------------------------------------------------

def detect_photo(img):

    """
    Detect passport/id photo.

    Uses colour variance + face-like rectangle.
    """

    H,W=img.shape[:2]

    roi=img[
        int(H*0.10):int(H*0.85),
        0:int(W*0.45)
    ]

    gray=cv2.cvtColor(roi,cv2.COLOR_RGB2GRAY)

    classifier=cv2.CascadeClassifier(
        cv2.data.haarcascades+
        "haarcascade_frontalface_default.xml"
    )

    faces=classifier.detectMultiScale(
        gray,
        scaleFactor=1.1,
        minNeighbors=5
    )

    if len(faces):

        x,y,w,h=max(
            faces,
            key=lambda f:f[2]*f[3]
        )

        return {

            "x":int(x),

            "y":int(y),

            "w":int(w),

            "h":int(h)
        }

    return None


# ----------------------------------------------------
# QR Detector
# ----------------------------------------------------

def detect_qr(img):

    detector=cv2.QRCodeDetector()

    _, points = detector.detect(img)

    if points is None:

        return None

    pts=points[0]

    x=int(np.min(pts[:,0]))

    y=int(np.min(pts[:,1]))

    w=int(np.max(pts[:,0])-x)

    h=int(np.max(pts[:,1])-y)

    return {

        "x":x,

        "y":y,

        "w":w,

        "h":h

    }


# ----------------------------------------------------
# Signature Detector
# ----------------------------------------------------

def detect_signature(img):

    """
    Find handwritten signature.

    Usually bottom region.
    """

    H,W=img.shape[:2]

    roi=img[int(H*0.60):H]

    gray=cv2.cvtColor(
        roi,
        cv2.COLOR_RGB2GRAY
    )

    thr=cv2.threshold(
        gray,
        0,
        255,
        cv2.THRESH_BINARY_INV+
        cv2.THRESH_OTSU
    )[1]

    cnts,_=cv2.findContours(
        thr,
        cv2.RETR_EXTERNAL,
        cv2.CHAIN_APPROX_SIMPLE
    )

    candidate=None

    best=0

    for c in cnts:

        x,y,w,h=cv2.boundingRect(c)

        area=w*h

        if area<250:

            continue

        ratio=w/max(h,1)

        if ratio<3:

            continue

        if area>best:

            best=area

            candidate={

                "x":x,

                "y":y+int(H*0.60),

                "w":w,

                "h":h

            }

    return candidate


# ----------------------------------------------------
# Text Block Detector
# ----------------------------------------------------

def detect_text_blocks(img):

    gray=cv2.cvtColor(
        img,
        cv2.COLOR_RGB2GRAY
    )

    thr=cv2.adaptiveThreshold(

        gray,

        255,

        cv2.ADAPTIVE_THRESH_GAUSSIAN_C,

        cv2.THRESH_BINARY_INV,

        31,

        15

    )

    kernel=cv2.getStructuringElement(
        cv2.MORPH_RECT,
        (25,4)
    )

    morph=cv2.morphologyEx(
        thr,
        cv2.MORPH_CLOSE,
        kernel
    )

    cnts,_=cv2.findContours(
        morph,
        cv2.RETR_EXTERNAL,
        cv2.CHAIN_APPROX_SIMPLE
    )

    blocks=[]

    for c in cnts:

        x,y,w,h=cv2.boundingRect(c)

        if w<80:

            continue

        if h<8:

            continue

        blocks.append({

            "x":x,

            "y":y,

            "w":w,

            "h":h

        })

    return blocks


# ----------------------------------------------------
# Margin Analysis
# ----------------------------------------------------

def analyse_margins(img):

    gray=cv2.cvtColor(img,cv2.COLOR_RGB2GRAY)

    thr=cv2.threshold(

        gray,

        240,

        255,

        cv2.THRESH_BINARY_INV

    )[1]

    ys,xs=np.where(thr>0)

    if len(xs)==0:

        return None

    left=np.min(xs)

    right=img.shape[1]-np.max(xs)

    top=np.min(ys)

    bottom=img.shape[0]-np.max(ys)

    return {

        "left":left,

        "right":right,

        "top":top,

        "bottom":bottom

    }

# ----------------------------------------------------
# IoU
# ----------------------------------------------------

def bbox_iou(a,b):

    ax1=a["x"]
    ay1=a["y"]
    ax2=ax1+a["w"]
    ay2=ay1+a["h"]

    bx1=b["x"]
    by1=b["y"]
    bx2=bx1+b["w"]
    by2=by1+b["h"]

    interx1=max(ax1,bx1)
    intery1=max(ay1,by1)
    interx2=min(ax2,bx2)
    intery2=min(ay2,by2)

    if interx2<=interx1 or intery2<=intery1:
        return 0.0

    inter=(interx2-interx1)*(intery2-intery1)

    areaA=a["w"]*a["h"]
    areaB=b["w"]*b["h"]

    return inter/(areaA+areaB-inter+1e-6)


# ----------------------------------------------------
# Position Distance
# ----------------------------------------------------

def center_distance(a,b):

    ax=a["x"]+a["w"]/2
    ay=a["y"]+a["h"]/2

    bx=b["x"]+b["w"]/2
    by=b["y"]+b["h"]/2

    return math.sqrt((ax-bx)**2+(ay-by)**2)


# ----------------------------------------------------
# Compare Box
# ----------------------------------------------------

def compare_box(name,expected,detected,issues):

    if expected is None:
        return 100

    if detected is None:

        issues.append(f"{name} missing")

        return 0

    iou=bbox_iou(expected,detected)

    dist=center_distance(expected,detected)

    score=100

    if iou<0.20:

        score-=45

        issues.append(
            f"{name} position mismatch"
        )

    elif iou<0.50:

        score-=20

        issues.append(
            f"{name} slightly shifted"
        )

    if dist>120:

        score-=20

        issues.append(
            f"{name} centre displaced"
        )

    expected_area=expected["w"]*expected["h"]

    detected_area=detected["w"]*detected["h"]

    ratio=detected_area/max(expected_area,1)

    if ratio<0.65 or ratio>1.50:

        score-=15

        issues.append(
            f"{name} size mismatch"
        )

    return max(score,0)


# ----------------------------------------------------
# Margin Comparison
# ----------------------------------------------------

def compare_margins(expected,detected,issues):

    if expected is None:

        return 100

    if detected is None:

        issues.append("Margins not detected")

        return 50

    score=100

    for side in ["left","right","top","bottom"]:

        diff=abs(
            expected[side]-detected[side]
        )

        if diff>30:

            score-=8

            issues.append(
                f"{side} margin differs by {diff}px"
            )

    return max(score,0)


# ----------------------------------------------------
# Text Block Comparison
# ----------------------------------------------------

def compare_text(expected_blocks,
                 detected_blocks,
                 issues):

    if expected_blocks is None:

        return 100

    if detected_blocks is None:

        issues.append(
            "No text blocks detected"
        )

        return 30

    if len(detected_blocks)==0:

        issues.append(
            "Document appears text sparse"
        )

        return 20

    score=100

    diff=abs(
        len(expected_blocks)-len(detected_blocks)
    )

    if diff>5:

        score-=20

        issues.append(
            "Unexpected number of text regions"
        )

    return score


# ----------------------------------------------------
# Fabrication Probability
# ----------------------------------------------------

def fabrication_probability(scores):

    """
    Converts layout score into probability
    that the document was fabricated.

    100 layout

        ↓

    0 fabrication

    0 layout

        ↓

    100 fabrication
    """

    layout=np.mean(scores)

    probability=100-layout

    return max(
        0,
        min(
            probability,
            100
        )
    )


# ----------------------------------------------------
# Compare Template
# ----------------------------------------------------

def compare_template(img,template):

    issues=[]

    detected_logo=detect_logo(img)

    detected_photo=detect_photo(img)

    detected_qr=detect_qr(img)

    detected_sign=detect_signature(img)

    detected_blocks=detect_text_blocks(img)

    detected_margin=analyse_margins(img)

    scores=[]

    scores.append(

        compare_box(

            "Logo",

            template.get("logo"),

            detected_logo,

            issues

        )

    )

    scores.append(

        compare_box(

            "Photo",

            template.get("photo"),

            detected_photo,

            issues

        )

    )

    scores.append(

        compare_box(

            "QR",

            template.get("qr"),

            detected_qr,

            issues

        )

    )

    scores.append(

        compare_box(

            "Signature",

            template.get("signature"),

            detected_sign,

            issues

        )

    )

    scores.append(

        compare_text(

            template.get("text_blocks"),

            detected_blocks,

            issues

        )

    )

    scores.append(

        compare_margins(

            template.get("margins"),

            detected_margin,

            issues

        )

    )

    result=TemplateResult()

    result.score=np.mean(scores)

    result.fabrication_probability=\
        fabrication_probability(scores)

    result.issues=issues

    result.detected_boxes={

        "logo":detected_logo,

        "photo":detected_photo,

        "qr":detected_qr,

        "signature":detected_sign

    }

    result.expected_boxes={

        "logo":template.get("logo"),

        "photo":template.get("photo"),

        "qr":template.get("qr"),

        "signature":template.get("signature")

    }

    result.matched=result.score>80

    return result

# ----------------------------------------------------
# AI Generated / Fabricated Heuristics
# ----------------------------------------------------

def ai_document_checks(img):

    issues=[]

    score=100

    gray=cv2.cvtColor(img,cv2.COLOR_RGB2GRAY)

    # --------------------------
    # Noise Consistency
    # --------------------------

    lap=cv2.Laplacian(gray,cv2.CV_64F)

    noise=np.var(lap)

    if noise<80:

        issues.append(
            "Very low image noise (possible AI generated)"
        )

        score-=20

    # --------------------------
    # Frequency Analysis
    # --------------------------

    fft=np.fft.fft2(gray)

    fft=np.abs(np.fft.fftshift(fft))

    fft_std=np.std(fft)

    if fft_std<650:

        issues.append(
            "Synthetic frequency distribution detected"
        )

        score-=25

    # --------------------------
    # Gradient Analysis
    # --------------------------

    gx=cv2.Sobel(gray,cv2.CV_64F,1,0)

    gy=cv2.Sobel(gray,cv2.CV_64F,0,1)

    grad=np.mean(np.sqrt(gx*gx+gy*gy))

    if grad<18:

        issues.append(
            "Edges appear unnaturally smooth"
        )

        score-=20

    # --------------------------
    # Color Diversity
    # --------------------------

    colours=len(np.unique(
        img.reshape(-1,3),
        axis=0
    ))

    if colours<1200:

        issues.append(
            "Low colour diversity"
        )

        score-=10

    return max(score,0),issues


# ----------------------------------------------------
# Hard Fraud Rules
# ----------------------------------------------------

def apply_hard_rules(result):

    if result.fabrication_probability>90:

        result.score=min(result.score,20)

        result.issues.append(
            "High confidence fabricated document"
        )

    if len(result.issues)>=8:

        result.score=min(result.score,35)

    if not result.detected_boxes["photo"]:

        result.score=min(result.score,40)

    if not result.detected_boxes["logo"]:

        result.score=min(result.score,45)

    if not result.detected_boxes["signature"]:

        result.score=min(result.score,45)

    return result


# ----------------------------------------------------
# Main API
# ----------------------------------------------------

def validate(image, doc_type):

    result = TemplateResult()

    template = load_template(doc_type)

    if template is None:
        result.score = 50
        result.fabrication_probability = 50
        result.issues.append(
            "No template available for this document type"
        )
        return result

    # -------------------------
    # preprocess
    # -------------------------

    img = normalize(image)
    img = correct_perspective(img)

    # -------------------------
    # Layout comparison
    # -------------------------

    layout_result = compare_template(img, template)

    result.score = layout_result.score
    result.issues.extend(layout_result.issues)
    result.detected_boxes = layout_result.detected_boxes
    result.expected_boxes = layout_result.expected_boxes

    # -------------------------
    # Security feature detection
    # -------------------------

    security, security_flags = security_features(img, doc_type)

    result.issues.extend(security_flags)

    if not security["logo_present"]:
        result.score -= 10

    if not security["photo_present"]:
        result.score -= 15

    if not security["signature_present"]:
        result.score -= 10

    if doc_type in ["PAN", "AADHAAR"]:
        if not security["qr_present"]:
            result.score -= 15

    # -------------------------
    # AI document heuristics
    # -------------------------

    ai_score, ai_flags = ai_document_checks(img)

    result.issues.extend(ai_flags)

    result.score = (
        result.score * 0.75 +
        ai_score * 0.25
    )

    result.score = max(0, min(result.score, 100))

    result.fabrication_probability = 100 - result.score

    result = apply_hard_rules(result)

    return result

# ----------------------------------------------------
# Security Feature Detector
# ----------------------------------------------------

def security_features(img, doc_type):

    features = {}
    issues = []

    H, W = img.shape[:2]

    gray = cv2.cvtColor(img, cv2.COLOR_RGB2GRAY)

    # ---------------------------
    # QR Detection
    # ---------------------------

    qr = detect_qr(img)

    features["qr_present"] = qr is not None

    if doc_type in ["AADHAAR", "PAN"]:

        if qr is None:

            issues.append("QR Code missing")

    # ---------------------------
    # Face Detection
    # ---------------------------

    photo = detect_photo(img)

    features["photo_present"] = photo is not None

    if doc_type in [

        "PAN",

        "AADHAAR",

        "PASSPORT",

        "DRIVING_LICENCE",

        "VOTER_ID"

    ]:

        if photo is None:

            issues.append("Photo missing")

    # ---------------------------
    # Signature

    # ---------------------------

    sign = detect_signature(img)

    features["signature_present"] = sign is not None

    if doc_type in [

        "PAN",

        "PASSPORT",

        "DRIVING_LICENCE"

    ]:

        if sign is None:

            issues.append("Signature missing")

    # ---------------------------
    # Logo

    # ---------------------------

    logo = detect_logo(img)

    features["logo_present"] = logo is not None

    if logo is None:

        issues.append("Government logo not detected")

    # ---------------------------
    # Edge Quality

    # ---------------------------

    lap = cv2.Laplacian(gray, cv2.CV_64F).var()

    features["edge_quality"] = lap

    if lap < 120:

        issues.append("Document appears over-smoothed")

    return features, issues
def validate_template(image, doc_type):
    return validate(image, doc_type)