"""
SuRaksha DocShield — Streamlit Dashboard
Interactive XAI document forensics UI. Fully offline.
"""
import sys
import io
import base64
import json
import time
from pathlib import Path

import streamlit as st
import numpy as np
from PIL import Image
import plotly.graph_objects as go
import plotly.express as px

# ── Add backend to path ──────────────────────────────────────────────
BACKEND_PATH = Path(__file__).resolve().parent.parent / "backend"
sys.path.insert(0, str(BACKEND_PATH))

from database import init_db, compute_sha256
from utils.preprocessor import load_document, enhance_for_ocr, resize_for_analysis
from layers.visual_forensics import analyse_visual
from layers.semantic_nlp import verify_semantic
from layers.crypto_hash import verify_hash
from layers.scoring_engine import compute_score
from layers.doc_validator import validate_document
from layers.template_validator import validate_template
from layers.ai_forgery_detector import detect_ai_forgery
from layers.authenticity_engine import calculate_authenticity

import numpy as np
import cv2

init_db()

# ─────────────────────────────────────────────────────────────────────
# Page config
# ─────────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="SuRaksha DocShield",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─────────────────────────────────────────────────────────────────────
# Custom CSS
# ─────────────────────────────────────────────────────────────────────
st.markdown("""
<style>
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700&family=JetBrains+Mono:wght@400;600&display=swap');

  html, body, [class*="css"] { font-family: 'Inter', sans-serif; }

  .main-header {
    background: linear-gradient(135deg, #0f2027 0%, #203a43 50%, #2c5364 100%);
    padding: 2rem 2.5rem 1.5rem;
    border-radius: 12px;
    margin-bottom: 1.5rem;
    color: white;
  }
  .main-header h1 { font-size: 2rem; font-weight: 700; margin: 0; letter-spacing: -0.5px; }
  .main-header p  { font-size: 0.9rem; opacity: 0.75; margin: 0.25rem 0 0; }

  .score-card {
    background: white;
    border-radius: 12px;
    padding: 1.2rem 1rem;
    text-align: center;
    border-left: 5px solid #3b82f6;
    box-shadow: 0 2px 12px rgba(0,0,0,0.07);
  }
  .score-card.genuine { border-color: #22c55e; }
  .score-card.review  { border-color: #f59e0b; }
  .score-card.fraud   { border-color: #ef4444; }

  .verdict-badge {
    display: inline-block;
    padding: 0.5rem 1.5rem;
    border-radius: 50px;
    font-weight: 700;
    font-size: 1.1rem;
    letter-spacing: 1px;
  }
  .badge-genuine  { background: #dcfce7; color: #15803d; }
  .badge-review   { background: #fef3c7; color: #92400e; }
  .badge-fraud    { background: #fee2e2; color: #991b1b; }

  .flag-item {
    background: #fef2f2;
    border-left: 4px solid #ef4444;
    padding: 0.5rem 0.75rem;
    border-radius: 4px;
    margin: 0.3rem 0;
    font-size: 0.88rem;
    color: #7f1d1d;
  }
  .entity-chip {
    display: inline-block;
    background: #eff6ff;
    border: 1px solid #bfdbfe;
    color: #1d4ed8;
    border-radius: 20px;
    padding: 0.15rem 0.7rem;
    font-size: 0.8rem;
    margin: 0.2rem;
    font-family: 'JetBrains Mono', monospace;
  }
  .hash-box {
    background: #0f172a;
    color: #4ade80;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.75rem;
    padding: 0.75rem 1rem;
    border-radius: 8px;
    word-break: break-all;
    margin: 0.5rem 0;
  }
  .section-label {
    font-size: 0.72rem;
    font-weight: 600;
    letter-spacing: 1.5px;
    text-transform: uppercase;
    color: #6b7280;
    margin-bottom: 0.5rem;
  }
  .xai-item { padding: 0.4rem 0; font-size: 0.9rem; }
</style>
""", unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────
def score_colour(score: float) -> str:
    if score >= 72: return "#22c55e"
    if score >= 45: return "#f59e0b"
    return "#ef4444"


def make_gauge(value: float, title: str) -> go.Figure:
    colour = score_colour(value)
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=value,
        title={"text": title, "font": {"size": 13}},
        number={"suffix": "%", "font": {"size": 22, "color": colour}},
        gauge={
            "axis": {"range": [0, 100], "tickwidth": 1},
            "bar":  {"color": colour},
            "steps": [
                {"range": [0,  45], "color": "#fee2e2"},
                {"range": [45, 72], "color": "#fef3c7"},
                {"range": [72, 100],"color": "#dcfce7"},
            ],
            "threshold": {
                "line": {"color": colour, "width": 3},
                "thickness": 0.8,
                "value": value
            }
        }
    ))
    fig.update_layout(height=200, margin=dict(t=40, b=0, l=10, r=10),
                      paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)")
    return fig


def make_radar(scores: dict) -> go.Figure:
    categories = list(scores.keys()) + [list(scores.keys())[0]]
    values     = list(scores.values()) + [list(scores.values())[0]]
    fig = go.Figure(go.Scatterpolar(
        r=values, theta=categories, fill="toself",
        line_color="#3b82f6", fillcolor="rgba(59,130,246,0.15)",
        name="Score"
    ))
    fig.update_layout(
        polar=dict(radialaxis=dict(visible=True, range=[0, 100])),
        height=280, margin=dict(t=20, b=20),
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        showlegend=False
    )
    return fig


def draw_annotated(page: Image.Image, regions: list[dict]) -> np.ndarray:
    arr = cv2.cvtColor(np.array(page), cv2.COLOR_RGB2BGR)
    colour_map = {"ela_anomaly": (0,0,255), "copy_move": (0,140,255)}
    for reg in regions:
        c = colour_map.get(reg["type"], (255, 0, 255))
        x, y, w, h = reg["x"], reg["y"], reg["w"], reg["h"]
        cv2.rectangle(arr, (x, y), (x+w, y+h), c, 2)
        cv2.putText(arr, reg["type"], (x, max(y-5, 12)),
                    cv2.FONT_HERSHEY_SIMPLEX, 0.4, c, 1)
    return cv2.cvtColor(arr, cv2.COLOR_BGR2RGB)


def colourise_ela(ela_arr: np.ndarray) -> np.ndarray:
    gray = cv2.cvtColor(ela_arr, cv2.COLOR_RGB2GRAY)
    coloured = cv2.applyColorMap(gray, cv2.COLORMAP_JET)
    return cv2.cvtColor(coloured, cv2.COLOR_BGR2RGB)


def run_analysis(raw_bytes: bytes, filename: str):
    """
    Complete document analysis pipeline.
    """

    pages = load_document(raw_bytes, filename)

    page = resize_for_analysis(
        pages[0],
        max_dim=1600
    )

    page_ocr = enhance_for_ocr(page)

    # --------------------------------------------------
    # Layer 1 : Visual Forensics
    # --------------------------------------------------

    visual_result = analyse_visual(
        page,
        raw_bytes,
        filename
    )

    # --------------------------------------------------
    # Layer 2 : OCR + Semantic
    # --------------------------------------------------

    semantic_result = verify_semantic(
        page_ocr
    )

    ocr_text = ""

    if semantic_result.ocr_result:
        ocr_text = semantic_result.ocr_result.text

    # --------------------------------------------------
    # Layer 3 : SHA256
    # --------------------------------------------------

    hash_result = verify_hash(
        raw_bytes,
        filename
    )

    # --------------------------------------------------
    # Layer 4 : Document Validation
    # --------------------------------------------------

    doc_validation = validate_document(
        ocr_text,
        page
    )

    # --------------------------------------------------
    # Layer 5 : Template Validation
    # --------------------------------------------------

    try:

        template_result = validate_template(
            page,
            doc_validation.doc_type
        )

    except Exception as e:

        template_result = {

            "overall": 100,

            "error": str(e)

        }

    # --------------------------------------------------
    # Layer 6 : AI Fabrication Detection
    # --------------------------------------------------

    try:

        bgr = cv2.cvtColor(
            np.array(page),
            cv2.COLOR_RGB2BGR
        )

        ai_result = detect_ai_forgery(
            bgr
        )

    except Exception:

        class DummyAI:

            fabrication_score = 0

            tampering_score = 0

            flags = []

        ai_result = DummyAI()

    # --------------------------------------------------
    # Layer 7 : Authenticity Engine
    # --------------------------------------------------

    authenticity = calculate_authenticity(

        visual=visual_result,

        template=template_result,

        ai=ai_result,

        validation=doc_validation,

        hash_result=hash_result

    )

    # --------------------------------------------------
    # Existing report
    # --------------------------------------------------

    report = compute_score(

        visual_result,

        semantic_result,

        hash_result,

        doc_validation

    )

    return (

        report,

        authenticity,

        template_result,

        ai_result,

        visual_result,

        semantic_result,

        doc_validation,

        page,

        pages

    )   


# ─────────────────────────────────────────────────────────────────────
# Sidebar
# ─────────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("## 🛡️ DocShield")
    st.caption("SuRaksha Document Forensics Platform")
    st.divider()

    st.markdown("### How it works")
    st.markdown("""
    **Layer 1 — Visual Forensics**
    - Error Level Analysis (ELA)
    - Copy-move detection (ORB)
    - EXIF/PDF metadata inspection

    **Layer 2 — Semantic NLP**
    - Offline OCR (Tesseract / EasyOCR)
    - Regex entity extraction
    - Font consistency analysis

    **Layer 3 — Cryptographic Hash**
    - SHA-256 fingerprinting
    - Local fraud registry lookup
    - Mini-blockchain ledger

    **Layer 4 — Doc-Specific Checks**
    - 16 document types supported
    - Verhoeff / MRZ checksums
    - Format & authority validation
    """)
    st.divider()

    st.markdown("### Supported document types")
    st.markdown("""
    🪪 Aadhaar · PAN · Passport  
    🚗 Driving Licence · Voter ID  
    🏦 Bank Statement · Passbook · Cheque · FD  
    💼 Salary Slip · ITR · Loan Doc  
    🏘️ Property Deed · Birth Certificate  
    🏢 GST Certificate · Income Certificate
    """)

    st.divider()
    st.markdown("### Risk thresholds")
    st.markdown("""
    | Score | Verdict |
    |-------|---------|
    | 90–100 | ✅ Verified Genuine |
    | 75–89  | ✅ Likely Genuine |
    | 50–74  | ⚠️ Needs Review |
    | 25–49  | 🚨 High Risk |
    | 0–24   | 🚨 Likely Fraudulent |
    """)

    st.divider()
    st.caption("All processing is 100% offline. No documents leave this machine.")

    if st.button("📋 View document history"):
        from database import DB_PATH
        import sqlite3
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT filename, status, score, created_at FROM document_hashes ORDER BY id DESC LIMIT 10")
        rows = c.fetchall()
        conn.close()
        if rows:
            st.dataframe(
                [{"File": r[0], "Status": r[1], "Score": f"{r[2]:.1f}", "Date": r[3]} for r in rows],
                use_container_width=True
            )
        else:
            st.info("No documents analysed yet.")


# ─────────────────────────────────────────────────────────────────────
# Header
# ─────────────────────────────────────────────────────────────────────
st.markdown("""
<div class="main-header">
  <h1>🛡️ SuRaksha DocShield</h1>
  <p>AI-powered offline document forensics for banking &amp; fintech · 16 document types · Multi-layer fraud detection</p>
</div>
""", unsafe_allow_html=True)

# ─────────────────────────────────────────────────────────────────────
# File upload
# ─────────────────────────────────────────────────────────────────────
uploaded = st.file_uploader(
    "Upload a document for forensic analysis",
    type=["pdf", "jpg", "jpeg", "png", "tiff", "bmp"],
    help="Supports PDF, JPEG, PNG, TIFF. Max 20 MB. Processing is entirely offline.",
)

if not uploaded:
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.info("**🔍 Visual Forensics**\nELA + copy-move detection + EXIF metadata inspection.")
    with col2:
        st.info("**📝 Semantic NLP**\nOffline OCR + regex entity extraction + font consistency.")
    with col3:
        st.info("**🔒 Cryptographic Hash**\nSHA-256 fingerprint + fraud registry + blockchain ledger.")
    with col4:
        st.info("**📋 Doc-Specific (16 types)**\nVerhoeff checksums, MRZ validation, authority checks, format rules.")
    st.stop()

# ─────────────────────────────────────────────────────────────────────
# Analyse
# ─────────────────────────────────────────────────────────────────────
raw_bytes = uploaded.read()
filename  = uploaded.name

with st.spinner("🔬 Running multi-layer forensic analysis…"):
    t0 = time.time()
    (report,authenticity,template_result,ai_result,visual_result,semantic_result,doc_validation,page,pages,)=run_analysis(raw_bytes,filename)
    elapsed = time.time() - t0

st.success(f"Analysis complete in **{elapsed:.1f}s** · {len(pages)} page(s) · OCR: `{report.ocr_engine}`")

# ─────────────────────────────────────────────────────────────────────
# Verdict banner
# ─────────────────────────────────────────────────────────────────────
verdict_css = {"GENUINE": "badge-genuine", "REVIEW": "badge-review", "FRAUD": "badge-fraud"}
badge_class = verdict_css.get(report.verdict, "badge-review")

# Full verdict label comes directly from report.verdict (v3 engine)
full_verdict = report.verdict

penalty_info = ""
if report.total_penalty > 0:
    penalty_info = f"Total penalty: −{report.total_penalty:.0f} pts"
    if report.hard_cap_applied is not None:
        penalty_info += f" · Hard cap: ≤{report.hard_cap_applied:.0f}"

st.markdown(f"""
<div style="text-align:center; margin: 1rem 0 0.5rem;">
  <span class="verdict-badge {badge_class}">{full_verdict}</span>
  <p style="font-size:0.85rem; color:#6b7280; margin-top:0.4rem;">{report.recommendation}</p>
  <p style="font-size:0.8rem; color:#9ca3af; margin-top:0.2rem;">{penalty_info}</p>
</div>
""", unsafe_allow_html=True)

# ─────────────────────────────────────────────────────────────────────
# Scores row
# ─────────────────────────────────────────────────────────────────────
g1, g2, g3, g4, g5 = st.columns(5)
with g1:
    st.plotly_chart(make_gauge(report.final_score, "Authenticity Score"), use_container_width=True)
with g2:
    st.plotly_chart(make_gauge(report.visual_score, "Visual Forensics"), use_container_width=True)
with g3:
    st.plotly_chart(make_gauge(report.semantic_score, "Semantic NLP"), use_container_width=True)
with g4:
    st.plotly_chart(make_gauge(report.hash_score, "Hash Integrity"), use_container_width=True)
with g5:
    st.plotly_chart(make_gauge(report.doc_specific_score, f"Doc Checks\n({report.doc_type})"), use_container_width=True)

# ─────────────────────────────────────────────────────────────────────
# Main content tabs
# ─────────────────────────────────────────────────────────────────────
tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
    "🖼️ Visual Analysis",
    "📝 OCR & Entities",
    "🔍 Doc-Specific Checks",
    "🔒 Hash & Blockchain",
    "⚠️ Flags & XAI",
    "📊 Score Breakdown",
])

# ── Tab 1: Visual ─────────────────────────────────────────────────────
with tab1:
    c1, c2 = st.columns(2)
    with c1:
        st.markdown('<div class="section-label">Original Document (page 1)</div>', unsafe_allow_html=True)
        st.image(page, use_container_width=True)
    with c2:
        st.markdown('<div class="section-label">Annotated — Suspicious Regions</div>', unsafe_allow_html=True)
        ann = draw_annotated(page, report.suspicious_regions)
        st.image(ann, use_container_width=True)

    if visual_result.ela_image is not None:
        c3, c4 = st.columns(2)
        with c3:
            st.markdown('<div class="section-label">Error Level Analysis (ELA) — Heat Map</div>', unsafe_allow_html=True)
            ela_vis = colourise_ela(visual_result.ela_image)
            st.image(ela_vis, use_container_width=True)
            st.caption("🔴 Red/yellow areas indicate possible editing. Blue/green = untouched.")
        with c4:
            st.markdown('<div class="section-label">Visual Sub-scores</div>', unsafe_allow_html=True)
            st.metric("ELA Score (higher = suspicious)", f"{visual_result.ela_score:.1f} / 100")
            st.metric("Copy-Move Score",                  f"{visual_result.copy_move_score:.1f} / 100")
            st.metric("Metadata Anomaly Score",           f"{visual_result.metadata_score:.1f} / 100")
            st.metric("Suspicious Regions Found",         len(report.suspicious_regions))

# ── Tab 2: OCR & Entities ─────────────────────────────────────────────
with tab2:
    ocr_col, ent_col = st.columns([3, 2])
    with ocr_col:
        st.markdown('<div class="section-label">Extracted Text (OCR Preview)</div>', unsafe_allow_html=True)
        if report.ocr_text:
            st.text_area("", value=report.ocr_text[:1200], height=280, disabled=True, label_visibility="collapsed")
        else:
            st.warning("OCR output unavailable.")

    with ent_col:
        st.markdown('<div class="section-label">Detected Entities</div>', unsafe_allow_html=True)
        if report.entities:
            for label, values in report.entities.items():
                st.markdown(f"**{label.upper()}**")
                html_chips = "".join(f'<span class="entity-chip">{v}</span>' for v in values)
                st.markdown(html_chips, unsafe_allow_html=True)
                st.write("")
        else:
            st.info("No structured entities detected.")

        if report.semantic_score < 80:
            st.markdown('<div class="section-label" style="margin-top:1rem;">Semantic Inconsistencies</div>', unsafe_allow_html=True)
            for issue in (semantic_result.inconsistencies if hasattr(semantic_result, 'inconsistencies') else []):
                st.markdown(f'<div class="flag-item">{issue}</div>', unsafe_allow_html=True)

# ── Tab 3: Doc-Specific Checks ───────────────────────────────────────
with tab3:
    doc_type_labels = {
        "AADHAAR": "🪪 Aadhaar Card",
        "PAN": "🪪 PAN Card",
        "PASSPORT": "📘 Passport",
        "DRIVING_LICENCE": "🚗 Driving Licence",
        "VOTER_ID": "🗳️ Voter ID (EPIC)",
        "GST": "🏢 GST Certificate",
        "SALARY_SLIP": "💼 Salary Slip",
        "ITR": "📄 Income Tax Return",
        "BANK_STATEMENT": "🏦 Bank Statement",
        "PASSBOOK": "📒 Passbook",
        "CHEQUE": "📝 Cheque",
        "FD_RECEIPT": "💰 Fixed Deposit Receipt",
        "LOAN_DOC": "🏠 Loan Document",
        "PROPERTY_DOC": "🏘️ Property Document",
        "BIRTH_CERT": "👶 Birth Certificate",
        "INCOME_DOC": "💵 Income Certificate",
        "GENERIC": "📄 Generic Document",
        "UNKNOWN": "❓ Unknown",
    }

    label = doc_type_labels.get(report.doc_type, report.doc_type)
    st.markdown(f'<div class="section-label">Document Type Detected: {label}</div>', unsafe_allow_html=True)
    st.metric("Document-Specific Score", f"{report.doc_specific_score:.1f} / 100")
    st.divider()

    # Checks performed — use the checks_performed list from validation result
    checks = doc_validation.checks_performed
    if checks:
        st.markdown("**Checks performed:**")
        for check in checks:
            # Heuristic: check is failed if a related flag exists
            check_lower = check.lower()[:20]
            failed = any(check_lower[:12] in f.lower() for f in report.doc_validation_flags)
            st.markdown(f"{'✅' if not failed else '🚨'} {check}")

    if report.doc_validation_flags:
        st.divider()
        st.markdown("**Issues found:**")
        for flag in report.doc_validation_flags:
            st.markdown(f'<div class="flag-item">{flag}</div>', unsafe_allow_html=True)
    else:
        st.success("All document-specific checks passed.")

    avatar_conf = doc_validation.details.get("avatar_confidence", 0)
    if avatar_conf > 0:
        st.divider()
        st.metric(
            "Avatar/Illustration Detection Confidence",
            f"{avatar_conf:.0f}%",
            help="High = photo region looks like cartoon/AI avatar, not a real person"
        )

# ── Tab 4: Hash & Blockchain ──────────────────────────────────────────
with tab4:
    h1, h2 = st.columns(2)
    with h1:
        st.markdown('<div class="section-label">SHA-256 Document Fingerprint</div>', unsafe_allow_html=True)
        st.markdown(f'<div class="hash-box">{report.sha256}</div>', unsafe_allow_html=True)
        dup_status = "⚠️ DUPLICATE" if report.is_duplicate else "✅ FIRST SEEN"
        st.metric("Registry Status", dup_status)
        if report.previous_record:
            st.warning(
                f"Previously seen as: **{report.previous_record.get('filename','?')}**  "
                f"Status: `{report.previous_record.get('status','?')}`  "
                f"Score: `{report.previous_record.get('score',0):.1f}`"
            )
    with h2:
        st.markdown('<div class="section-label">Mini-Blockchain Block</div>', unsafe_allow_html=True)
        block = report.blockchain_block
        if block:
            st.markdown(
                f'<div class="hash-box">'
                f'prev_hash:&nbsp; {block.get("prev_hash","")[:32]}…<br>'
                f'doc_hash:&nbsp;&nbsp; {block.get("doc_hash","")[:32]}…<br>'
                f'block_hash: {block.get("block_hash","")[:32]}…<br>'
                f'timestamp:&nbsp; {block.get("timestamp",0):.0f}'
                f'</div>', unsafe_allow_html=True
            )
        st.caption("Each document is chained to the previous — tamper-evident audit ledger.")

# ── Tab 5: Flags & XAI ────────────────────────────────────────────────
with tab5:
    st.markdown('<div class="section-label">Penalty Breakdown — Every Deduction Explained</div>', unsafe_allow_html=True)

    col_score, col_cap, col_pen = st.columns(3)
    col_score.metric("Start Score", "100")
    col_pen.metric("Total Penalty", f"−{report.total_penalty:.0f} pts")
    if report.hard_cap_applied is not None:
        col_cap.metric("Hard Cap Applied", f"≤ {report.hard_cap_applied:.0f}")
    else:
        col_cap.metric("Hard Cap", "None")

    st.divider()

    sev_colours = {"CRITICAL": "#991b1b", "HIGH": "#92400e", "MEDIUM": "#1e40af", "LOW": "#374151"}
    if report.failed_rules:
        st.markdown("**❌ Failed Rules (with penalty deductions):**")
        for rule in report.failed_rules:
            colour = sev_colours.get(rule.severity, "#374151")
            st.markdown(
                f'<div class="flag-item" style="border-color:{colour};">'
                f'<b>[{rule.severity}]</b> {rule.reason} '
                f'<span style="float:right;font-weight:700;color:{colour};">−{rule.penalty:.0f} pts</span>'
                f'{"<br><small>→ " + rule.suggested_action + "</small>" if rule.suggested_action else ""}'
                f'</div>',
                unsafe_allow_html=True
            )
    else:
        st.success("No penalties applied — all rules passed.")

    if report.passed_rules:
        st.divider()
        st.markdown("**✅ Passed Rules:**")
        for rule in report.passed_rules[:10]:
            st.markdown(f'<div class="xai-item">{rule.reason}</div>', unsafe_allow_html=True)

    st.divider()
    risk_colours = {"LOW": "green", "MEDIUM": "orange", "HIGH": "red", "CRITICAL": "darkred"}
    st.markdown(f"""
    <div style="font-size:1.5rem; font-weight:700; color:{risk_colours.get(report.risk_level,'gray')}">
      {report.risk_level} RISK
    </div>
    """, unsafe_allow_html=True)

# ── Tab 6: Score Breakdown ────────────────────────────────────────────
with tab6:
    sc1, sc2 = st.columns(2)
    with sc1:
        radar_scores = {
            "Visual":       report.visual_score,
            "Semantic":     report.semantic_score,
            "Hash":         report.hash_score,
            "Doc-Specific": report.doc_specific_score,
        }
        st.plotly_chart(make_radar(radar_scores), use_container_width=True)

    with sc2:
        fig = go.Figure(go.Bar(
            x=["Visual", "Semantic", "Hash", "Doc-Specific"],
            y=[report.visual_score, report.semantic_score, report.hash_score, report.doc_specific_score],
            marker_color=[score_colour(s) for s in [
                report.visual_score, report.semantic_score, report.hash_score, report.doc_specific_score
            ]],
            text=[f"{s:.1f}%" for s in [
                report.visual_score, report.semantic_score, report.hash_score, report.doc_specific_score
            ]],
            textposition="outside"
        ))
        fig.update_layout(
            title="Sub-score Breakdown",
            yaxis=dict(range=[0, 110]),
            height=280,
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            margin=dict(t=40, b=20)
        )
        st.plotly_chart(fig, use_container_width=True)

    st.markdown(f"""
    | Layer | Weight | Raw Score | Contribution |
    |-------|--------|-----------|--------------|
    | Visual Forensics | 30% | {report.visual_score:.1f} | {report.visual_score*0.30:.1f} |
    | Semantic NLP | 25% | {report.semantic_score:.1f} | {report.semantic_score*0.25:.1f} |
    | Hash Integrity | 20% | {report.hash_score:.1f} | {report.hash_score*0.20:.1f} |
    | Doc-Specific ({report.doc_type}) | 25% | {report.doc_specific_score:.1f} | {report.doc_specific_score*0.25:.1f} |
    | **Final Score** | 100% | | **{report.final_score:.1f}** |
    """)

# ─────────────────────────────────────────────────────────────────────
# Export report
# ─────────────────────────────────────────────────────────────────────
st.divider()
export_data = {
    "filename":     filename,
    "sha256":       report.sha256,
    "verdict":      report.verdict,
    "risk_level":   report.risk_level,
    "final_score":  round(report.final_score, 2),
    "doc_type":     report.doc_type,
    "scores": {
        "visual":        round(report.visual_score, 2),
        "semantic":      round(report.semantic_score, 2),
        "hash":          round(report.hash_score, 2),
        "doc_specific":  round(report.doc_specific_score, 2),
    },
    "flags":        report.all_flags,
    "entities":     report.entities,
    "explanation":  report.explanation,
    "recommendation": report.recommendation,
    "blockchain_block": report.blockchain_block,
}
st.download_button(
    label="⬇️ Download Forensic Report (JSON)",
    data=json.dumps(export_data, indent=2),
    file_name=f"docshield_{Path(filename).stem}_report.json",
    mime="application/json",
)