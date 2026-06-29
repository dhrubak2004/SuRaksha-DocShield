# 🛡️ SuRaksha DocShield

> **Offline AI-Powered Document Forensics for Banking & Fintech**
> Multi-layer fraud detection · No internet required · Explainable AI dashboard

---

## What it does

DocShield analyses uploaded documents (PDFs, images) through three simultaneous forensic layers and produces an **Authenticity Score** (0–100) with an explainable verdict for bank underwriters.

| Layer | Technique | Output |
|-------|-----------|--------|
| **Visual Forensics** | ELA, Copy-Move (ORB), EXIF metadata | Tamper score + annotated heatmap |
| **Semantic NLP** | OCR + regex entity extraction + font variance | Consistency score + entities |
| **Crypto Hash** | SHA-256 + local fraud registry + mini-blockchain | Integrity score + duplicate flag |

**Verdict thresholds:**

| Score | Verdict | Action |
|-------|---------|--------|
| ≥ 72 | ✅ GENUINE | Proceed with standard due diligence |
| 45–71 | ⚠️ REVIEW | Manual review by senior underwriter |
| < 45 | 🚨 FRAUD | Reject + escalate to fraud team |

---

## Project structure

```
docshield/
├── backend/
│   ├── main.py                    # FastAPI REST API
│   ├── database.py                # SQLite hash registry + audit log
│   ├── layers/
│   │   ├── visual_forensics.py    # Layer 1: ELA, copy-move, metadata
│   │   ├── semantic_nlp.py        # Layer 2: OCR + rule-based NLP
│   │   ├── crypto_hash.py         # Layer 3: SHA-256 + blockchain ledger
│   │   └── scoring_engine.py      # Weighted composite score + XAI
│   └── utils/
│       └── preprocessor.py        # PDF→image, enhancement, resize
├── frontend/
│   └── dashboard.py               # Streamlit XAI dashboard
├── data/                          # SQLite DB + document hashes (auto-created)
├── requirements.txt
├── Dockerfile
└── start.sh                       # Launch both services
```

---

## Quick start (local)

### 1. System dependencies

```bash
# Ubuntu / Debian
sudo apt-get install tesseract-ocr tesseract-ocr-eng poppler-utils libgl1

# macOS
brew install tesseract poppler
```

### 2. Python dependencies

```bash
pip install -r requirements.txt
```

### 3. Run

```bash
# Start both FastAPI (port 8000) + Streamlit (port 8501)
bash start.sh

# Or individually:
cd backend && uvicorn main:app --reload --port 8000
streamlit run frontend/dashboard.py --server.port 8501
```

### 4. Docker (recommended)

```bash
docker build -t docshield .
docker run -p 8000:8000 -p 8501:8501 docshield
```

- **Dashboard**: http://localhost:8501
- **API docs**: http://localhost:8000/docs

---

## API reference

### `POST /analyse`

Upload a document for forensic analysis.

```bash
curl -X POST http://localhost:8000/analyse \
  -F "file=@income_statement.pdf"
```

**Response:**
```json
{
  "filename": "income_statement.pdf",
  "final_score": 83.5,
  "verdict": "GENUINE",
  "risk_level": "LOW",
  "recommendation": "Document passes all three verification layers...",
  "scores": {
    "visual": 91.2,
    "semantic": 78.0,
    "hash": 100.0
  },
  "explanation": [
    "✅ Visual forensics: No significant tampering detected.",
    "✅ Semantic analysis: Document text appears internally consistent.",
    "✅ Hash integrity: Document not previously flagged in fraud registry."
  ],
  "flags": [],
  "entities": {
    "pan": ["ABCDE1234F"],
    "date": ["01/06/2025"],
    "amount_inr": ["Rs. 50,000"]
  },
  "sha256": "3f1e9c4a...",
  "blockchain_block": { "prev_hash": "...", "block_hash": "..." },
  "annotated_image_b64": "...",
  "ela_image_b64": "..."
}
```

### `GET /history`

Returns the last 20 analysed documents from the local registry.

### `GET /health`

Health check — confirms offline mode.

---

## How each layer works

### Layer 1: Visual Forensics

**Error Level Analysis (ELA)**
Re-saves the document image at reduced JPEG quality (90%) and computes the pixel-level difference. Edited regions show disproportionately high error levels compared to untouched areas. The difference is amplified and colourised into a heat map shown in the dashboard.

**Copy-Move Detection**
Uses ORB (Oriented FAST and Rotated BRIEF) keypoint descriptors to find regions of the image that have been copied and pasted within the same document — a common technique for duplicating seals, signatures, or stamps.

**EXIF / PDF Metadata Analysis**
Checks document metadata for suspicious software (Photoshop, GIMP, Canva, Midjourney, Stable Diffusion, etc.) and inconsistencies between creation and modification timestamps.

### Layer 2: Semantic NLP

**Offline OCR** via Tesseract (primary) or EasyOCR (fallback). Both run entirely offline after initial installation.

**Entity Extraction** via regex patterns for:
- PAN number (`ABCDE1234F` format)
- Aadhaar (`XXXX XXXX XXXX`)
- Dates, INR amounts
- GST numbers, phone numbers, email, pincodes

**Consistency Checks:**
- Name spelling inconsistency across pages (edit-distance heuristic)
- Zero-value amounts
- High font height variance (indicates text insertion from another source)
- Low OCR confidence (indicates image overlays)

### Layer 3: Cryptographic Hash

**SHA-256 Fingerprint** — every document gets a unique hash that changes if even a single pixel or byte is modified.

**Local Registry** (SQLite) — previous scans are stored. Duplicates are flagged, and previously-FLAGGED documents are automatically downscored.

**Mini-Blockchain Ledger** — each new document creates a block containing the previous block's hash, making the audit trail tamper-evident. Judges love this for hackathons.

---

## Scoring formula

```
Authenticity Score = 0.40 × (100 - visual_tamper) 
                   + 0.35 × semantic_score 
                   + 0.25 × hash_integrity_score
```

---

## Extending for production

| Feature | How to add |
|---------|-----------|
| Better NLP | `pip install spacy && python -m spacy download en_core_web_sm` — replace regex with spaCy NER |
| AI-generated doc detection | Add DistilBERT / MiniLM locally via `sentence-transformers` |
| Real blockchain | Replace mini-chain with Hyperledger Fabric or Ethereum private node |
| Multi-page analysis | Loop `analyse_visual` over all pages, aggregate scores |
| Template matching | Add a reference document set and compare layout structure |
| API auth | Add JWT middleware to FastAPI |

---

## Technologies

| Component | Technology | Why |
|-----------|-----------|-----|
| Backend API | FastAPI + Uvicorn | Fast async, auto-docs |
| Image analysis | OpenCV + Pillow | Battle-tested, offline |
| OCR | Tesseract / EasyOCR | Both fully offline |
| NLP | Regex + spaCy (optional) | No cloud dependency |
| Database | SQLite | Zero-config, portable |
| Hashing | hashlib SHA-256 | Standard, fast |
| Dashboard | Streamlit + Plotly | Rapid prototyping |
| Deployment | Docker | Reproducible |

**100% offline — no document ever leaves the machine.**
