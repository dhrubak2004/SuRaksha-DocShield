from pathlib import Path
import sys
import cv2
import numpy as np
import joblib

from skimage.feature import hog
from skimage.feature import local_binary_pattern

# --------------------------------------------------
# Config
# --------------------------------------------------

ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(ROOT))

from layers.document_masks import apply_mask

TEMPLATE_DIR = ROOT / "templates" / "processed"
OUTPUT_DIR = ROOT / "features"

OUTPUT_DIR.mkdir(exist_ok=True)

ORB = cv2.ORB_create(nfeatures=3000)

LBP_RADIUS = 2
LBP_POINTS = 16

# --------------------------------------------------
# Feature Extraction
# --------------------------------------------------

def extract_features(image):

    image = cv2.resize(image, (900, 600))

    gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)

    # ---------------- ORB ----------------

    kp, des = ORB.detectAndCompute(gray, None)

    if des is None:
        des = np.empty((0, 32), dtype=np.uint8)

    # ---------------- HOG ----------------

    hog_vector = hog(
        gray,
        orientations=9,
        pixels_per_cell=(16, 16),
        cells_per_block=(2, 2),
        feature_vector=True,
    )

    # ---------------- LBP ----------------

    lbp = local_binary_pattern(
        gray,
        LBP_POINTS,
        LBP_RADIUS,
    )

    hist, _ = np.histogram(
        lbp.ravel(),
        bins=64,
        range=(0, 64),
    )

    hist = hist.astype(np.float32)
    hist /= hist.sum() + 1e-6

    # ---------------- Edge Histogram ----------------

    edge = cv2.Canny(gray, 80, 180)

    edge_hist = cv2.calcHist(
        [edge],
        [0],
        None,
        [32],
        [0, 256],
    )

    edge_hist = cv2.normalize(
        edge_hist,
        edge_hist,
    ).flatten()

    # ---------------- Color Histogram ----------------

    hsv = cv2.cvtColor(
        image,
        cv2.COLOR_BGR2HSV,
    )

    colour = cv2.calcHist(
        [hsv],
        [0, 1],
        None,
        [32, 32],
        [0, 180, 0, 256],
    )

    colour = cv2.normalize(
        colour,
        colour,
    ).flatten()

    return {

        "orb": des,

        "hog": hog_vector,

        "lbp": hist,

        "edge": edge_hist,

        "colour": colour,

    }


# --------------------------------------------------
# Build Feature Database
# --------------------------------------------------

print("=" * 60)
print("Building Feature Database...")
print("=" * 60)

for folder in TEMPLATE_DIR.iterdir():

    if not folder.is_dir():
        continue

    print(f"\nProcessing {folder.name}")

    document = []

    for img_path in folder.glob("*"):

        if img_path.suffix.lower() not in [".png", ".jpg", ".jpeg"]:
            continue

        img = cv2.imread(str(img_path))

        if img is None:
            continue

        # --------------------------------------
        # Apply document-specific mask
        # --------------------------------------

        masked = apply_mask(
            img,
            folder.name
        )

        # --------------------------------------
        # Extract features
        # --------------------------------------

        features = extract_features(masked)

        # --------------------------------------
        # Store template
        # --------------------------------------

        document.append({

            "name": img_path.name,

            "features": features

        })

        print(f"  ✓ {img_path.name}")

    out = OUTPUT_DIR / f"{folder.name.lower()}.pkl"

    joblib.dump(document, out)

    print(f"Saved -> {out}")

print("\nFeature database created successfully!")