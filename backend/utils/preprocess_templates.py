"""
Preprocess all document templates before feature extraction.

Input:
backend/templates/images/

Output:
backend/templates/processed/
"""

from pathlib import Path
import cv2
import numpy as np

ROOT = Path(__file__).resolve().parents[1]

INPUT_DIR = ROOT / "templates" / "images"
OUTPUT_DIR = ROOT / "templates" / "processed"

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


TARGET_WIDTH = 1000
TARGET_HEIGHT = 650


def preprocess(img):

    # Resize
    img = cv2.resize(img, (TARGET_WIDTH, TARGET_HEIGHT))

    # Denoise
    img = cv2.fastNlMeansDenoisingColored(img, None, 5, 5, 7, 21)

    # Normalize illumination
    lab = cv2.cvtColor(img, cv2.COLOR_BGR2LAB)

    l, a, b = cv2.split(lab)

    clahe = cv2.createCLAHE(
        clipLimit=2.0,
        tileGridSize=(8, 8)
    )

    l = clahe.apply(l)

    img = cv2.cvtColor(
        cv2.merge([l, a, b]),
        cv2.COLOR_LAB2BGR
    )

    return img


for folder in INPUT_DIR.iterdir():

    if not folder.is_dir():
        continue

    out_folder = OUTPUT_DIR / folder.name
    out_folder.mkdir(exist_ok=True)

    print(f"\nProcessing {folder.name}")

    for img_path in folder.glob("*"):

        img = cv2.imread(str(img_path))

        if img is None:
            continue

        img = preprocess(img)

        cv2.imwrite(
            str(out_folder / img_path.name),
            img
        )

        print("Saved", img_path.name)

print("\nDone.")