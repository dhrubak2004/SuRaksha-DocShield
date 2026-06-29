"""
SuRaksha DocShield
Offline AI / Fabricated Document Detector

Detects:
- AI-generated documents
- Photoshop edits
- Canva edits
- Synthetic textures

No internet required.
"""

from dataclasses import dataclass, field

import cv2
import numpy as np
@dataclass
class ForgeryResult:

    fabrication_score: float = 0.0

    tampering_score: float = 0.0

    flags: list[str] = field(default_factory=list)

    details: dict = field(default_factory=dict)
def fft_score(gray):

    f = np.fft.fft2(gray)

    fshift = np.fft.fftshift(f)

    magnitude = np.log(np.abs(fshift) + 1)

    h,w = magnitude.shape

    center = magnitude[
        h//2-40:h//2+40,
        w//2-40:w//2+40
    ]

    outer = magnitude.copy()

    outer[
        h//2-40:h//2+40,
        w//2-40:w//2+40
    ] = 0

    center_energy = np.mean(center)

    outer_energy = np.mean(outer)

    score = 100*(1-center_energy/(outer_energy+1e-6))

    return max(0,min(score,100))
def noise_score(gray):

    blur = cv2.GaussianBlur(
        gray,
        (5,5),
        0
    )

    residual = cv2.absdiff(
        gray,
        blur
    )

    std = np.std(residual)

    score = 100-min(std,40)/40*100

    return max(0,min(score,100))

def texture_score(gray):

    lap = cv2.Laplacian(
        gray,
        cv2.CV_64F
    )

    variance = lap.var()

    score = 100-min(variance,900)/900*100

    return max(0,min(score,100))    

def edge_score(gray):

    edge = cv2.Canny(
        gray,
        100,
        220
    )

    density = np.sum(edge>0)/edge.size

    score = 100-100*min(density,0.12)/0.12

    return max(0,min(score,100))
def jpeg_artifact_score(gray):
    """
    Detect JPEG compression artifacts.
    """

    h, w = gray.shape

    vertical = []

    horizontal = []

    for x in range(8, w, 8):

        diff = np.abs(
            gray[:, x].astype(np.int16)
            - gray[:, x-1].astype(np.int16)
        )

        vertical.append(np.mean(diff))

    for y in range(8, h, 8):

        diff = np.abs(
            gray[y, :].astype(np.int16)
            - gray[y-1, :].astype(np.int16)
        )

        horizontal.append(np.mean(diff))

    score = (np.mean(vertical) + np.mean(horizontal)) / 2

    return min(score * 4, 100)  
def gradient_score(gray):
    """
    AI images often contain unnaturally smooth gradients.
    """

    gx = cv2.Sobel(gray, cv2.CV_64F, 1, 0)
    gy = cv2.Sobel(gray, cv2.CV_64F, 0, 1)

    magnitude = np.sqrt(gx**2 + gy**2)

    std = np.std(magnitude)

    score = 100 - min(std, 80) / 80 * 100

    return max(0, min(score, 100))
def colour_distribution_score(image):
    """
    AI-generated images usually have overly smooth
    color distributions.
    """

    hsv = cv2.cvtColor(image, cv2.COLOR_BGR2HSV)

    hist = cv2.calcHist(
        [hsv],
        [0, 1],
        None,
        [32, 32],
        [0, 180, 0, 256]
    )

    hist = cv2.normalize(hist, hist).flatten()

    entropy = -np.sum(hist * np.log2(hist + 1e-10))

    score = 100 - min(entropy * 8, 100)

    return float(score)

def detect_ai_forgery(image):

    if len(image.shape) == 3:
        gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
    else:
        gray = image.copy()

    result = ForgeryResult()

    fft = fft_score(gray)

    noise = noise_score(gray)

    texture = texture_score(gray)

    edge = edge_score(gray)

    jpeg = jpeg_artifact_score(gray)

    colour = colour_distribution_score(image)

    gradient = gradient_score(gray)

    result.details = {

        "fft": fft,

        "noise": noise,

        "texture": texture,

        "edge": edge,

        "jpeg": jpeg,

        "colour": colour,

        "gradient": gradient

    }

    # Weighted fabrication score
    fabrication = (

        0.22 * fft +

        0.18 * noise +

        0.16 * texture +

        0.12 * edge +

        0.12 * jpeg +

        0.10 * colour +

        0.10 * gradient

    )

    result.fabrication_score = round(fabrication, 2)

    # Tampering score (editing leaves compression + noise traces)
    result.tampering_score = round(

        0.45 * jpeg +

        0.35 * noise +

        0.20 * fft,

        2

    )

    # Generate flags
    if fft > 70:
        result.flags.append("High frequency-domain anomaly detected")

    if noise > 70:
        result.flags.append("Sensor noise pattern inconsistent")

    if texture > 70:
        result.flags.append("Texture appears unnaturally smooth")

    if edge > 70:
        result.flags.append("Edge distribution inconsistent with scanned documents")

    if jpeg > 70:
        result.flags.append("Strong JPEG compression artifacts detected")

    if gradient > 70:
        result.flags.append("Gradient smoothness suggests synthetic generation")

    if colour > 70:
        result.flags.append("Colour distribution appears artificial")

    return result
