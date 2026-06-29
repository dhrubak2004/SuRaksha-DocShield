"""
SuRaksha DocShield
Authenticity Fusion Engine

Combines all detection layers into one final decision.
"""

from dataclasses import dataclass, field

print("Loaded authenticity_engine from:", __file__)
@dataclass
class AuthenticityResult:

    authenticity_score: float = 100.0

    classification: str = "GENUINE"

    risk: str = "LOW"

    fabricated_probability: float = 0.0

    tampered_probability: float = 0.0

    reasons: list[str] = field(default_factory=list)

    details: dict = field(default_factory=dict)


# ---------------------------------------------------------
# Main Engine
# ---------------------------------------------------------

def calculate_authenticity(
    visual=None,
    template=None,
    ai=None,
    validation=None,
    hash_result=None,
):

    score = 100.0

    reasons = []

    details = {}

    # -----------------------------------------------------
    # Visual Forensics
    # -----------------------------------------------------

    if visual is not None:

        details["visual"] = visual.tamper_score

        if visual.tamper_score > 80:
            score -= 45
            reasons.append("Very strong visual tampering detected")

        elif visual.tamper_score > 60:
            score -= 30
            reasons.append("Visual forgery indicators detected")

        elif visual.tamper_score > 40:
            score -= 15
            reasons.append("Minor visual anomalies detected")

        reasons.extend(visual.flags)

    # -----------------------------------------------------
    # Template Matching
    # -----------------------------------------------------

    if template is not None:

        similarity = getattr(template, "score", 100)

        details["template_similarity"] = similarity

        if similarity < 30:
            score -= 45
            reasons.append("Document template mismatch")

        elif similarity < 50:
            score -= 30
            reasons.append("Low template similarity")

        elif similarity < 70:
            score -= 15
            reasons.append("Template partially matches")

    # -----------------------------------------------------
    # AI Detector
    # -----------------------------------------------------

    if ai is not None:

        details["fabrication_score"] = ai.fabrication_score

        details["tampering_score"] = ai.tampering_score

        if ai.fabrication_score > 90:
            score -= 50
            reasons.append("Very high probability of AI-generated document")

        elif ai.fabrication_score > 75:
            score -= 35
            reasons.append("Strong AI generation indicators")

        elif ai.fabrication_score > 55:
            score -= 20
            reasons.append("Possible AI generated document")

        reasons.extend(ai.flags)

    # -----------------------------------------------------
    # Document Validator
    # -----------------------------------------------------

    if validation is not None:

        details["document_score"] = validation.doc_score

        penalty = (100 - validation.doc_score) * 0.50

        score -= penalty

        reasons.extend(validation.flags)

    # -----------------------------------------------------
    # SHA256 / Registry
    # -----------------------------------------------------

    if hash_result is not None:

        details["hash"] = hash_result

        if isinstance(hash_result, dict):

            if hash_result.get("registry_match") is False:

                score -= 20

                reasons.append("Hash not found in trusted registry")

            if hash_result.get("blacklisted"):

                score = 0

                reasons.append("Document fingerprint found in fraud registry")

    # -----------------------------------------------------
    # Clamp
    # -----------------------------------------------------

    score = max(0, min(score, 100))

    # -----------------------------------------------------
    # Tampered Probability
    # -----------------------------------------------------

    tampered = 0

    if visual is not None:

        tampered += visual.tamper_score * 0.60

    if ai is not None:

        tampered += ai.tampering_score * 0.40

    tampered = min(tampered, 100)

    # -----------------------------------------------------
    # Fabricated Probability
    # -----------------------------------------------------

    fabricated = 0

    if ai is not None:
        fabricated += ai.fabrication_score * 0.70

    if template is not None:
        fabricated += (100 - template.score) * 0.30

    # -----------------------------------------------------
    # Classification
    # -----------------------------------------------------

    if score >= 90:

        classification = "GENUINE"

        risk = "LOW"

    elif score >= 70:

        classification = "LOW RISK"

        risk = "LOW"

    elif score >= 40:

        classification = "SUSPICIOUS"

        risk = "MEDIUM"

    elif fabricated > tampered:

        classification = "FABRICATED"

        risk = "HIGH"

    else:

        classification = "TAMPERED"

        risk = "HIGH"

    return AuthenticityResult(

        authenticity_score=round(score, 2),

        classification=classification,

        risk=risk,

        fabricated_probability=round(fabricated, 2),

        tampered_probability=round(tampered, 2),

        reasons=list(dict.fromkeys(reasons)),

        details=details,

    )