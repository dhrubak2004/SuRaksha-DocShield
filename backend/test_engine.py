from layers.authenticity_engine import calculate_authenticity

# Fake objects for testing
class Visual:
    tamper_score = 72
    flags = ["ELA anomaly", "Copy-move detected"]

class AI:
    fabrication_score = 91
    tampering_score = 44
    flags = ["AI texture detected"]

class Validation:
    doc_score = 62
    flags = ["Invalid PAN format"]

template = {
    "overall": 42
}

result = calculate_authenticity(
    visual=Visual(),
    template=template,
    ai=AI(),
    validation=Validation(),
)

print(result)