from functools import lru_cache
from pathlib import Path

import joblib

MODEL_PATH = Path(__file__).resolve().parent.parent / 'phishing_model.pkl'


@lru_cache(maxsize=1)
def load_model():
    if not MODEL_PATH.exists():
        return None
    try:
        return joblib.load(MODEL_PATH)
    except Exception:
        return None


def predict_phishing_probability(email_text):
    model = load_model()
    if model is None:
        return None

    try:
        probability = model.predict_proba([email_text])[0][1]
    except Exception:
        return None

    return round(float(probability) * 100, 2)
