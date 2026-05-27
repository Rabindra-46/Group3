from pathlib import Path

import joblib

MODEL_PATH = Path(__file__).resolve().parent.parent / 'phishing_model.pkl'
_MODEL = None
_MODEL_MTIME = None


def load_model():
    global _MODEL, _MODEL_MTIME

    if not MODEL_PATH.exists():
        _MODEL = None
        _MODEL_MTIME = None
        return None

    model_mtime = MODEL_PATH.stat().st_mtime
    if _MODEL is not None and _MODEL_MTIME == model_mtime:
        return _MODEL

    try:
        _MODEL = joblib.load(MODEL_PATH)
        _MODEL_MTIME = model_mtime
        return _MODEL
    except Exception:
        _MODEL = None
        _MODEL_MTIME = None
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
