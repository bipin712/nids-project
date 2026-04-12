import joblib, numpy as np, os

MODEL_PATH = os.path.join('models', 'rf_model.pkl')

try:
    model    = joblib.load(MODEL_PATH)
    ML_READY = True
    print(f"[ML] Model loaded — classes: {model.classes_}")
except FileNotFoundError:
    model    = None
    ML_READY = False
    print("[ML] WARNING: rf_model.pkl not found. Run train_model.py first.")

def classify(feature_vector):
    """Returns predicted class: normal/dos/probe/r2l/u2r"""
    if not ML_READY:
        return 'unknown'
    try:
        arr  = np.array(feature_vector).reshape(1, -1)
        return model.predict(arr)[0]
    except Exception as e:
        print(f"[ML] Error: {e}")
        return 'unknown'

def get_confidence(feature_vector):
    """Returns confidence score 0.0 to 1.0"""
    if not ML_READY:
        return 0.0
    try:
        arr   = np.array(feature_vector).reshape(1, -1)
        proba = model.predict_proba(arr)[0]
        return round(float(max(proba)), 2)
    except:
        return 0.0

def is_ready():
    return ML_READY