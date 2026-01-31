import sys
import os
import pandas as pd
import joblib
from sklearn.ensemble import IsolationForest

# ---------------- PATH FIX ---------------- #
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../"))
sys.path.insert(0, PROJECT_ROOT)

from ml.anomaly.anomaly_preprocessing import preprocess_anomaly_data

# ---------------- CONFIG ---------------- #
DATA_PATH = "D:/syllabus books VIT/Capstone/soc-intrusion-detection/data/raw/UNSW_NB15_training-set.csv"

MODEL_DIR = "ml/anomaly/models"
MODEL_PATH = os.path.join(MODEL_DIR, "anomaly_model.pkl")

os.makedirs(MODEL_DIR, exist_ok=True)

# ---------------------------------------- #

print("[*] Loading data...")
df = pd.read_csv(DATA_PATH)

# -------- TRAIN ONLY ON NORMAL TRAFFIC -------- #
if "label" in df.columns:
    df = df[df["label"] == 0]

print(f"[*] Normal samples: {len(df)}")

print("[*] Preprocessing...")
X = preprocess_anomaly_data(df, fit=True)

print("[*] Training Isolation Forest...")
model = IsolationForest(
    n_estimators=200,
    contamination=0.05,
    random_state=42,
    n_jobs=-1
)
model.fit(X)

joblib.dump(model, MODEL_PATH)

print("[✅] Anomaly model trained and saved!")
