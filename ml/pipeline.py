# ml/pipeline.py

import os
import pandas as pd

from ml.core.event import Event
from ml.core.model_loader import ModelLoader
from ml.core.preprocessor import Preprocessor
from ml.supervised.detector import SupervisedDetector
from ml.anomaly.anomaly_model import AnomalyDetector
from ml.campaign.builder import CampaignBuilder


def run_pipeline(csv_path):
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    MODEL_DIR = os.path.join(BASE_DIR, "model")

    print("[*] Loading models and preprocessor...")
    loader = ModelLoader(MODEL_DIR)
    preprocessor = Preprocessor(MODEL_DIR)
    detector = SupervisedDetector(loader.binary_model, loader.multiclass_model)

    print("[*] Loading CSV...")
    df = pd.read_csv(csv_path)

    print("[*] Saving metadata columns...")
    
    times = df["stime"] if "stime" in df.columns else pd.Series(df.index)
    srcips = df["srcip"] if "srcip" in df.columns else ["unknown"] * len(df)
    dstips = df["dstip"] if "dstip" in df.columns else ["unknown"] * len(df)

    print("[*] Preprocessing features...")
    X = preprocessor.transform(df)

    print("[*] Running supervised models...")
    attack_probs, attack_types = detector.analyze(X)

    print("[*] Running anomaly detection...")

    anomaly_detector = AnomalyDetector()
    anomaly_scores = anomaly_detector.predict(X)

    print("[*] Building Event objects...")

    events = []
    for i in range(len(df)):
        # Use dataset 'id' column if exists, else row index
        if "id" in df.columns:
            flow_id = int(df["id"].iloc[i])
        else:
            flow_id = i

        ev = Event(flow_id)
        ev.attack_prob = float(attack_probs[i])
        ev.attack_type = str(attack_types[i])
        ev.anomaly_score = float(anomaly_scores[i])
        events.append(ev)
    print("[*] Building campaigns...")

    builder = CampaignBuilder()
    campaigns = builder.build_campaigns(events)

    print("[*] Summarizing campaigns...")

    summaries = [builder.summarize(c) for c in campaigns]

    print("\n==============================")
    print("   CAMPAIGN SUMMARIES")
    print("==============================\n")

    for s in summaries:
        print(s.to_dict())

    print("\n[*] Sample events after anomaly:")
    for e in events[:5]:
        print(e.to_dict())



    print("[*] Done. Sample output:\n")
    for e in events[:5]:
        print(e.to_dict())

    return events


if __name__ == "__main__":
    events = run_pipeline("data/unsw_sample.csv")  # change path
