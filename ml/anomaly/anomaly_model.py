import joblib
import numpy as np

class AnomalyDetector:
    """
    Unsupervised anomaly detector wrapper
    """

    def __init__(self, model_path):
        self.model = joblib.load(model_path)

    def score(self, X):
        """
        Returns anomaly score per flow (higher = more anomalous).
        """
        scores = self.model.decision_function(X)
        return -scores  # higher = more suspicious

# Large positive	Highly anomalous
# Small / negative	Normal

    def average_score(self, X):
        """
        Returns a single average anomaly score for a group of flows.
        """
        scores = self.score(X)
        return float(np.mean(scores))
