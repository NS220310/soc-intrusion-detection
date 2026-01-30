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
        Returns anomaly score
        Higher = more anomalous
        """
        scores = self.model.decision_function(X)
        return -scores  # higher = more suspicious
