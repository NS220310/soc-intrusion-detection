import numpy as np

class EventVectorizer:
    """
    Converts Event objects into numeric vectors for clustering.
    """

    def vectorize(self, events):
        """
        Input:
            events: List[Event]
        Output:
            X: numpy array of shape (n_events, n_features)
        """

        vectors = []

        for ev in events:
            # For now we only use ML scores
            v = [
                ev.attack_prob,
                ev.anomaly_score if ev.anomaly_score is not None else 0.0
            ]
            vectors.append(v)

        return np.array(vectors)
