class UncertaintyReasoningAgent:
    """
    Agent 2: Uncertainty Reasoning Agent

    Purpose:
    - Reason about the confidence of ML predictions
    - Categorize predictions into LOW / MEDIUM / HIGH uncertainty
    - Align decisions with SOC alert triaging norms
    """

    def __init__(self,
                 low_confidence_threshold=0.65,
                 high_confidence_threshold=0.85):
        """
        Thresholds are SOC-aligned:
        - >= 0.85  → LOW uncertainty (high confidence)
        - 0.65–0.85 → MEDIUM uncertainty
        - < 0.65   → HIGH uncertainty
        """
        self.low_confidence_threshold = low_confidence_threshold
        self.high_confidence_threshold = high_confidence_threshold

    def assess(self, attack_probability):
        """
        Input:
        - attack_probability (float): P(attack) from binary IDS

        Output:
        - dict with uncertainty level and reasoning
        """

        if attack_probability >= self.high_confidence_threshold:
            return {
                "uncertainty": "LOW",
                "reason": (
                    f"High confidence attack probability "
                    f"({attack_probability:.2f})"
                )
            }

        if attack_probability >= self.low_confidence_threshold:
            return {
                "uncertainty": "MEDIUM",
                "reason": (
                    f"Moderate confidence attack probability "
                    f"({attack_probability:.2f})"
                )
            }

        return {
            "uncertainty": "HIGH",
            "reason": (
                f"Low confidence attack probability "
                f"({attack_probability:.2f})"
            )
        }
