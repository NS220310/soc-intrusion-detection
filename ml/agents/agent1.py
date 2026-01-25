class InputValidationAgent:
    """
    Agent 1: Input Validation / Gatekeeper Agent

    Purpose:
    - Decide whether a structured network-flow input is reliable
      enough to invoke preprocessing and ML inference.
    """

    # Minimal critical features required for reasoning
    REQUIRED_COLUMNS = [
        "proto", "service", "state",
        "dur", "sbytes", "dbytes"
    ]

    def validate(self, df):
        """
        Input: raw structured network flow(s) as pandas DataFrame
        Output: decision dict with status and reasoning
        """

        reasons = []

        # -------------------------------
        # 1. Schema reasoning
        # -------------------------------
        missing_cols = [
            col for col in self.REQUIRED_COLUMNS
            if col not in df.columns
        ]
        if missing_cols:
            reasons.append(
                f"Missing critical columns: {missing_cols}"
            )

        # -------------------------------
        # 2. Semantic sanity checks
        # -------------------------------
        if "dur" in df.columns and (df["dur"] < 0).any():
            reasons.append("Negative flow duration detected")

        if "sbytes" in df.columns and (df["sbytes"] < 0).any():
            reasons.append("Negative source byte count detected")

        if "dbytes" in df.columns and (df["dbytes"] < 0).any():
            reasons.append("Negative destination byte count detected")

        # -------------------------------
        # 3. Completeness / confidence check
        # -------------------------------
        missing_ratio = df.isnull().mean().mean()
        if missing_ratio > 0.30:
            reasons.append(
                f"High missing value ratio: {missing_ratio:.2f}"
            )

        # -------------------------------
        # Decision policy
        # -------------------------------
        if reasons:
            return {
                "status": "REJECT",
                "reasons": reasons
            }

        return {
            "status": "ACCEPT",
            "reasons": []
        }
