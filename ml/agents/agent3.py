from collections import defaultdict
import hashlib

class Agent3CorrelationEngine:
    """
    Agent 3: Correlates flow-level attack detections into campaign-level incidents
    Adds:
    - Severity scoring
    - Incident deduplication
    """

    def __init__(self, time_window=600):
        self.time_window = time_window  # seconds

        # Thresholds (tune if needed)
        self.DOS_EVENT_THRESHOLD = 100
        self.RECON_EVENT_THRESHOLD = 20
        self.UNIQUE_TARGET_THRESHOLD_SCAN = 10
        self.MULTI_STAGE_MIN_TYPES = 3
        self.MULTI_STAGE_MIN_EVENTS = 30
        self.SUSTAINED_EVENT_THRESHOLD = 50
        self.MULTI_TARGET_THRESHOLD = 20
        self.MULTI_TARGET_EVENT_THRESHOLD = 40

        # For deduplication
        self.seen_incidents = set()

    # ===============================
    # Main entry
    # ===============================
    def correlate(self, events):
        """
        Input:
            events: list of flow-level dicts from your pipeline
        Output:
            incidents: list of unique campaign-level incident dicts
        """

        # 1. Keep only confident attacks
        filtered = [
            e for e in events
            if e.get("is_attack") and e.get("uncertainty") in ["LOW", "MEDIUM"]
        ]

        if not filtered:
            return []

        # 2. Sort by time
        filtered.sort(key=lambda x: x["stime"])

        # 3. Group by source IP
        by_src = defaultdict(list)
        for e in filtered:
            by_src[e["srcip"]].append(e)

        incidents = []

        # 4. Sliding window per source IP
        for srcip, evs in by_src.items():
            n = len(evs)
            i = 0
            while i < n:
                window = [evs[i]]
                j = i + 1

                while j < n and (evs[j]["stime"] - evs[i]["stime"] <= self.time_window):
                    window.append(evs[j])
                    j += 1

                # 5. Analyze this window
                incident = self._analyze_window(srcip, window)
                if incident:
                    # 6. Deduplication
                    if not self._is_duplicate(incident):
                        incidents.append(incident)

                i += 1

        return incidents

    # ===============================
    # Core analysis
    # ===============================
    def _analyze_window(self, srcip, events):
        total_events = len(events)
        attack_types = [e["attack_type"] for e in events]
        unique_targets = len(set(e["dstip"] for e in events))
        unique_types = set(attack_types)

        # ================================
        # Rule 1: Multi-Stage Attack
        # ================================
        if (len(unique_types) >= self.MULTI_STAGE_MIN_TYPES and
            total_events >= self.MULTI_STAGE_MIN_EVENTS):

            base = {
                "type": "Multi-Stage Attack Campaign",
                "srcip": srcip,
                "severity": "HIGH",
                "events": total_events,
                "attack_types": list(unique_types),
                "unique_targets": unique_targets
            }
            base["risk_score"] = self._score(base)
            return base

        # ================================
        # Rule 2: DoS / Flood
        # ================================
        dos_like = sum(1 for x in attack_types if x in ["DoS", "Generic"])
        if dos_like >= self.DOS_EVENT_THRESHOLD:
            base = {
                "type": "DoS / Flood Campaign",
                "srcip": srcip,
                "severity": "HIGH",
                "events": total_events,
                "unique_targets": unique_targets
            }
            base["risk_score"] = self._score(base)
            return base

        # ================================
        # Rule 3: Scanning / Recon
        # ================================
        recon_count = sum(1 for x in attack_types if x == "Reconnaissance")
        if (recon_count >= self.RECON_EVENT_THRESHOLD and
            unique_targets >= self.UNIQUE_TARGET_THRESHOLD_SCAN):

            base = {
                "type": "Scanning / Recon Campaign",
                "srcip": srcip,
                "severity": "MEDIUM",
                "events": total_events,
                "unique_targets": unique_targets
            }
            base["risk_score"] = self._score(base)
            return base

        # ================================
        # Rule 4: Multi-Target Attack
        # ================================
        if (unique_targets >= self.MULTI_TARGET_THRESHOLD and
            total_events >= self.MULTI_TARGET_EVENT_THRESHOLD):

            base = {
                "type": "Multi-Target Attack Campaign",
                "srcip": srcip,
                "severity": "MEDIUM",
                "events": total_events,
                "unique_targets": unique_targets
            }
            base["risk_score"] = self._score(base)
            return base

        # ================================
        # Rule 5: Sustained Attack
        # ================================
        if total_events >= self.SUSTAINED_EVENT_THRESHOLD:
            base = {
                "type": "Sustained Attack Campaign",
                "srcip": srcip,
                "severity": "MEDIUM",
                "events": total_events,
                "unique_targets": unique_targets
            }
            base["risk_score"] = self._score(base)
            return base

        return None

    # ===============================
    # Risk scoring (SOC-style)
    # ===============================
    def _score(self, incident):
        """
        Returns a numeric risk score (0–100)
        """

        score = 0

        # Severity weight
        if incident["severity"] == "HIGH":
            score += 50
        else:
            score += 30

        # Volume weight
        score += min(30, incident["events"] // 10)

        # Spread weight
        score += min(20, incident.get("unique_targets", 1) * 2)

        return min(100, score)

    # ===============================
    # Deduplication
    # ===============================
    def _is_duplicate(self, incident):
        """
        Uses hash of (type, srcip, severity) to avoid duplicates
        """

        key = f"{incident['type']}|{incident['srcip']}|{incident['severity']}"
        h = hashlib.md5(key.encode()).hexdigest()

        if h in self.seen_incidents:
            return True

        self.seen_incidents.add(h)
        return False
