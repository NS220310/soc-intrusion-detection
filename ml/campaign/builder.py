from ml.campaign.models import Campaign, CampaignSummary
from ml.campaign.vectorizer import EventVectorizer

class CampaignBuilder:
    def __init__(self):
        self.vectorizer = EventVectorizer()

    def build_campaigns(self, events):
        """
        Input:
            events: List[Event]
        Output:
            campaigns: List[Campaign]
        """

        # Step 1: Convert events to vectors (for future clustering)
        X = self.vectorizer.vectorize(events)

        # TODO: Replace this with real clustering later
        # For now, put everything into ONE dummy campaign
        campaign = Campaign(campaign_id=0, events=events)

        return [campaign]

    def summarize(self, campaign):
        """
        Input:
            campaign: Campaign
        Output:
            CampaignSummary
        """

        summary = CampaignSummary(campaign.campaign_id)

        events = campaign.events
        n = len(events)

        if n == 0:
            return summary

        summary.size = n
        summary.avg_attack_prob = sum(e.attack_prob for e in events) / n

        valid_anoms = [e.anomaly_score for e in events if e.anomaly_score is not None]
        if len(valid_anoms) > 0:
            summary.avg_anomaly_score = sum(valid_anoms) / len(valid_anoms)

        types = [e.attack_type for e in events]
        summary.dominant_attack_type = max(set(types), key=types.count)

        return summary
