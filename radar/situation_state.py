"""Singleton instance of SituationEngine to avoid circular imports."""
from radar.situation import SituationEngine

situation_engine = SituationEngine()
