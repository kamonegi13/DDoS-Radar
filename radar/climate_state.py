"""radar.climate_state -- Singleton Strategic Climate Engine instance.

Separated from radar.climate to avoid circular imports.
The engine is updated from the main scoring loop in routes/core.py.
"""
from radar.climate import StrategicClimateEngine

climate_engine = StrategicClimateEngine()
