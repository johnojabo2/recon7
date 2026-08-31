import logging
from typing import Dict, List, Optional
from core.sensors.base import Sensor

logger = logging.getLogger(__name__)


class SensorRegistry:
    """Registry that catalogues and coordinates reconnaissance sensors."""

    def __init__(self):
        self._sensors: Dict[str, Sensor] = {}

    def register(self, sensor: Sensor) -> None:
        """Registers a sensor instance."""
        self._sensors[sensor.name] = sensor
        logger.debug(f"Registered sensor '{sensor.name}' v{sensor.version}")

    def get(self, name: str) -> Optional[Sensor]:
        """Retrieves a registered sensor by name."""
        return self._sensors.get(name)

    def list_all(self) -> List[Sensor]:
        """Returns a list of all registered sensors."""
        return list(self._sensors.values())

    def get_sensors_for_target(self, target_type: str) -> List[Sensor]:
        """
        Returns all sensors whose capabilities include the specified target_type
        (e.g., 'domain', 'ip', 'person', 'email', 'organization').
        """
        target_type = target_type.lower().strip()
        matched = []
        for s in self._sensors.values():
            if target_type in [c.lower() for c in s.capabilities] or "any" in s.capabilities:
                matched.append(s)
        return matched


# Global registry singleton
sensor_registry = SensorRegistry()
