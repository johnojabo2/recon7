import abc
import logging
from typing import Dict, Any, List, Optional
from core.sensors.observation import Observation

logger = logging.getLogger(__name__)


class Sensor(abc.ABC):
    """
    Abstract contract for all reconnaissance sensors per Spec Section 28.
    Sensors are isolated observers that probe public assets, collect telemetry,
    and normalize observations into structured facts without writing unvalidated claims.
    """

    @property
    @abc.abstractmethod
    def name(self) -> str:
        """Unique identifier of the sensor (e.g., 'whois_sensor', 'dns_subdomain_sensor')."""
        pass

    @property
    @abc.abstractmethod
    def version(self) -> str:
        """Version string of the sensor implementation."""
        pass

    @property
    def capabilities(self) -> List[str]:
        """List of target types and features supported by this sensor."""
        return ["domain"]

    @property
    def authorization_requirements(self) -> str:
        """Authorization requirement: 'passive' (safe) or 'active' (requires explicit scope)."""
        return "passive"

    @abc.abstractmethod
    def execute(self, target: str, context: Dict[str, Any], scan_profile: str = "standard") -> Dict[str, Any]:
        """
        Executes the sensor collection logic.
        Must handle exceptions gracefully and return a dictionary of raw results.
        """
        pass

    @abc.abstractmethod
    def normalize(self, target: str, raw_results: Dict[str, Any], context: Dict[str, Any]) -> Observation:
        """
        Transforms raw sensor outputs into a standardized Observation packet
        containing candidate entities, relationships, findings, and evidence claims.
        """
        pass

    def health_check(self) -> bool:
        """Returns True if the sensor dependencies/binaries are ready for execution."""
        return True
