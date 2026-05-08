from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class ThreatIntel:
    threat_type: str
    ttps: List[str]
    iocs: List[str]
    confidence: float
    threat_actor: Optional[str] = None
    recommendations: List[str] = field(default_factory=list)
    affected_platforms: List[str] = field(default_factory=list)
    severity: str = "medium"

    def to_dict(self) -> dict:
        return {
            "threat_type": self.threat_type,
            "ttps": self.ttps,
            "iocs": self.iocs,
            "confidence": self.confidence,
            "threat_actor": self.threat_actor,
            "recommendations": self.recommendations,
            "affected_platforms": self.affected_platforms,
            "severity": self.severity,
        }
