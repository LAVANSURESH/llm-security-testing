from dataclasses import dataclass, field
from typing import List, Optional
import uuid
from datetime import datetime

from .alert import Alert


@dataclass
class Incident:
    alerts: List[Alert]
    priority: str
    status: str
    classification: str
    id: str = field(default_factory=lambda: f"INC-{str(uuid.uuid4())[:6].upper()}")
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    ttps: List[str] = field(default_factory=list)
    iocs: List[str] = field(default_factory=list)
    affected_assets: List[str] = field(default_factory=list)
    timeline: List[dict] = field(default_factory=list)
    playbook: Optional[str] = None
    risk_score: float = 0.0
    analyst_notes: List[str] = field(default_factory=list)
    triage_summary: Optional[str] = None
    threat_intel_summary: Optional[str] = None
    log_analysis_summary: Optional[str] = None
    response_summary: Optional[str] = None
    final_report: Optional[str] = None
    executive_summary: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "created_at": self.created_at,
            "alerts": [a.to_dict() for a in self.alerts],
            "priority": self.priority,
            "status": self.status,
            "classification": self.classification,
            "ttps": self.ttps,
            "iocs": self.iocs,
            "affected_assets": self.affected_assets,
            "timeline": self.timeline,
            "risk_score": self.risk_score,
            "analyst_notes": self.analyst_notes,
            "triage_summary": self.triage_summary,
            "threat_intel_summary": self.threat_intel_summary,
            "log_analysis_summary": self.log_analysis_summary,
            "response_summary": self.response_summary,
        }
