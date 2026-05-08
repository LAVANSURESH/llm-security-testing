from dataclasses import dataclass, field
from typing import Optional
import uuid
from datetime import datetime


@dataclass
class Alert:
    source: str
    alert_type: str
    severity: str
    description: str
    raw_data: dict
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    user: Optional[str] = None
    hostname: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "source": self.source,
            "alert_type": self.alert_type,
            "severity": self.severity,
            "description": self.description,
            "source_ip": self.source_ip,
            "dest_ip": self.dest_ip,
            "user": self.user,
            "hostname": self.hostname,
            "raw_data": self.raw_data,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Alert":
        return cls(
            id=data.get("id", str(uuid.uuid4())[:8]),
            timestamp=data.get("timestamp", datetime.utcnow().isoformat()),
            source=data["source"],
            alert_type=data["alert_type"],
            severity=data["severity"],
            description=data["description"],
            raw_data=data.get("raw_data", {}),
            source_ip=data.get("source_ip"),
            dest_ip=data.get("dest_ip"),
            user=data.get("user"),
            hostname=data.get("hostname"),
        )
