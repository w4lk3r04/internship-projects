"""Domain models for report analysis."""

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class TechniqueMatch:
    """A technique recommendation backed by a report excerpt."""

    technique_id: str
    technique_name: str
    tactic: str
    confidence: float
    evidence: str
    source_line: int
    status: str = "needs_review"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class AttackEvent:
    """An ordered report event and its ATT&CK recommendations."""

    event_id: str
    order: int
    evidence: str
    techniques: tuple[TechniqueMatch, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "order": self.order,
            "evidence": self.evidence,
            "techniques": [technique.to_dict() for technique in self.techniques],
        }
