"""Rule-based, evidence-preserving ATT&CK mapper."""

import re
from pathlib import Path

from .catalog import CATALOG_VERSION, TECHNIQUES, Technique
from .models import AttackEvent, TechniqueMatch


Rule = tuple[re.Pattern[str], str, float]


RULES: tuple[Rule, ...] = (
    (re.compile(r"\b(?:nmap|masscan)\b|\bport scan\b|\bscan(?:ned|ning)?\b", re.I), "T1046", 0.94),
    (re.compile(r"\b(?:spring4shell|log4shell|exploit(?:ed|ing)?)\b", re.I), "T1190", 0.91),
    (re.compile(r"\b(?:webshell|web shell|\.jsp\b)", re.I), "T1505.003", 0.96),
    (re.compile(r"\b(?:hydra|brute[- ]force|password spraying)\b", re.I), "T1110", 0.95),
    (re.compile(r"\b(?:valid accounts?|stolen credentials?|reused credentials?)\b", re.I), "T1078", 0.86),
    (re.compile(r"\b(?:ssh|remote login)\b", re.I), "T1021.004", 0.78),
    (re.compile(r"\b(?:credentials?\.txt|passwords?\.txt|secrets?\.txt)\b", re.I), "T1552.001", 0.93),
    (re.compile(r"\b(?:ls|find|cat|ps aux|sudo -l)\b|\bfile(?:s| and directory) enumeration\b", re.I), "T1083", 0.83),
    (re.compile(r"\b(?:bash|sh|unix shell|remote command(?:s)?|execute command(?:s)?)\b", re.I), "T1059.004", 0.80),
)


class AttackMapper:
    """Map report lines to ATT&CK techniques while retaining source evidence."""

    def __init__(self, catalog: dict[str, Technique] | None = None) -> None:
        self.catalog = catalog or TECHNIQUES

    def analyze(self, report: str) -> dict[str, object]:
        """Return a JSON-serializable analysis of a plain-text report."""
        events: list[AttackEvent] = []
        order = 0
        for line_number, raw_line in enumerate(report.splitlines(), start=1):
            evidence = raw_line.strip()
            if not evidence:
                continue
            matches = self._map_line(evidence, line_number)
            if not matches:
                continue
            order += 1
            events.append(
                AttackEvent(
                    event_id=f"evt-{order:03d}",
                    order=order,
                    evidence=evidence,
                    techniques=tuple(matches),
                )
            )

        return {
            "catalog_version": CATALOG_VERSION,
            "event_count": len(events),
            "events": [event.to_dict() for event in events],
        }

    def analyze_file(self, path: str | Path) -> dict[str, object]:
        """Analyze a UTF-8 text or Markdown report."""
        report_path = Path(path)
        return self.analyze(report_path.read_text(encoding="utf-8"))

    def _map_line(self, evidence: str, line_number: int) -> list[TechniqueMatch]:
        matches: list[TechniqueMatch] = []
        seen: set[str] = set()
        for pattern, technique_id, confidence in RULES:
            if technique_id in seen or not pattern.search(evidence):
                continue
            technique = self.catalog.get(technique_id)
            if technique is None:
                continue
            seen.add(technique_id)
            matches.append(
                TechniqueMatch(
                    technique_id=technique.technique_id,
                    technique_name=technique.name,
                    tactic=technique.tactic,
                    confidence=confidence,
                    evidence=evidence,
                    source_line=line_number,
                )
            )
        return matches
