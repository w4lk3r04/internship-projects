"""Small, versioned ATT&CK catalog used by the MVP.

The catalog is intentionally limited to techniques exercised by the lab. It can
later be replaced by an importer for the official MITRE STIX distribution.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class Technique:
    technique_id: str
    name: str
    tactic: str


CATALOG_VERSION = "mvp-2026-01"

TECHNIQUES: dict[str, Technique] = {
    "T1046": Technique("T1046", "Network Service Scanning", "Discovery"),
    "T1083": Technique("T1083", "File and Directory Discovery", "Discovery"),
    "T1059.004": Technique("T1059.004", "Unix Shell", "Execution"),
    "T1078": Technique("T1078", "Valid Accounts", "Defense Evasion"),
    "T1110": Technique("T1110", "Brute Force", "Credential Access"),
    "T1190": Technique(
        "T1190", "Exploit Public-Facing Application", "Initial Access"
    ),
    "T1505.003": Technique(
        "T1505.003", "Server Software Component: Web Shell", "Persistence"
    ),
    "T1552.001": Technique(
        "T1552.001", "Unsecured Credentials: Credentials In Files", "Credential Access"
    ),
    "T1021.004": Technique("T1021.004", "Remote Services: SSH", "Lateral Movement"),
}
