import json
import subprocess
import sys

from attack_mapper import AttackMapper
from attack_mapper.markdown import render_markdown


def test_maps_lab_attack_steps_with_source_evidence() -> None:
    report = """\
Nmap identified ports 22 and 80 on webserver.
The attacker exploited Spring4Shell and obtained root access.
A JSP webshell was uploaded.
Hydra brute-forced SSH using stolen credentials.
The attacker read credentials.txt with cat.
"""

    result = AttackMapper().analyze(report)

    assert result["event_count"] == 5
    techniques = [
        technique["technique_id"]
        for event in result["events"]
        for technique in event["techniques"]
    ]
    assert techniques == [
        "T1046",
        "T1190",
        "T1505.003",
        "T1110",
        "T1078",
        "T1021.004",
        "T1552.001",
        "T1083",
    ]
    assert result["events"][1]["techniques"][0]["source_line"] == 2


def test_cli_returns_json(tmp_path) -> None:
    report = tmp_path / "report.txt"
    report.write_text("Nmap scanned the target.\n", encoding="utf-8")

    completed = subprocess.run(
        [sys.executable, "-m", "attack_mapper.cli", str(report)],
        check=True,
        capture_output=True,
        text=True,
    )

    result = json.loads(completed.stdout)
    assert result["events"][0]["techniques"][0]["technique_id"] == "T1046"


def test_renders_threat_intelligence_matrix_as_markdown() -> None:
    result = AttackMapper().analyze("Nmap scanned the target.\n")

    markdown = render_markdown(result, title="Test matrix")

    assert "# Test matrix" in markdown
    assert "| T1046 | Network Service Scanning |" in markdown
    assert "| Discovery | 1 |" in markdown
    assert "## Threat intelligence workflow" in markdown
    assert "## Security recommendations" in markdown
