"""Markdown rendering for ATT&CK analysis results."""

from collections import Counter
from datetime import date
from typing import Any


def render_markdown(
    result: dict[str, object],
    *,
    title: str = "MITRE ATT&CK Threat Intelligence Matrix",
) -> str:
    """Render an analysis result as an analyst-readable Markdown report."""
    events = result.get("events", [])
    rows: list[str] = []
    tactic_counts: Counter[str] = Counter()
    technique_counts: Counter[str] = Counter()

    for event in events:  # type: ignore[union-attr]
        for technique in event["techniques"]:
            tactic_counts[technique["tactic"]] += 1
            technique_counts[technique["technique_id"]] += 1
            rows.append(
                "| {event} | {tactic} | {technique_id} | {name} | "
                "{confidence:.2f} | L{line} | {evidence} |".format(
                    event=event["event_id"],
                    tactic=technique["tactic"],
                    technique_id=technique["technique_id"],
                    name=technique["technique_name"],
                    confidence=technique["confidence"],
                    line=technique["source_line"],
                    evidence=_escape_cell(technique["evidence"]),
                )
            )

    tactic_summary = "\n".join(
        f"| {tactic} | {count} |" for tactic, count in sorted(tactic_counts.items())
    ) or "| None | 0 |"
    technique_summary = "\n".join(
        f"| {technique_id} | {count} |"
        for technique_id, count in sorted(technique_counts.items())
    ) or "| None | 0 |"

    return f"""# {title}

Generated: {date.today().isoformat()}

## Analysis summary

- Catalog version: `{result.get("catalog_version", "unknown")}`
- Events with recommendations: **{result.get("event_count", 0)}**
- Recommendations: **{sum(technique_counts.values())}**

## Threat intelligence matrix

| Event | Tactic | Technique ID | Technique | Confidence | Source line | Evidence |
|---|---|---|---|---:|---:|---|
{chr(10).join(rows) or "| None | | | | | | No technique recommendation |"}

## Tactic summary

| Tactic | Recommendations |
|---|---:|
{tactic_summary}

## Technique summary

| Technique ID | Recommendations |
|---|---:|
{technique_summary}

## Threat intelligence workflow

1. **Collect and preserve** the original report, logs, commands, screenshots,
   host inventory, and timestamps.
2. **Normalize** hosts, users, tools, services, vulnerabilities, commands,
   files, credentials, and outcomes into common event fields.
3. **Build the timeline** from timestamps, or preserve report order and mark
   inferred ordering.
4. **Map to ATT&CK** using the versioned catalog and retain a citation for
   every recommendation.
5. **Validate evidence** by separating observed, inferred, possible, and
   unsupported activity.
6. **Correlate and prioritize** attack paths by privilege gained, lateral
   movement, credential exposure, exploitability, and business impact.
7. **Disseminate** the matrix, indicators, detections, and remediation owners.
8. **Improve the knowledge base** with analyst accept/reject decisions and
   versioned mapping rules.

## Security recommendations

- Patch public-facing frameworks and remove unsupported Tomcat versions.
- Put public applications behind a WAF and restrict management endpoints.
- Remove WebShells and monitor Tomcat `webapps` and web-root integrity.
- Disable anonymous FTP and restrict SSH to an administration network.
- Require unique accounts, key-based SSH authentication, MFA, and least
  privilege; remove unrestricted `sudo -i` access.
- Rotate credentials exposed in reports, files, archives, or shell history and
  store secrets in a dedicated secrets manager.
- Run application services as non-root users and prevent web processes from
  writing executable files.
- Replace restricted-shell assumptions with proper isolation and authorization.
- Compile native programs with memory-safety protections and fix unsafe input
  handling.
- Centralize and protect SSH, HTTP, Tomcat, FTP, authentication, sudo, process,
  and file-integrity logs.
- Alert on scanning, directory enumeration, repeated SSH failures, JSP creation,
  anonymous FTP, and commands executed by web processes.
- Segment DMZ, extranet, and internal networks with explicit allow-lists.
- Maintain offline backups and rehearse containment, credential rotation,
  WebShell eradication, and host rebuild procedures.

## Analyst review

Recommendations are evidence-backed suggestions and require analyst validation.
Confirm that the cited evidence describes an observed action rather than a
hypothesis, capability, or planned activity before accepting a technique.
"""


def _escape_cell(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")
