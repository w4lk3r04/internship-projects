# Red Team Test Reports

## Purpose

This document contains three controlled Red Team scenarios extracted from
`mitre_attack_scenario.pdf`. It is a test corpus for the VulnLab ATT&CK Mapper.
The scenarios describe activity performed inside the Kathara lab only.

The mapper must preserve the evidence line for each recommendation. A technique
must not be marked as confirmed when this report only describes a hypothesis,
an intended action, or a capability that was not exercised.

## Scope and lab topology

### In-scope assets

| Asset | Address | Zone | Role |
|---|---:|---|---|
| Tomcat | `192.168.250.2/30` | DMZ | Apache Tomcat and Spring application |
| Web server | `192.168.250.5/30` | Extranet | HTTP and SSH services |
| Linux1 | `192.168.2.1/24` | Internal network | FTP service and restricted shell |
| PC2 | `192.168.2.2/24` | Internal network | Client |
| Attacker | `192.168.2.3` | Internal test position | Kali-based test node |

### Rules of engagement

- Testing is limited to the Kathara infrastructure listed above.
- No external systems or public credentials are in scope.
- The report describes a laboratory challenge; it is not evidence of a
  production incident.
- Credentials and flags below are intentionally included as synthetic lab
  fixtures for parser and correlation testing.

## Scenario 1 — Tomcat initial access and WebShell

### Objective

Obtain initial access to the Tomcat host through the exposed Spring application,
execute commands, and establish a WebShell for continued access.

### Attack narrative

1. The attacker used Nmap to discover hosts and exposed services.
2. The Tomcat service was identified at `192.168.250.2:8080`.
3. Gobuster identified the application path
   `http://192.168.250.2:8080/imageApp/greeting`.
4. `spring4shell-scan.py` was used to check the Spring4Shell hypothesis.
5. `spring4shell-exploit` sent a malicious request that modified the
   `ClassLoader` chain and uploaded a JSP WebShell.
6. The exploit returned root access on the Tomcat host.
7. The WebShell was used to execute Unix commands and inspect `/root` and
   `/home`.
8. The attacker recovered `root.txt`, `flag.txt`, and the hidden file
   `.user.txt`.
9. The content of `.user.txt` was decoded and produced the synthetic lab
   credential `Sh@ring4n`.

### Evidence

```text
Nmap identified the Tomcat host at 192.168.250.2 and port 8080.
Gobuster discovered http://192.168.250.2:8080/imageApp/greeting.
spring4shell-scan.py confirmed the Spring4Shell hypothesis.
spring4shell-exploit uploaded a JSP WebShell through the ClassLoader chain.
The exploit returned root access on the Tomcat server.
The WebShell executed Unix commands to list /root and /home.
The attacker read root.txt, flag.txt, and the hidden file .user.txt.
The decoded .user.txt value was Sh@ring4n.
```

### Expected ATT&CK mapping

| Tactic | Technique | Expected status | Evidence |
|---|---|---|---|
| Discovery | T1046 — Network Service Scanning | Observed | Nmap host and port discovery |
| Initial Access | T1190 — Exploit Public-Facing Application | Observed | Spring4Shell exploitation |
| Persistence | T1505.003 — Web Shell | Observed | JSP WebShell upload |
| Execution | T1059.004 — Unix Shell | Observed | Unix commands through the WebShell |
| Discovery | T1083 — File and Directory Discovery | Observed | Listing `/root` and `/home` |
| Credential Access | T1552.001 — Credentials In Files | Candidate | `.user.txt` contained a decoded credential |

### Test expectations

- The mapper should cite the exact evidence line for each technique.
- `T1190` should not be inferred solely from the word “Tomcat”.
- The decoded credential should be represented as evidence, not exposed as a
  recommendation for a technique without context.
- The scanner should preserve the sequence from reconnaissance to persistence.

## Scenario 2 — Web server compromise and privilege escalation

### Objective

Use information obtained during Scenario 1 to access the web server, obtain
root privileges, and identify a credential-harvesting page.

### Attack narrative

1. Nmap identified HTTP on port 80 and SSH on port 22 at
   `192.168.250.5`.
2. The attacker used information recovered from the Tomcat host and Linux1.
3. Hydra brute-forced SSH with the username `sasuk3`.
4. SSH access to the web server succeeded.
5. The attacker explored `/var/www/html` and discovered
   `credentials.txt` in the `vulnic` directory.
6. The file contained the synthetic lab values `sasuk3` and
   `adm1n:G0ld3n_he@rt`.
7. The attacker used the `sammy` account and executed `sudo -i`.
8. Root access was obtained.
9. The attacker opened `root.zip` with the lab password `Sh@ring4n`.
10. A fake login page and a PHP file that stored submitted credentials were
    discovered during post-exploitation.

### Evidence

```text
Nmap identified HTTP on port 80 and SSH on port 22 on 192.168.250.5.
Hydra brute-forced the SSH login for the username sasuk3.
The attacker obtained SSH access to the web server.
The attacker searched /var/www/html and found vulnic/credentials.txt.
credentials.txt contained sasuk3 and adm1n:G0ld3n_he@rt.
The attacker accessed the sammy account and ran sudo -i.
The attacker obtained root access and opened root.zip with Sh@ring4n.
Post-exploitation revealed a fake login page and a PHP credential collector.
```

### Expected ATT&CK mapping

| Tactic | Technique | Expected status | Evidence |
|---|---|---|---|
| Discovery | T1046 — Network Service Scanning | Observed | Nmap scan of ports 22 and 80 |
| Credential Access | T1110 — Brute Force | Observed | Hydra SSH brute force |
| Lateral Movement | T1021.004 — SSH | Observed | Successful SSH access |
| Credential Access | T1552.001 — Credentials In Files | Observed | `credentials.txt` |
| Defense Evasion | T1078 — Valid Accounts | Candidate | Reuse of recovered account credentials |
| Privilege Escalation | T1548 — Abuse Elevation Control Mechanism | Observed | `sudo -i` |
| Discovery | T1083 — File and Directory Discovery | Observed | Exploration of `/var/www/html` |

### Test expectations

- `T1110` must be supported by Hydra or explicit brute-force evidence.
- SSH alone should map to `T1021.004`, not automatically to `T1078`.
- `T1078` should remain a candidate unless valid credential reuse is explicit.
- Discovery of a credential collector is not proof that credentials were
  successfully captured.

## Scenario 3 — Linux1 restricted shell and binary exploitation

### Objective

Access Linux1, bypass the restricted shell limitations, retrieve the vulnerable
binary source through anonymous FTP, and exploit the binary logic to disclose the
lab flag.

### Attack narrative

1. Nmap identified FTP, SNPP, and an exposed listener on port 444.
2. The attacker connected to port 444 with netcat.
3. The connection provided a restricted `rbash` shell.
4. The attacker used the available commands and identified the `worth_it`
   program.
5. Anonymous FTP access was available without a password.
6. FTP directory listing exposed `worth` and `worth_it.c`.
7. The attacker downloaded both files with the FTP `get` command.
8. Source review showed unsafe memory handling and a buffer overflow.
9. The attacker supplied an oversized input to overwrite the program state.
10. The program's win condition disclosed `/home/local.txt`.
11. The decoded flag contained the synthetic lab values `sasuk3` and
    `adm1n:G0ld3n_he@rt`.

### Evidence

```text
Nmap identified FTP, SNPP, and a listener on port 444 on Linux1.
Netcat connected to port 444 and returned a restricted rbash shell.
Anonymous FTP access succeeded without a password.
FTP listing exposed worth and worth_it.c.
The attacker downloaded worth and worth_it.c with FTP get.
Source review identified unsafe memory handling and a buffer overflow.
An oversized input triggered the program win condition.
The win condition disclosed /home/local.txt.
The decoded flag contained sasuk3 and adm1n:G0ld3n_he@rt.
```

### Expected ATT&CK mapping

| Tactic | Technique | Expected status | Evidence |
|---|---|---|---|
| Discovery | T1046 — Network Service Scanning | Observed | Nmap service discovery |
| Initial Access | T1190 — Exploit Public-Facing Application | Candidate | Anonymous FTP exposure, depending on interpretation |
| Execution | T1059.004 — Unix Shell | Candidate | Commands executed from the restricted shell |
| Discovery | T1083 — File and Directory Discovery | Observed | FTP listing and file retrieval |
| Credential Access | T1552.001 — Credentials In Files | Candidate | Credentials recovered from the decoded flag |
| Execution | Buffer overflow | Unmapped in MVP | Binary input corruption is explicitly described |

### Test expectations

- The mapper should not map every use of “FTP” to SSH or valid accounts.
- “Buffer overflow” should remain visible as an unmapped observation in the
  current MVP unless a suitable ATT&CK technique is added.
- Anonymous access and credential reuse must be represented separately.
- The report should expose the gap between the observed binary exploit and the
  current limited ATT&CK catalog.

## Cross-scenario test cases

### Positive cases

- Detect Nmap as T1046.
- Detect Spring4Shell exploitation as T1190.
- Detect JSP WebShell as T1505.003.
- Detect Hydra brute force as T1110.
- Detect SSH lateral movement as T1021.004.
- Detect `credentials.txt` as T1552.001.
- Detect Unix command execution when the evidence explicitly mentions a shell
  or remote command.

### Negative and ambiguity cases

- Do not infer exploitation from a product name alone.
- Do not infer valid accounts from an SSH connection alone.
- Do not infer successful credential harvesting from discovering a PHP
  collector.
- Do not treat a capability, hypothesis, or planned action as an observed event.
- Preserve unmapped observations for analyst review.

## Threat intelligence workflow

The following workflow turns a Red Team report into an actionable threat
intelligence product:

1. **Collect and preserve**: ingest the report, commands, logs, screenshots,
   host inventory, and timestamps. Keep the original file immutable and record
   the source location of every observation.
2. **Normalize**: extract hosts, users, tools, services, vulnerabilities,
   commands, files, credentials, and outcomes into common event fields.
3. **Build the attack timeline**: order events by timestamp when available;
   otherwise preserve the report order and mark the ordering as inferred.
4. **Map to ATT&CK**: generate candidate tactics and techniques using
   deterministic rules and contextual analysis. Prefer sub-techniques when the
   evidence supports them.
5. **Validate evidence**: require a citation for every recommendation. An
   analyst must distinguish observed, strongly inferred, possible, and
   unsupported activity.
6. **Correlate and prioritize**: connect hosts, accounts, tools, and techniques
   into attack paths. Prioritize findings by exploitability, privilege gained,
   lateral movement potential, credential exposure, and business impact.
7. **Disseminate**: publish the ATT&CK matrix, attack timeline, indicators,
   detection ideas, and remediation owners in Markdown, JSON, or the incident
   management system.
8. **Improve the knowledge base**: record analyst accept/reject decisions,
   update detection rules, and version the ATT&CK catalog and mapping rules.

## Security recommendations

### Immediate controls

- Patch Spring Framework and remove unsupported Tomcat versions.
- Place public applications behind a WAF and restrict management endpoints.
- Remove JSP WebShells and verify the integrity of Tomcat `webapps` directories.
- Disable anonymous FTP and remove unnecessary FTP services.
- Restrict SSH to an administration network, disable password authentication,
  and require unique keys with MFA for privileged access.
- Rotate every credential exposed in `root.txt`, `.user.txt`,
  `credentials.txt`, ZIP archives, or shell history. Store secrets in a
  dedicated secrets manager.
- Remove shared accounts and enforce unique named accounts with least privilege.

### Host and application hardening

- Run application services as non-root users and prevent service accounts from
  writing executable files into web roots.
- Remove `sudo` rules that permit unrestricted shells such as `sudo -i` and
  review all privileged commands with `sudo -l`.
- Replace `rbash`-based restrictions with proper isolation and authorization;
  restricted shells are not a security boundary.
- Compile native programs with stack canaries, PIE, NX, fortified libc options,
  and address sanitizer during testing. Fix unsafe input handling instead of
  relying on the challenge's win condition.
- Remove hard-coded flags, passwords, and sensitive files from images and
  startup scripts.

### Detection and response

- Centralize and protect SSH, HTTP, Tomcat, FTP, authentication, sudo, and
  process execution logs.
- Alert on Nmap-like scans, Gobuster-like directory enumeration, repeated SSH
  failures, anonymous FTP access, JSP file creation, and commands executed by
  web processes.
- Monitor changes under `/var/www`, Tomcat `webapps`, `/etc/sudoers`, user
  home directories, and log files.
- Use file integrity monitoring for WebShell indicators and credential stores.
- Segment DMZ, extranet, and internal networks with explicit allow-lists; block
  direct administrative paths between zones.
- Maintain offline backups and rehearse containment, credential rotation,
  WebShell eradication, and host rebuild procedures.

### Validation plan

After implementing the controls, replay each scenario in an isolated copy of
the lab. Record which attack steps are blocked, which are detected, alert
latency, and whether the original evidence remains available for investigation.

## Suggested evaluation procedure

1. Submit this file to the local mapper interface.
2. Review the event count and every source-line citation.
3. Compare predicted technique IDs with the three expected mapping tables.
4. Record false positives, missed techniques, and ambiguous recommendations.
5. Use the analyst decisions as the first labelled evaluation set for future
   rule and model changes.
