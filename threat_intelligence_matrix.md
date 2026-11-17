# VulnLab Threat Intelligence Matrix

Generated: 2026-11-17

## Analysis summary

- Catalog version: `mvp-2026-01`
- Events with recommendations: **62**
- Recommendations: **75**

## Threat intelligence matrix

| Event | Tactic | Technique ID | Technique | Confidence | Source line | Evidence |
|---|---|---|---|---:|---:|---|
| evt-001 | Lateral Movement | T1021.004 | Remote Services: SSH | 0.78 | L20 | \| Web server \| `192.168.250.5/30` \| Extranet \| HTTP and SSH services \| |
| evt-002 | Persistence | T1505.003 | Server Software Component: Web Shell | 0.96 | L34 | ## Scenario 1 — Tomcat initial access and WebShell |
| evt-003 | Persistence | T1505.003 | Server Software Component: Web Shell | 0.96 | L39 | execute commands, and establish a WebShell for continued access. |
| evt-003 | Execution | T1059.004 | Unix Shell | 0.80 | L39 | execute commands, and establish a WebShell for continued access. |
| evt-004 | Discovery | T1046 | Network Service Scanning | 0.94 | L43 | 1. The attacker used Nmap to discover hosts and exposed services. |
| evt-005 | Discovery | T1046 | Network Service Scanning | 0.94 | L47 | 4. `spring4shell-scan.py` was used to check the Spring4Shell hypothesis. |
| evt-005 | Initial Access | T1190 | Exploit Public-Facing Application | 0.91 | L47 | 4. `spring4shell-scan.py` was used to check the Spring4Shell hypothesis. |
| evt-006 | Initial Access | T1190 | Exploit Public-Facing Application | 0.91 | L48 | 5. `spring4shell-exploit` sent a malicious request that modified the |
| evt-007 | Persistence | T1505.003 | Server Software Component: Web Shell | 0.96 | L49 | `ClassLoader` chain and uploaded a JSP WebShell. |
| evt-008 | Initial Access | T1190 | Exploit Public-Facing Application | 0.91 | L50 | 6. The exploit returned root access on the Tomcat host. |
| evt-009 | Persistence | T1505.003 | Server Software Component: Web Shell | 0.96 | L51 | 7. The WebShell was used to execute Unix commands and inspect `/root` and |
| evt-010 | Execution | T1059.004 | Unix Shell | 0.80 | L56 | credential `Sh@ring4n`. |
| evt-011 | Discovery | T1046 | Network Service Scanning | 0.94 | L61 | Nmap identified the Tomcat host at 192.168.250.2 and port 8080. |
| evt-012 | Discovery | T1046 | Network Service Scanning | 0.94 | L63 | spring4shell-scan.py confirmed the Spring4Shell hypothesis. |
| evt-012 | Initial Access | T1190 | Exploit Public-Facing Application | 0.91 | L63 | spring4shell-scan.py confirmed the Spring4Shell hypothesis. |
| evt-013 | Initial Access | T1190 | Exploit Public-Facing Application | 0.91 | L64 | spring4shell-exploit uploaded a JSP WebShell through the ClassLoader chain. |
| evt-013 | Persistence | T1505.003 | Server Software Component: Web Shell | 0.96 | L64 | spring4shell-exploit uploaded a JSP WebShell through the ClassLoader chain. |
| evt-014 | Initial Access | T1190 | Exploit Public-Facing Application | 0.91 | L65 | The exploit returned root access on the Tomcat server. |
| evt-015 | Persistence | T1505.003 | Server Software Component: Web Shell | 0.96 | L66 | The WebShell executed Unix commands to list /root and /home. |
| evt-016 | Execution | T1059.004 | Unix Shell | 0.80 | L68 | The decoded .user.txt value was Sh@ring4n. |
| evt-017 | Discovery | T1046 | Network Service Scanning | 0.94 | L75 | \| Discovery \| T1046 — Network Service Scanning \| Observed \| Nmap host and port discovery \| |
| evt-018 | Initial Access | T1190 | Exploit Public-Facing Application | 0.91 | L76 | \| Initial Access \| T1190 — Exploit Public-Facing Application \| Observed \| Spring4Shell exploitation \| |
| evt-019 | Persistence | T1505.003 | Server Software Component: Web Shell | 0.96 | L77 | \| Persistence \| T1505.003 — Web Shell \| Observed \| JSP WebShell upload \| |
| evt-020 | Persistence | T1505.003 | Server Software Component: Web Shell | 0.96 | L78 | \| Execution \| T1059.004 — Unix Shell \| Observed \| Unix commands through the WebShell \| |
| evt-020 | Execution | T1059.004 | Unix Shell | 0.80 | L78 | \| Execution \| T1059.004 — Unix Shell \| Observed \| Unix commands through the WebShell \| |
| evt-021 | Discovery | T1046 | Network Service Scanning | 0.94 | L99 | 1. Nmap identified HTTP on port 80 and SSH on port 22 at |
| evt-021 | Lateral Movement | T1021.004 | Remote Services: SSH | 0.78 | L99 | 1. Nmap identified HTTP on port 80 and SSH on port 22 at |
| evt-022 | Credential Access | T1110 | Brute Force | 0.95 | L102 | 3. Hydra brute-forced SSH with the username `sasuk3`. |
| evt-022 | Lateral Movement | T1021.004 | Remote Services: SSH | 0.78 | L102 | 3. Hydra brute-forced SSH with the username `sasuk3`. |
| evt-023 | Lateral Movement | T1021.004 | Remote Services: SSH | 0.78 | L103 | 4. SSH access to the web server succeeded. |
| evt-024 | Credential Access | T1552.001 | Unsecured Credentials: Credentials In Files | 0.93 | L105 | `credentials.txt` in the `vulnic` directory. |
| evt-025 | Execution | T1059.004 | Unix Shell | 0.80 | L110 | 9. The attacker opened `root.zip` with the lab password `Sh@ring4n`. |
| evt-026 | Discovery | T1046 | Network Service Scanning | 0.94 | L117 | Nmap identified HTTP on port 80 and SSH on port 22 on 192.168.250.5. |
| evt-026 | Lateral Movement | T1021.004 | Remote Services: SSH | 0.78 | L117 | Nmap identified HTTP on port 80 and SSH on port 22 on 192.168.250.5. |
| evt-027 | Credential Access | T1110 | Brute Force | 0.95 | L118 | Hydra brute-forced the SSH login for the username sasuk3. |
| evt-027 | Lateral Movement | T1021.004 | Remote Services: SSH | 0.78 | L118 | Hydra brute-forced the SSH login for the username sasuk3. |
| evt-028 | Lateral Movement | T1021.004 | Remote Services: SSH | 0.78 | L119 | The attacker obtained SSH access to the web server. |
| evt-029 | Credential Access | T1552.001 | Unsecured Credentials: Credentials In Files | 0.93 | L120 | The attacker searched /var/www/html and found vulnic/credentials.txt. |
| evt-030 | Credential Access | T1552.001 | Unsecured Credentials: Credentials In Files | 0.93 | L121 | credentials.txt contained sasuk3 and adm1n:G0ld3n_he@rt. |
| evt-031 | Execution | T1059.004 | Unix Shell | 0.80 | L123 | The attacker obtained root access and opened root.zip with Sh@ring4n. |
| evt-032 | Discovery | T1046 | Network Service Scanning | 0.94 | L131 | \| Discovery \| T1046 — Network Service Scanning \| Observed \| Nmap scan of ports 22 and 80 \| |
| evt-033 | Credential Access | T1110 | Brute Force | 0.95 | L132 | \| Credential Access \| T1110 — Brute Force \| Observed \| Hydra SSH brute force \| |
| evt-033 | Lateral Movement | T1021.004 | Remote Services: SSH | 0.78 | L132 | \| Credential Access \| T1110 — Brute Force \| Observed \| Hydra SSH brute force \| |
| evt-034 | Lateral Movement | T1021.004 | Remote Services: SSH | 0.78 | L133 | \| Lateral Movement \| T1021.004 — SSH \| Observed \| Successful SSH access \| |
| evt-035 | Credential Access | T1552.001 | Unsecured Credentials: Credentials In Files | 0.93 | L134 | \| Credential Access \| T1552.001 — Credentials In Files \| Observed \| `credentials.txt` \| |
| evt-036 | Defense Evasion | T1078 | Valid Accounts | 0.86 | L135 | \| Defense Evasion \| T1078 — Valid Accounts \| Candidate \| Reuse of recovered account credentials \| |
| evt-037 | Credential Access | T1110 | Brute Force | 0.95 | L141 | - `T1110` must be supported by Hydra or explicit brute-force evidence. |
| evt-038 | Lateral Movement | T1021.004 | Remote Services: SSH | 0.78 | L142 | - SSH alone should map to `T1021.004`, not automatically to `T1078`. |
| evt-039 | Initial Access | T1190 | Exploit Public-Facing Application | 0.91 | L152 | binary source through anonymous FTP, and exploit the binary logic to disclose the |
| evt-040 | Discovery | T1046 | Network Service Scanning | 0.94 | L157 | 1. Nmap identified FTP, SNPP, and an exposed listener on port 444. |
| evt-041 | Discovery | T1046 | Network Service Scanning | 0.94 | L174 | Nmap identified FTP, SNPP, and a listener on port 444 on Linux1. |
| evt-042 | Discovery | T1046 | Network Service Scanning | 0.94 | L189 | \| Discovery \| T1046 — Network Service Scanning \| Observed \| Nmap service discovery \| |
| evt-043 | Initial Access | T1190 | Exploit Public-Facing Application | 0.91 | L190 | \| Initial Access \| T1190 — Exploit Public-Facing Application \| Candidate \| Anonymous FTP exposure, depending on interpretation \| |
| evt-044 | Execution | T1059.004 | Unix Shell | 0.80 | L191 | \| Execution \| T1059.004 — Unix Shell \| Candidate \| Commands executed from the restricted shell \| |
| evt-045 | Defense Evasion | T1078 | Valid Accounts | 0.86 | L198 | - The mapper should not map every use of “FTP” to SSH or valid accounts. |
| evt-045 | Lateral Movement | T1021.004 | Remote Services: SSH | 0.78 | L198 | - The mapper should not map every use of “FTP” to SSH or valid accounts. |
| evt-046 | Initial Access | T1190 | Exploit Public-Facing Application | 0.91 | L202 | - The report should expose the gap between the observed binary exploit and the |
| evt-047 | Discovery | T1046 | Network Service Scanning | 0.94 | L209 | - Detect Nmap as T1046. |
| evt-048 | Initial Access | T1190 | Exploit Public-Facing Application | 0.91 | L210 | - Detect Spring4Shell exploitation as T1190. |
| evt-049 | Persistence | T1505.003 | Server Software Component: Web Shell | 0.96 | L211 | - Detect JSP WebShell as T1505.003. |
| evt-050 | Credential Access | T1110 | Brute Force | 0.95 | L212 | - Detect Hydra brute force as T1110. |
| evt-051 | Lateral Movement | T1021.004 | Remote Services: SSH | 0.78 | L213 | - Detect SSH lateral movement as T1021.004. |
| evt-052 | Credential Access | T1552.001 | Unsecured Credentials: Credentials In Files | 0.93 | L214 | - Detect `credentials.txt` as T1552.001. |
| evt-053 | Execution | T1059.004 | Unix Shell | 0.80 | L216 | or remote command. |
| evt-054 | Defense Evasion | T1078 | Valid Accounts | 0.86 | L221 | - Do not infer valid accounts from an SSH connection alone. |
| evt-054 | Lateral Movement | T1021.004 | Remote Services: SSH | 0.78 | L221 | - Do not infer valid accounts from an SSH connection alone. |
| evt-055 | Persistence | T1505.003 | Server Software Component: Web Shell | 0.96 | L260 | - Remove JSP WebShells and verify the integrity of Tomcat `webapps` directories. |
| evt-056 | Lateral Movement | T1021.004 | Remote Services: SSH | 0.78 | L262 | - Restrict SSH to an administration network, disable password authentication, |
| evt-057 | Credential Access | T1552.001 | Unsecured Credentials: Credentials In Files | 0.93 | L265 | `credentials.txt`, ZIP archives, or shell history. Store secrets in a |
| evt-058 | Discovery | T1083 | File and Directory Discovery | 0.83 | L274 | review all privileged commands with `sudo -l`. |
| evt-059 | Lateral Movement | T1021.004 | Remote Services: SSH | 0.78 | L285 | - Centralize and protect SSH, HTTP, Tomcat, FTP, authentication, sudo, and |
| evt-060 | Discovery | T1046 | Network Service Scanning | 0.94 | L287 | - Alert on Nmap-like scans, Gobuster-like directory enumeration, repeated SSH |
| evt-060 | Lateral Movement | T1021.004 | Remote Services: SSH | 0.78 | L287 | - Alert on Nmap-like scans, Gobuster-like directory enumeration, repeated SSH |
| evt-061 | Persistence | T1505.003 | Server Software Component: Web Shell | 0.96 | L292 | - Use file integrity monitoring for WebShell indicators and credential stores. |
| evt-062 | Persistence | T1505.003 | Server Software Component: Web Shell | 0.96 | L296 | WebShell eradication, and host rebuild procedures. |

## Tactic summary

| Tactic | Recommendations |
|---|---:|
| Credential Access | 11 |
| Defense Evasion | 3 |
| Discovery | 14 |
| Execution | 8 |
| Initial Access | 11 |
| Lateral Movement | 16 |
| Persistence | 12 |

## Technique summary

| Technique ID | Recommendations |
|---|---:|
| T1021.004 | 16 |
| T1046 | 13 |
| T1059.004 | 8 |
| T1078 | 3 |
| T1083 | 1 |
| T1110 | 5 |
| T1190 | 11 |
| T1505.003 | 12 |
| T1552.001 | 6 |

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
