# VulnLab: Vulnerable and Secured Infrastructure Lab

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![GitHub branch check](https://img.shields.io/github/actions/workflow/status/w4lk3r04/internship-projects/main.yml?branch=vuln_lab&label=build)](https://github.com/w4lk3r04/internship-projects/actions)

## 🎯 Project Overview

The **VulnLab** project aims to create a **lightweight, vulnerable yet isolated and secured infrastructure**, serving as a training platform for **security testing** (pentesting) practice and **cybersecurity education**.

Beyond the feasibility study for this design, the central objective is to perform a **thorough security audit** of the infrastructure itself. This process allows for the identification and analysis of the **methods, techniques, and tactics (TTPs)** commonly used in cyberattacks.

The analysis and documentation of the findings are based on the **MITRE ATT&CK® matrix**, which acts as a reference to structure threat identification and map attack scenarios.

## 🚀 Key Objectives

* **Design of a Lightweight and Realistic Infrastructure**: Utilizing containerization or virtualization technologies to simulate an enterprise environment with known vulnerabilities (e.g., outdated services, misconfigurations).
* **In-Depth Security Test**: Execution of a complete penetration test (black box and grey box).
* **MITRE ATT&CK Mapping**: Structuring the analysis of the discovered TTPs using the MITRE ATT&CK framework as a reference.
* **Documentation**: Providing detailed reports on vulnerabilities, Proofs of Concept (PoC) for exploits, and remediation measures.

## 🛠️ Potential Technologies

While specific to the implementation, common technologies for this type of lab include:

* **Containerization**: `Docker` or `Docker Compose` for isolation and rapid deployment of vulnerable services.
* **Target Systems**: Vulnerable operating system images (e.g., `Metasploitable`, DVWA, OWASP Juice Shop).
* **Virtualization**: `VirtualBox` or `VMware` (if the infrastructure goes beyond containerization).
* **Attack Tools**: Kali Linux, `Metasploit` framework, `Nmap`, `Burp Suite`, etc.
* **Documentation**: Markdown and report generation tools.

## ⚙️ Installation and Quick Start

### Prerequisites

* `git` installed.
* `Docker` and `Docker Compose` installed (recommended method).

### Steps

1.  **Clone the Repository:**
    ```bash
    git clone [https://github.com/w4lk3r04/internship-projects](https://github.com/w4lk3r04/internship-projects)
    cd internship-projects/tree/vuln_lab
    ```

2.  **Deploy the Infrastructure (Docker Compose Example):**
    ```bash
    # If a docker-compose.yml file is provided
    docker-compose up -d
    ```

3.  **Verification:**
    Verify that the services are launched and accessible on the specified ports (check the specific documentation inside the `vuln_lab` folder for access details and IP addresses).

## 📚 Usage

This laboratory is designed to:

1.  **Practice Enumeration and Reconnaissance** on the deployed targets.
2.  **Identify and Exploit** vulnerabilities (SQL Injection, XSS, RCE, Privilege Escalation, etc.).
3.  **Document the Attack Path** and the TTPs used.
4.  **Map** the exploited techniques using the **MITRE ATT&CK** matrix (e.g., T1059.004 for command execution via PHP, T1078 for valid accounts).
5.  **Develop and test** defensive measures.

## ATT&CK mapping MVP

The repository includes a first, evidence-preserving ATT&CK mapper for UTF-8
text and Markdown Red Team reports. It maps the techniques exercised by the lab
and keeps the source line for every recommendation:

```bash
python -m attack_mapper.cli path/to/report.txt
```

To export the threat intelligence matrix as Markdown:

```bash
python -m attack_mapper.cli path/to/report.txt \
  --markdown-output threat_intelligence_matrix.md
```

For a local test interface that accepts pasted reports or text/Markdown files:

```bash
python -m attack_mapper.web
```

Then open `http://127.0.0.1:8000`. Reports are processed in memory and are not
stored by the MVP.

The MVP is intentionally rule-based. It provides the validation baseline for
the next iterations: PDF ingestion, the official versioned ATT&CK STIX catalog,
semantic retrieval, and analyst review of low-confidence recommendations.

## 🤝 Contribution and License

This project is developed as part of an internship and is open for learning purposes.

This project is licensed under the **MIT License**. See the `LICENSE` file for more details.
