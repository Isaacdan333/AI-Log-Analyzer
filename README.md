# Cybersecurity Log Analyzer

A deterministic, explainable Python-based log analysis project designed to ingest multiple log sources, normalize them into a common event model, detect suspicious activity, and generate clear incident reports.

The goal is to help analysts review security-relevant behavior without relying on opaque ML or LLM decisions for the core detection pipeline. The first release focuses on rule-based detection, evidence-backed alerts, and clear reporting.

## Project goal

This project is intended to:

- ingest logs from multiple security sources
- normalize them into a shared event format
- detect suspicious patterns such as brute-force activity, privilege escalation, suspicious logins, and port scanning
- produce readable human reports with evidence and recommended actions
- provide a future-ready foundation for JSON output, API integrations, and advanced analytics

## Supported log sources

The initial implementation supports:

- Windows Security Event Log CSV exports
- Firewall logs
- SSH authentication logs
- Web server logs in Apache/Nginx combined format

## Key principles

- Normalize diverse log formats into a common event model
- Keep parsing, detection, and reporting separate
- Make every alert explainable with evidence
- Prefer deterministic rules over black-box model decisions
- Treat ML and LLM features as optional enhancement layers, not as the source of truth

## Example output

```text
Severity: HIGH

Potential brute-force attack detected.

47 failed SSH login attempts
Source: 185.xxx.xxx.xxx
Time: 02:14-02:19

Recommended actions:
1. Block source IP
2. Disable password authentication
3. Review successful logins
```

## Repository structure

```text
CyberSecurity Log Analyzer/
├── loganalyzer/
│   ├── __init__.py
│   ├── cli.py
│   ├── engine.py
│   ├── models.py
│   ├── report.py
│   ├── detectors/
│   ├── parsers/
│   └── synthetic/
├── samples/
├── tests/
├── .gitignore
├── plan.md
├── pyproject.toml
├── README.md
└── report.txt (generated output; should be ignored in Git)
```

## Requirements

### Python

- Python 3.11 or newer
- Recommended: use a project-local virtual environment

### Runtime dependencies

These are defined in [pyproject.toml](pyproject.toml):

- pandas
- python-dateutil

### Development dependencies

- pytest

## Local setup

From the project root, create and activate a virtual environment:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

If PowerShell blocks activation scripts, run Python directly from the environment or adjust your execution policy for the current user only.

## Verify the environment

```powershell
python --version
python -c "import sys; print(sys.executable)"
```

The output should point to the project's local `.venv` directory.

## Run the tests

```powershell
python -m pytest
```

## Run the analyzer

Analyze the sample logs:

```powershell
python -m loganalyzer.cli analyze --logs .\samples
```

Write output to a report file:

```powershell
python -m loganalyzer.cli analyze --logs .\samples --out report.txt
```

Export JSON output:

```powershell
python -m loganalyzer.cli analyze --logs .\samples --format json
```

## Current project direction

The project is currently focused on a Phase 1 rule-based MVP approach:

1. parse log sources into a normalized event model
2. run rule-based detectors for suspicious activity
3. correlate evidence and produce structured alerts
4. format clear text or JSON reports
5. validate against synthetic and sample data

Later phases may add statistical anomaly detection and optional LLM-based summarization, but those features are intentionally secondary to explainability and correctness.

## Security and operational notes

- Treat logs as untrusted input
- Keep findings grounded in observed evidence
- Avoid storing secrets or credentials in reports or source control
- Do not commit virtual environments, generated reports, or local environment files
- Prefer synthetic or sanitized data for development and testing

## License

This project is intended for educational and security-research use. Add an appropriate open-source license if you plan to publish it publicly on GitHub.

## Notes

This repository is designed around a clean, testable engineering workflow and a future path toward richer analysis, structured alerting, and operational reporting.
