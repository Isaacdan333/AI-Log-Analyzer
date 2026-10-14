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
- scikit-learn is optional for rule-based runs; install the `ml` extra to use the standalone anomaly model.

### Development dependencies

- pytest
- scikit-learn (included so the ML tests run)

## Local setup

From the project root, create and activate a virtual environment:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

For a rule-based runtime that also uses the isolated IsolationForest component,
install the optional ML extra:

```powershell
python -m pip install -e ".[ml]"
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

## Optional ML anomaly analysis (CLI)

Install the optional dependency (the `dev` extra already includes it):

```powershell
python -m pip install -e ".[ml]"
```

Choose a directory or file of representative baseline logs for training and
keep it separate from the logs being analyzed (overlapping files are rejected):

```powershell
python -m loganalyzer.cli analyze --logs .\samples --enable-ml --ml-training-logs .\training_samples --format json
```

`--enable-ml` requires `--ml-training-logs`. Model settings come from
`[ml.isolation_forest]` in the `--config` TOML file. Output gains a separate
`ML Anomaly Findings` text section, or `ml_analysis` and `ml_findings` JSON
fields. Without `--enable-ml`, output is unchanged.

ML findings differ from deterministic alerts: they have no severity, do not
affect alerts or the exit code, and mean only that an activity pattern deviates
from the training baseline. They are not confirmed attacks. IsolationForest
gives no per-feature causal attribution; the listed training ranges and
percentiles are context only. The model is refit on each run (no persistence),
and results depend heavily on a representative, mostly normal baseline; an
unrepresentative baseline produces misleading output.

## Standalone IsolationForest scoring

The ML model is opt-in and independent of deterministic alerts. It consumes the existing `FeatureObservation` records and returns
`MLAnomalyFinding` values labelled `normal` or `anomaly`. An anomaly is a model
classification, not a confirmed attack. Per-feature ranges and percentiles
provide training-data context only; they are not causal feature explanations.

This example trains with the generated normal web baseline and scores a
separate generated web spike. The two sets are parsed and feature-engineered
independently:

```python
from pathlib import Path

from loganalyzer.config import load_config
from loganalyzer.engine import analyze_paths
from loganalyzer.features import engineer_features
from loganalyzer.ml import IsolationForestAnomalyDetector
from loganalyzer.synthetic.generate_logs import generate_logs

training_file = generate_logs(
    Path("synthetic-training"), scenario="web_baseline", seed=2026
)["web_baseline"]
training_result = analyze_paths(
    [training_file], formats={training_file: "web"}, detectors=[]
)
training_observations = engineer_features(training_result.events)

scoring_file = generate_logs(
    Path("synthetic-scoring"), scenario="web_spike", seed=2026
)["web_spike"]
scoring_result = analyze_paths(
    [scoring_file], formats={scoring_file: "web"}, detectors=[]
)
scoring_observations = engineer_features(scoring_result.events)

settings = load_config(Path("config.example.toml")).ml_options["isolation_forest"]
model = IsolationForestAnomalyDetector(**settings).fit(training_observations)
for finding in model.score(scoring_observations):
    print(finding.classification, finding.source_group, finding.time_bucket)
```

The checked-in generator's baseline is intentionally small; this example
demonstrates the API, not detection accuracy. In practice, fit against a
representative normal history and evaluate on separate data before relying on
model classifications.

`IsolationForestAnomalyDetector` defaults to a fixed random seed and exposes
its effective training and decision settings through `model.metadata`.
Settings can be supplied in `[ml.isolation_forest]` in a TOML config and are
used by both the standalone component (pass them directly) and the CLI ML
workflow.

## Current project direction

The project has a rule-based MVP and an independently usable Phase 2 feature
engineering and anomaly-scoring layer:

1. parse log sources into a normalized event model
2. run rule-based detectors for suspicious activity
3. correlate evidence and produce structured alerts
4. format clear text or JSON reports
5. validate against synthetic and sample data

Optional LLM-based summarization remains a later phase and is intentionally
secondary to explainability and correctness.

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
